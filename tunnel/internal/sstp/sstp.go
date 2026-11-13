// Package sstp is an SSTP client (MS-SSTP): PPP inside HTTPS. TLS to the
// server, an SSTP_DUPLEX_POST request, then SSTP packets both ways: control
// messages and data packets holding PPP frames.
package sstp

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/G1Vh/LocalProxy/tunnel/internal/core"
	"github.com/G1Vh/LocalProxy/tunnel/internal/packet"
	"github.com/G1Vh/LocalProxy/tunnel/internal/ppp"
)

// Options come from the outbound settings in LocalProxy.
type Options struct {
	// "host" or "host:port"; 443 by default.
	Server   string `json:"server"`
	User     string `json:"user"`
	Password string `json:"password"`
	// SHA-256 of the server certificate: trust exactly this certificate
	// (a self-signed one, typically). Colons and spaces are ignored.
	CertSHA256 string `json:"certSha256"`
	// Skip certificate checks altogether.
	Insecure bool `json:"insecure"`
	// Pins the connection to the physical interface while the TUN is on.
	Bind core.Bind `json:"-"`
}

const (
	sstpVersion = 0x10

	msgConnectRequest = 1
	msgConnectAck     = 2
	msgConnectNak     = 3
	msgConnected      = 4
	msgAbort          = 5
	msgDisconnect     = 6
	msgDisconnectAck  = 7
	msgEchoRequest    = 8
	msgEchoResponse   = 9

	attrEncapsulatedProtocol = 1
	attrCryptoBinding        = 3
	attrCryptoBindingReq     = 4

	hashSHA1   = 1
	hashSHA256 = 2

	// The SSTP length field has 12 bits.
	sstpMaxPacket = 4095
)

const sstpPath = "/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/"

var errSstpClosed = errors.New("сервер закрыл SSTP-соединение")

type conn struct {
	tc  *tls.Conn
	r   *bufio.Reader
	wmu sync.Mutex
	// Unix nanoseconds of the last packet from the server.
	lastRx    atomic.Int64
	closeOnce sync.Once
}

func splitServer(server string) (host, port string) {
	server = strings.TrimSpace(server)
	server = strings.TrimPrefix(strings.TrimPrefix(server, "https://"), "sstp://")
	server = strings.TrimSuffix(server, "/")
	if h, p, err := net.SplitHostPort(server); err == nil {
		return h, p
	}
	return strings.Trim(server, "[]"), "443"
}

func normalizeFingerprint(s string) string {
	r := strings.NewReplacer(":", "", " ", "", "-", "")
	return strings.ToLower(r.Replace(strings.TrimSpace(s)))
}

func formatFingerprint(sum []byte) string {
	h := strings.ToUpper(hex.EncodeToString(sum))
	parts := make([]string, 0, len(sum))
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// verifyServer checks the certificate by the pinned fingerprint, or against
// the Windows certificate store; a failure names the fingerprint so the
// user can pin a self-signed certificate.
func verifyServer(cs tls.ConnectionState, host string, opts Options) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("сервер не прислал сертификат")
	}
	leaf := cs.PeerCertificates[0]
	sum := sha256.Sum256(leaf.Raw)
	if pin := normalizeFingerprint(opts.CertSHA256); pin != "" {
		if pin != hex.EncodeToString(sum[:]) {
			return fmt.Errorf("сертификат сервера не совпадает с указанным отпечатком: у сервера %s", formatFingerprint(sum[:]))
		}
		return nil
	}
	if opts.Insecure {
		return nil
	}
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter}); err != nil {
		return fmt.Errorf("сертификат сервера не подтверждён (%v). Если у сервера самоподписанный сертификат, укажите его отпечаток SHA-256: %s", err, formatFingerprint(sum[:]))
	}
	return nil
}

// Dial connects and runs PPP up to a working IPv4 link. wantIP asks for the
// same address again after a reconnect.
func Dial(ctx context.Context, opts Options, wantIP netip.Addr) (*packet.Session, error) {
	host, port := splitServer(opts.Server)
	if host == "" {
		return nil, errors.New("не указан сервер")
	}
	if opts.User == "" {
		return nil, errors.New("не указан логин")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(20 * time.Second)
	}
	raw, err := (&net.Dialer{Control: opts.Bind.Control}).DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("нет соединения с %s: %w", net.JoinHostPort(host, port), err)
	}
	if tcp, ok := raw.(*net.TCPConn); ok {
		tcp.SetNoDelay(true)
		tcp.SetKeepAlive(true)
	}
	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Checked by verifyServer, which knows about pinned certificates.
		InsecureSkipVerify: true,
		VerifyConnection:   func(cs tls.ConnectionState) error { return verifyServer(cs, host, opts) },
	}
	if net.ParseIP(host) == nil {
		tlsConf.ServerName = host
	}
	tc := tls.Client(raw, tlsConf)
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, tlsError(err)
	}
	c := &conn{tc: tc, r: bufio.NewReaderSize(tc, 16<<10)}
	c.lastRx.Store(time.Now().UnixNano())
	res, err := c.handshake(host, opts, wantIP, deadline)
	if err != nil {
		c.Close()
		return nil, err
	}
	return &packet.Session{
		Conn: &packetConn{conn: c, ppp: ppp.NewSession(c, res)},
		IP:   res.IP,
		DNS:  res.DNS,
		MTU:  res.MTU,
	}, nil
}

// packetConn moves IPv4 packets over the PPP session of one connection.
type packetConn struct {
	*conn
	ppp *ppp.Session
}

func (p *packetConn) ReadPacket() ([]byte, error)  { return p.ppp.ReadIP() }
func (p *packetConn) WritePacket(pkt []byte) error { return p.ppp.WriteIP(pkt) }
func (p *packetConn) Ping() error                  { return p.writeControl(msgEchoRequest) }

func tlsError(err error) error {
	var verr *tls.CertificateVerificationError
	if errors.As(err, &verr) {
		return verr.Err
	}
	// VerifyConnection errors come wrapped as an alert we sent.
	msg := err.Error()
	if i := strings.Index(msg, "сертификат"); i >= 0 {
		return errors.New(msg[i:])
	}
	return fmt.Errorf("TLS: %w", err)
}

func (c *conn) handshake(host string, opts Options, wantIP netip.Addr, deadline time.Time) (*ppp.Result, error) {
	c.tc.SetDeadline(deadline)
	defer c.tc.SetDeadline(time.Time{})

	var corr [16]byte
	rand.Read(corr[:])
	req := "SSTP_DUPLEX_POST " + sstpPath + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Content-Length: 18446744073709551615\r\n" +
		"SSTPCORRELATIONID: {" + guid(corr) + "}\r\n\r\n"
	if _, err := io.WriteString(c.tc, req); err != nil {
		return nil, err
	}
	status, err := c.r.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("сервер не ответил на запрос SSTP: %w", err)
	}
	if f := strings.Fields(status); len(f) < 2 || f[1] != "200" {
		return nil, fmt.Errorf("это не SSTP-сервер или путь закрыт: %s", strings.TrimSpace(status))
	}
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	// CALL_CONNECT_REQUEST: PPP is the only protocol SSTP carries.
	if err := c.writeControl(msgConnectRequest, attr(attrEncapsulatedProtocol, []byte{0, 1})); err != nil {
		return nil, err
	}
	var nonce []byte
	hashProto := 0
	for nonce == nil {
		ctrl, body, err := c.readPacket()
		if err != nil {
			return nil, fmt.Errorf("сервер не принял SSTP-подключение: %w", err)
		}
		if !ctrl {
			continue
		}
		typ, attrs, err := parseControl(body)
		if err != nil {
			return nil, err
		}
		switch typ {
		case msgConnectAck:
			v, ok := attrs[attrCryptoBindingReq]
			if !ok || len(v) < 36 {
				return nil, errors.New("SSTP: сервер не прислал параметры crypto binding")
			}
			if v[3]&hashSHA256 != 0 {
				hashProto = hashSHA256
			} else if v[3]&hashSHA1 != 0 {
				hashProto = hashSHA1
			} else {
				return nil, errors.New("SSTP: сервер предлагает неизвестный алгоритм хэша")
			}
			nonce = append([]byte(nil), v[4:36]...)
		case msgConnectNak:
			return nil, errors.New("сервер отклонил SSTP-подключение")
		case msgAbort, msgDisconnect:
			return nil, errSstpClosed
		}
	}

	certHash := certHash(c.tc.ConnectionState().PeerCertificates[0].Raw, hashProto)
	onAuth := func(hlak []byte) error {
		return c.sendConnected(hashProto, nonce, certHash, hlak)
	}
	return ppp.Negotiate(c, ppp.Config{User: opts.User, Password: opts.Password, WantIP: wantIP, OnAuth: onAuth}, deadline)
}

func guid(b [16]byte) string {
	h := strings.ToUpper(hex.EncodeToString(b[:]))
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func certHash(der []byte, proto int) []byte {
	out := make([]byte, 32)
	if proto == hashSHA256 {
		s := sha256.Sum256(der)
		copy(out, s[:])
	} else {
		s := sha1.Sum(der)
		copy(out, s[:])
	}
	return out
}

func attr(id byte, value []byte) []byte {
	b := []byte{0, id, 0, 0}
	binary.BigEndian.PutUint16(b[2:], uint16(4+len(value)))
	return append(b, value...)
}

// controlPacket builds a whole control packet: header, message, attributes.
func controlPacket(msgType uint16, attrs ...[]byte) []byte {
	body := binary.BigEndian.AppendUint16(nil, msgType)
	body = binary.BigEndian.AppendUint16(body, uint16(len(attrs)))
	for _, a := range attrs {
		body = append(body, a...)
	}
	return wirePacket(true, body)
}

func wirePacket(control bool, body []byte) []byte {
	b := make([]byte, 4, 4+len(body))
	b[0] = sstpVersion
	if control {
		b[1] = 1
	}
	binary.BigEndian.PutUint16(b[2:], uint16(4+len(body))&0x0fff)
	return append(b, body...)
}

func parseControl(body []byte) (uint16, map[byte][]byte, error) {
	if len(body) < 4 {
		return 0, nil, errors.New("SSTP: короткое управляющее сообщение")
	}
	typ := binary.BigEndian.Uint16(body)
	n := int(binary.BigEndian.Uint16(body[2:]))
	attrs := map[byte][]byte{}
	b := body[4:]
	for range n {
		if len(b) < 4 {
			return 0, nil, errors.New("SSTP: неверный атрибут")
		}
		l := int(binary.BigEndian.Uint16(b[2:]) & 0x0fff)
		if l < 4 || l > len(b) {
			return 0, nil, errors.New("SSTP: неверная длина атрибута")
		}
		attrs[b[1]] = b[4:l]
		b = b[l:]
	}
	return typ, attrs, nil
}

// sendConnected proves to the server that the TLS session and the PPP login
// belong together: a MAC over this very packet keyed from the login.
func (c *conn) sendConnected(hashProto int, nonce, certHash, hlak []byte) error {
	value := make([]byte, 100)
	value[3] = byte(hashProto)
	copy(value[4:36], nonce)
	copy(value[36:68], certHash)
	pkt := controlPacket(msgConnected, attr(attrCryptoBinding, value))
	mac := compoundMAC(hashProto, hlak, pkt)
	copy(pkt[80:112], mac)
	return c.write(pkt)
}

// compoundMAC: CMK = HMAC(HLAK, "SSTP inner method derived CMK" | LEN | 1),
// MAC = HMAC(CMK, packet with the MAC field zeroed); LEN is little endian.
func compoundMAC(hashProto int, hlak, pkt []byte) []byte {
	newHash, size := sha256.New, 32
	if hashProto == hashSHA1 {
		newHash, size = func() hash.Hash { return sha1.New() }, 20
	}
	m := hmac.New(newHash, hlak)
	m.Write([]byte("SSTP inner method derived CMK"))
	m.Write([]byte{byte(size), byte(size >> 8), 1})
	cmk := m.Sum(nil)
	m = hmac.New(newHash, cmk)
	m.Write(pkt)
	out := make([]byte, 32)
	copy(out, m.Sum(nil))
	return out
}

func (c *conn) readPacket() (control bool, body []byte, err error) {
	var h [4]byte
	if _, err := io.ReadFull(c.r, h[:]); err != nil {
		return false, nil, err
	}
	if h[0] != sstpVersion {
		return false, nil, fmt.Errorf("SSTP: неизвестная версия протокола %#x", h[0])
	}
	n := int(binary.BigEndian.Uint16(h[2:]) & 0x0fff)
	if n < 4 {
		return false, nil, errors.New("SSTP: неверная длина пакета")
	}
	body = make([]byte, n-4)
	if _, err := io.ReadFull(c.r, body); err != nil {
		return false, nil, err
	}
	c.lastRx.Store(time.Now().UnixNano())
	return h[1]&1 == 1, body, nil
}

func (c *conn) write(pkt []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.tc.SetWriteDeadline(time.Now().Add(15 * time.Second))
	_, err := c.tc.Write(pkt)
	return err
}

func (c *conn) writeControl(msgType uint16, attrs ...[]byte) error {
	return c.write(controlPacket(msgType, attrs...))
}

// ReadFrame returns the next PPP frame, answering control messages on the way.
func (c *conn) ReadFrame() ([]byte, error) {
	for {
		ctrl, body, err := c.readPacket()
		if err != nil {
			return nil, err
		}
		if !ctrl {
			return body, nil
		}
		typ, _, err := parseControl(body)
		if err != nil {
			continue
		}
		switch typ {
		case msgEchoRequest:
			if err := c.writeControl(msgEchoResponse); err != nil {
				return nil, err
			}
		case msgDisconnect:
			c.writeControl(msgDisconnectAck)
			return nil, errSstpClosed
		case msgAbort:
			return nil, errSstpClosed
		}
	}
}

func (c *conn) WriteFrame(frame []byte) error {
	if 4+len(frame) > sstpMaxPacket {
		return errors.New("SSTP: слишком большой пакет")
	}
	return c.write(wirePacket(false, frame))
}

func (c *conn) SetReadDeadline(t time.Time) error { return c.tc.SetReadDeadline(t) }

// Idle is how long the server has been silent.
func (c *conn) Idle() time.Duration {
	return time.Since(time.Unix(0, c.lastRx.Load()))
}

// Close says goodbye to the server if it still listens, then drops the connection.
func (c *conn) Close() {
	c.closeOnce.Do(func() {
		// A writer stuck on a dead connection holds the lock: skip the goodbye then.
		if c.wmu.TryLock() {
			c.tc.SetWriteDeadline(time.Now().Add(time.Second))
			c.tc.Write(controlPacket(msgDisconnect))
			c.wmu.Unlock()
		}
		c.tc.Close()
	})
}

package sstp

// End-to-end SSTP: a fake SSTP server in this process (TLS, SSTP control
// messages, PPP with MS-CHAPv2 or PAP, IPCP, and its own network stack with
// an HTTP server and a UDP echo) and the bridge as its client. The server
// checks the crypto binding the way Windows RRAS does, independently of the
// client code paths it can avoid.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"

	"github.com/G1Vh/LocalProxy/tunnel/internal/core"
	"github.com/G1Vh/LocalProxy/tunnel/internal/core/coretest"
	"github.com/G1Vh/LocalProxy/tunnel/internal/mschap"
	"github.com/G1Vh/LocalProxy/tunnel/internal/packet"
	"github.com/G1Vh/LocalProxy/tunnel/internal/ppp"
)

const (
	sstpServerIP = "10.77.0.1"
	sstpUser     = `CORP\alice`
	sstpPass     = "Пароль-123"
)

type fakeSstp struct {
	t        *testing.T
	auth     uint16 // ppp.ProtoCHAP or ppp.ProtoPAP
	ln       net.Listener
	certDER  []byte
	finger   string
	dev      tun.Device
	assign   atomic.Pointer[netip.Addr]
	bound    atomic.Int32 // connections with a valid crypto binding
	conns    sync.Map     // *tls.Conn -> struct{}
	current  atomic.Pointer[fakeSession]
	failures atomic.Int32
}

type fakeSession struct {
	conn *tls.Conn
	wmu  sync.Mutex
}

func (s *fakeSession) send(control bool, body []byte) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.conn.Write(wirePacket(control, body))
}

func (s *fakeSession) sendPPP(proto uint16, p ppp.Packet) {
	s.send(false, ppp.EncodeFrame(proto, p.Bytes()))
}

func selfSigned(t *testing.T) tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sstp.test"},
		DNSNames:     []string{"sstp.test"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func startFakeSstp(t *testing.T, auth uint16) *fakeSstp {
	t.Helper()
	log.SetOutput(io.Discard)
	cert := selfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.Certificate[0])
	s := &fakeSstp{t: t, auth: auth, ln: ln, certDER: cert.Certificate[0], finger: hex.EncodeToString(sum[:])}
	ip := netip.MustParseAddr("10.77.0.2")
	s.assign.Store(&ip)

	dev, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(sstpServerIP)}, nil, 1400)
	if err != nil {
		t.Fatal(err)
	}
	s.dev = dev
	web, err := tnet.ListenTCP(&net.TCPAddr{IP: net.ParseIP(sstpServerIP), Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(web, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello through sstp")
	}))
	echo, err := tnet.ListenUDPAddrPort(netip.MustParseAddrPort(sstpServerIP + ":7"))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			echo.WriteTo(buf[:n], from)
		}
	}()
	// Server stack -> the connected client.
	go func() {
		bufs, sizes := [][]byte{make([]byte, 65535)}, []int{0}
		for {
			n, err := dev.Read(bufs, sizes, 0)
			if err != nil {
				return
			}
			if sess := s.current.Load(); sess != nil && n > 0 {
				sess.send(false, ppp.EncodeFrame(ppp.ProtoIPv4, bufs[0][:sizes[0]]))
			}
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns.Store(c, struct{}{})
			go s.serve(c.(*tls.Conn))
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		s.dropAll()
		web.Close()
		echo.Close()
		dev.Close()
	})
	return s
}

func (s *fakeSstp) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *fakeSstp) dropAll() {
	s.conns.Range(func(k, _ any) bool {
		k.(net.Conn).Close()
		s.conns.Delete(k)
		return true
	})
}

func (s *fakeSstp) fail(format string, args ...any) error {
	s.failures.Add(1)
	return fmt.Errorf(format, args...)
}

func (s *fakeSstp) serve(c *tls.Conn) {
	defer c.Close()
	if err := s.session(c); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		s.t.Logf("fake server: %v", err)
	}
}

func (s *fakeSstp) session(c *tls.Conn) error {
	r := bufio.NewReader(c)
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "SSTP_DUPLEX_POST "+sstpPath) {
		c.Write([]byte("HTTP/1.1 404 Not Found\r\n\r\n"))
		return s.fail("bad request line %q", line)
	}
	for {
		l, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		if strings.TrimSpace(l) == "" {
			break
		}
	}
	c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\nServer: Microsoft-HTTPAPI/2.0\r\n\r\n"))
	sess := &fakeSession{conn: c}
	read := func() (bool, []byte, error) {
		var h [4]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return false, nil, err
		}
		body := make([]byte, int(binary.BigEndian.Uint16(h[2:])&0xfff)-4)
		_, err := io.ReadFull(r, body)
		return h[1] == 1, body, err
	}

	ctrl, body, err := read()
	if err != nil {
		return err
	}
	if typ, attrs, _ := parseControl(body); !ctrl || typ != msgConnectRequest || !bytes.Equal(attrs[attrEncapsulatedProtocol], []byte{0, 1}) {
		return s.fail("expected CALL_CONNECT_REQUEST")
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	req := append([]byte{0, 0, 0, hashSHA1 | hashSHA256}, nonce...)
	ack := controlPacket(msgConnectAck, attr(attrCryptoBindingReq, req))
	sess.send(true, ack[4:])

	// PPP, server side.
	var mb [4]byte
	rand.Read(mb[:])
	magic := binary.BigEndian.Uint32(mb[:])
	authOpt := []byte{0xc2, 0x23, ppp.CHAPMSv2}
	if s.auth == ppp.ProtoPAP {
		authOpt = []byte{0xc0, 0x23}
	}
	lcpReq := ppp.EncodeOptions([]ppp.Option{{Type: 1, Data: []byte{0x05, 0x78}}, {Type: 3, Data: authOpt}, {Type: 5, Data: binary.BigEndian.AppendUint32(nil, magic)}, {Type: 7}, {Type: 8}})
	sess.sendPPP(ppp.ProtoLCP, ppp.Packet{Code: ppp.ConfReq, ID: 1, Data: lcpReq})

	var (
		lcpAckedByClient, lcpAckedClient bool
		challenge                        = make([]byte, 16)
		hlak                             []byte
		authed, bound                    bool
		ipcpSent                         bool
		ipcpAckedByClient, ipcpAckedOurs bool
		protoRejected, v6Sent            bool
	)
	rand.Read(challenge)
	assigned := *s.assign.Load()
	for {
		ctrl, body, err := read()
		if err != nil {
			return err
		}
		if ctrl {
			typ, attrs, err := parseControl(body)
			if err != nil {
				return s.fail("control: %v", err)
			}
			switch typ {
			case msgConnected:
				v := attrs[attrCryptoBinding]
				if len(v) != 100 || v[3] != hashSHA256 {
					return s.fail("crypto binding attribute %x", v)
				}
				if !bytes.Equal(v[4:36], nonce) {
					return s.fail("nonce mismatch")
				}
				if sum := sha256.Sum256(s.certDER); !bytes.Equal(v[36:68], sum[:]) {
					return s.fail("certificate hash mismatch")
				}
				pkt := wirePacket(true, body)
				got := append([]byte(nil), pkt[80:112]...)
				clear(pkt[80:112])
				// The CMK the spec way, written out here on its own.
				m := hmac.New(sha256.New, hlak)
				m.Write([]byte("SSTP inner method derived CMK\x20\x00\x01"))
				m = hmac.New(sha256.New, m.Sum(nil))
				m.Write(pkt)
				if !hmac.Equal(got, m.Sum(nil)) {
					return s.fail("compound MAC mismatch")
				}
				bound = true
				s.bound.Add(1)
			case msgEchoRequest:
				sess.send(true, controlPacket(msgEchoResponse)[4:])
			case msgDisconnect:
				return nil
			}
			continue
		}
		proto, payload, err := ppp.DecodeFrame(body)
		if err != nil {
			return s.fail("frame: %v", err)
		}
		if proto == ppp.ProtoIPv4 {
			if !bound {
				return s.fail("IPv4 before crypto binding")
			}
			s.dev.Write([][]byte{payload}, 0)
			continue
		}
		p, err := ppp.ParsePacket(payload)
		if err != nil {
			return s.fail("packet: %v", err)
		}
		switch proto {
		case ppp.ProtoLCP:
			switch p.Code {
			case ppp.ConfReq:
				sess.sendPPP(ppp.ProtoLCP, ppp.Packet{Code: ppp.ConfAck, ID: p.ID, Data: p.Data})
				lcpAckedClient = true
			case ppp.ConfAck:
				lcpAckedByClient = true
			case ppp.ProtoRej:
				if binary.BigEndian.Uint16(p.Data) == 0x8057 {
					protoRejected = true
				}
			case ppp.ConfNak, ppp.ConfRej:
				return s.fail("client refused our LCP options: %x", p.Data)
			}
			if lcpAckedClient && lcpAckedByClient && !v6Sent {
				// IPv6CP, as Windows sends it: the client must reject it.
				v6Sent = true
				sess.sendPPP(0x8057, ppp.Packet{Code: ppp.ConfReq, ID: 1, Data: []byte{1, 10, 1, 2, 3, 4, 5, 6, 7, 8}})
			}
			if lcpAckedClient && lcpAckedByClient && !authed && s.auth == ppp.ProtoCHAP && p.Code != ppp.ProtoRej {
				sess.sendPPP(ppp.ProtoCHAP, ppp.Packet{Code: 1, ID: 7, Data: append(append([]byte{16}, challenge...), "fake-server"...)})
			}
		case ppp.ProtoCHAP:
			if p.Code != 2 || len(p.Data) < 50 || p.Data[0] != 49 {
				return s.fail("CHAP response %x", p.Data)
			}
			peer, resp, name := p.Data[1:17], p.Data[25:49], string(p.Data[50:])
			if name != sstpUser || !bytes.Equal(resp, mschap.NTResponse(challenge, peer, sstpUser, sstpPass)) {
				sess.sendPPP(ppp.ProtoCHAP, ppp.Packet{Code: 4, ID: p.ID, Data: []byte("E=691 R=0 C=00 V=3 M=Access denied")})
				return nil
			}
			ok := mschap.AuthenticatorResponse(sstpPass, resp, peer, challenge, sstpUser) + " M=Welcome"
			sess.sendPPP(ppp.ProtoCHAP, ppp.Packet{Code: 3, ID: p.ID, Data: []byte(ok)})
			hlak, authed = mschap.ClientHLAK(sstpPass, resp), true
		case ppp.ProtoPAP:
			u := string(p.Data[1 : 1+p.Data[0]])
			rest := p.Data[1+p.Data[0]:]
			pw := string(rest[1 : 1+rest[0]])
			if u != sstpUser || pw != sstpPass {
				sess.sendPPP(ppp.ProtoPAP, ppp.Packet{Code: 3, ID: p.ID, Data: []byte("\x0dAccess denied")})
				return nil
			}
			sess.sendPPP(ppp.ProtoPAP, ppp.Packet{Code: 2, ID: p.ID, Data: []byte{0}})
			hlak, authed = make([]byte, 32), true
		case ppp.ProtoIPCP:
			if !ipcpSent {
				ipcpSent = true
				sess.sendPPP(ppp.ProtoIPCP, ppp.Packet{Code: ppp.ConfReq, ID: 1, Data: ppp.EncodeOptions([]ppp.Option{{Type: 3, Data: netip.MustParseAddr(sstpServerIP).AsSlice()}})})
			}
			switch p.Code {
			case ppp.ConfReq:
				opts, _ := ppp.ParseOptions(p.Data)
				var nak []ppp.Option
				for _, o := range opts {
					switch o.Type {
					case 3:
						if netip.AddrFrom4([4]byte(o.Data)) != assigned {
							nak = append(nak, ppp.Option{Type: 3, Data: assigned.AsSlice()})
						}
					case 129:
						if netip.AddrFrom4([4]byte(o.Data)) != netip.MustParseAddr(sstpServerIP) {
							nak = append(nak, ppp.Option{Type: 129, Data: netip.MustParseAddr(sstpServerIP).AsSlice()})
						}
					case 131:
						sess.sendPPP(ppp.ProtoIPCP, ppp.Packet{Code: ppp.ConfRej, ID: p.ID, Data: ppp.EncodeOptions([]ppp.Option{o})})
						goto next
					}
				}
				if len(nak) > 0 {
					sess.sendPPP(ppp.ProtoIPCP, ppp.Packet{Code: ppp.ConfNak, ID: p.ID, Data: ppp.EncodeOptions(nak)})
				} else {
					sess.sendPPP(ppp.ProtoIPCP, ppp.Packet{Code: ppp.ConfAck, ID: p.ID, Data: p.Data})
					ipcpAckedOurs = true
				}
			case ppp.ConfAck:
				ipcpAckedByClient = true
			}
			if ipcpAckedOurs && ipcpAckedByClient {
				if !protoRejected {
					return s.fail("client ignored IPv6CP instead of rejecting it")
				}
				s.current.Store(sess)
			}
		next:
		}
	}
}

func start(opts Options) (*packet.Tunnel, error) {
	dial := func(ctx context.Context, ip netip.Addr) (*packet.Session, error) { return Dial(ctx, opts, ip) }
	return packet.Start("sstp", dial, coretest.User, coretest.Pass, "127.0.0.1:0")
}

func startSstpClient(t *testing.T, s *fakeSstp, opts Options) *packet.Tunnel {
	t.Helper()
	b, err := start(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

func sstpOpts(s *fakeSstp) Options {
	return Options{
		Server:     fmt.Sprintf("127.0.0.1:%d", s.port()),
		User:       sstpUser,
		Password:   sstpPass,
		CertSHA256: strings.ToUpper(s.finger[:8]) + " " + s.finger[8:],
	}
}

func httpThrough(t *testing.T, port int) string {
	t.Helper()
	c, code := coretest.SocksConnect(t, port, sstpServerIP, 80)
	if code != 0 {
		t.Fatalf("CONNECT failed with code %d", code)
	}
	defer c.Close()
	c.Write([]byte("GET / HTTP/1.0\r\nHost: x\r\n\r\n"))
	body, _ := io.ReadAll(c)
	return string(body)
}

func TestSstpCarriesTCPAndUDP(t *testing.T) {
	s := startFakeSstp(t, ppp.ProtoCHAP)
	b := startSstpClient(t, s, sstpOpts(s))
	if !strings.Contains(httpThrough(t, b.Port), "hello through sstp") {
		t.Fatal("no HTTP response through the tunnel")
	}
	if s.bound.Load() != 1 || s.failures.Load() != 0 {
		t.Fatalf("crypto binding: bound=%d failures=%d", s.bound.Load(), s.failures.Load())
	}

	ctl, err := coretest.SocksHandshake(b.Port, coretest.User, coretest.Pass)
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()
	ctl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	rep := make([]byte, 10)
	if _, err := io.ReadFull(ctl, rep); err != nil || rep[1] != 0 {
		t.Fatalf("UDP ASSOCIATE: %v %v", rep, err)
	}
	relay := &net.UDPAddr{IP: net.IP(rep[4:8]), Port: int(binary.BigEndian.Uint16(rep[8:10]))}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udp.WriteToUDP(append(core.UDPHeader(netip.MustParseAddrPort(sstpServerIP+":7")), "ping-sstp"...), relay)
	udp.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := udp.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no UDP echo: %v", err)
	}
	if _, _, payload, err := core.ParseUDPHeader(buf[:n]); err != nil || string(payload) != "ping-sstp" {
		t.Fatalf("bad UDP reply %q %v", payload, err)
	}

	st, _ := b.Status()
	if st.LastHandshake == 0 || st.RxBytes == 0 || st.TxBytes == 0 {
		t.Fatalf("status shows no traffic: %+v", st)
	}
}

func TestSstpPAP(t *testing.T) {
	s := startFakeSstp(t, ppp.ProtoPAP)
	b := startSstpClient(t, s, sstpOpts(s))
	if !strings.Contains(httpThrough(t, b.Port), "hello through sstp") {
		t.Fatal("no HTTP response through the tunnel")
	}
	if s.bound.Load() != 1 {
		t.Fatal("no crypto binding with PAP (zero HLAK)")
	}
}

func TestSstpWrongPassword(t *testing.T) {
	for _, auth := range []uint16{ppp.ProtoCHAP, ppp.ProtoPAP} {
		s := startFakeSstp(t, auth)
		opts := sstpOpts(s)
		opts.Password = "wrong"
		_, err := start(opts)
		if err == nil || !strings.Contains(err.Error(), "неверный логин или пароль") {
			t.Fatalf("auth %#x: want a login error, got %v", auth, err)
		}
	}
}

func TestSstpCertificateChecks(t *testing.T) {
	s := startFakeSstp(t, ppp.ProtoCHAP)
	opts := sstpOpts(s)
	opts.CertSHA256 = ""
	_, err := start(opts)
	want := formatFingerprint(must(hex.DecodeString(s.finger)))
	if err == nil || !strings.Contains(err.Error(), "самоподписанный") || !strings.Contains(err.Error(), want) {
		t.Fatalf("untrusted certificate: %v", err)
	}

	opts.CertSHA256 = strings.Repeat("ab", 32)
	if _, err := start(opts); err == nil || !strings.Contains(err.Error(), "не совпадает") {
		t.Fatalf("wrong pin: %v", err)
	}

	opts.CertSHA256, opts.Insecure = "", true
	b := startSstpClient(t, s, opts)
	if !strings.Contains(httpThrough(t, b.Port), "hello through sstp") {
		t.Fatal("insecure mode does not connect")
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestSstpReconnects(t *testing.T) {
	saved := packet.Backoff
	packet.Backoff = []time.Duration{50 * time.Millisecond}
	t.Cleanup(func() { packet.Backoff = saved })

	s := startFakeSstp(t, ppp.ProtoCHAP)
	b := startSstpClient(t, s, sstpOpts(s))
	if !strings.Contains(httpThrough(t, b.Port), "hello") {
		t.Fatal("first connection does not work")
	}
	s.current.Store(nil)
	s.dropAll()
	deadline := time.Now().Add(10 * time.Second)
	for s.bound.Load() < 2 || !b.Connected() {
		if time.Now().After(deadline) {
			t.Fatal("bridge did not reconnect")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(httpThrough(t, b.Port), "hello") {
		t.Fatal("no traffic after reconnect")
	}
}

func TestSstpAddressChangeIsFatal(t *testing.T) {
	saved := packet.Backoff
	packet.Backoff = []time.Duration{50 * time.Millisecond}
	t.Cleanup(func() { packet.Backoff = saved })

	s := startFakeSstp(t, ppp.ProtoCHAP)
	b := startSstpClient(t, s, sstpOpts(s))
	fatal := make(chan error, 1)
	b.SetFatal(func(err error) { fatal <- err })
	other := netip.MustParseAddr("10.77.0.3")
	s.assign.Store(&other)
	s.dropAll()
	select {
	case err := <-fatal:
		if !strings.Contains(err.Error(), "другой адрес") {
			t.Fatalf("unexpected: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("address change went unnoticed")
	}
}

func TestSplitServer(t *testing.T) {
	for in, want := range map[string]string{
		"vpn.example.com":          "vpn.example.com:443",
		"vpn.example.com:4443":     "vpn.example.com:4443",
		"https://vpn.example.com/": "vpn.example.com:443",
		"[2001:db8::1]:443":        "[2001:db8::1]:443",
		"2001:db8::1":              "[2001:db8::1]:443",
	} {
		h, p := splitServer(in)
		if got := net.JoinHostPort(h, p); got != want {
			t.Errorf("%q: got %s, want %s", in, got, want)
		}
	}
}

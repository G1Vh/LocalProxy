// Package core holds what every tunnel shares: the network stack wrapper
// and the SOCKS5 server LocalProxy talks to.
package core

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

const handshakeTimeout = 15 * time.Second

// Tunnel is what the SOCKS server needs from a tunnel.
type Tunnel interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	// Resolve looks a name up through the tunnel's DNS (or locally without one).
	Resolve(ctx context.Context, host string) (netip.Addr, error)
	// ListenUDP opens a UDP socket inside the tunnel for the given family.
	ListenUDP(v6 bool) (net.PacketConn, error)
	// Up reports a recent handshake with the server.
	Up() bool
	// WarmingUp is true for a short while after start, before the first handshake.
	WarmingUp() bool
}

// Without a live tunnel a dial is given less time: it mostly serves to
// trigger the handshake.
const downDialTimeout = 5 * time.Second

// SocksServer is a SOCKS5 server (RFC 1928) with username/password auth
// (RFC 1929): CONNECT and UDP ASSOCIATE, both into the tunnel. It listens on
// loopback only and is meant for LocalProxy, which holds the credentials.
type SocksServer struct {
	User, Pass string
	Tunnel     Tunnel
}

func (s *SocksServer) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			if err := s.handle(c); err != nil && !errors.Is(err, io.EOF) {
				log.Printf("socks: %v", err)
			}
		}()
	}
}

func (s *SocksServer) handle(c net.Conn) error {
	defer c.Close()
	c.SetDeadline(time.Now().Add(handshakeTimeout))

	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return err
	}
	if head[0] != 5 {
		return errors.New("not SOCKS5")
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	if !contains(methods, 2) {
		c.Write([]byte{5, 0xFF})
		return errors.New("client does not offer username/password auth")
	}
	c.Write([]byte{5, 2})
	if err := s.auth(c); err != nil {
		return err
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return err
	}
	if req[0] != 5 {
		return errors.New("bad request version")
	}
	host, port, err := readAddr(c, req[3])
	if err != nil {
		reply(c, 8, nil)
		return err
	}

	switch req[1] {
	case 1:
		return s.connect(c, host, port)
	case 3:
		return s.udpAssociate(c)
	default:
		reply(c, 7, nil)
		return fmt.Errorf("unsupported command %d", req[1])
	}
}

func (s *SocksServer) auth(c net.Conn) error {
	ver := make([]byte, 2)
	if _, err := io.ReadFull(c, ver); err != nil {
		return err
	}
	user := make([]byte, ver[1])
	if _, err := io.ReadFull(c, user); err != nil {
		return err
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(c, plen); err != nil {
		return err
	}
	pass := make([]byte, plen[0])
	if _, err := io.ReadFull(c, pass); err != nil {
		return err
	}
	okUser := subtle.ConstantTimeCompare(user, []byte(s.User)) == 1
	okPass := subtle.ConstantTimeCompare(pass, []byte(s.Pass)) == 1
	if !okUser || !okPass {
		c.Write([]byte{1, 1})
		return errors.New("bad credentials")
	}
	_, err := c.Write([]byte{1, 0})
	return err
}

func (s *SocksServer) connect(c net.Conn, host string, port uint16) error {
	limit := handshakeTimeout
	if !s.Tunnel.Up() && !s.Tunnel.WarmingUp() {
		limit = downDialTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	up, err := s.Tunnel.DialContext(ctx, "tcp", target)
	if err != nil {
		if !s.Tunnel.Up() {
			// The server is not answering: close without a reply, so LocalProxy
			// treats the whole outbound as down (and blocks or goes direct by
			// its policy) instead of blaming this one site.
			return fmt.Errorf("tunnel down, dial %s: %w", target, err)
		}
		reply(c, 5, nil)
		return fmt.Errorf("dial %s: %w", target, err)
	}
	defer up.Close()
	if err := reply(c, 0, nil); err != nil {
		return err
	}
	c.SetDeadline(time.Time{})
	pipe(c, up)
	return nil
}

// pipe copies both ways and passes half-closes on, so request/response
// protocols that shut down their write side still get the answer.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

// udpAssociate relays datagrams between the client's UDP socket and the
// tunnel until the client's TCP control connection closes.
func (s *SocksServer) udpAssociate(c net.Conn) error {
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		reply(c, 1, nil)
		return err
	}
	defer relay.Close()
	if err := reply(c, 0, relay.LocalAddr().(*net.UDPAddr)); err != nil {
		return err
	}
	c.SetDeadline(time.Time{})

	a := &association{relay: relay, tunnel: s.Tunnel}
	defer a.close()
	go a.fromClient()

	// The association lives as long as the control connection.
	io.Copy(io.Discard, c)
	return nil
}

type association struct {
	relay  *net.UDPConn
	tunnel Tunnel

	mu     sync.Mutex
	client *net.UDPAddr
	out    [2]net.PacketConn // [v4, v6] sockets inside the tunnel
	closed bool
}

func (a *association) fromClient() {
	buf := make([]byte, 65535)
	for {
		n, from, err := a.relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if !from.IP.IsLoopback() {
			continue
		}
		a.mu.Lock()
		a.client = from
		a.mu.Unlock()

		host, port, payload, err := ParseUDPHeader(buf[:n])
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		addr, err := a.tunnel.Resolve(ctx, host)
		cancel()
		if err != nil {
			continue
		}
		out, err := a.socket(addr.Is6())
		if err != nil {
			continue
		}
		out.WriteTo(payload, net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, port)))
	}
}

// socket returns the tunnel socket for a family, opening it (and its reader) on first use.
func (a *association) socket(v6 bool) (net.PacketConn, error) {
	i := 0
	if v6 {
		i = 1
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, net.ErrClosed
	}
	if a.out[i] != nil {
		return a.out[i], nil
	}
	pc, err := a.tunnel.ListenUDP(v6)
	if err != nil {
		return nil, err
	}
	a.out[i] = pc
	go a.toClient(pc)
	return pc, nil
}

func (a *association) toClient(pc net.PacketConn) {
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		src, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		a.mu.Lock()
		client := a.client
		a.mu.Unlock()
		if client == nil {
			continue
		}
		a.relay.WriteToUDP(append(UDPHeader(src.AddrPort()), buf[:n]...), client)
	}
}

func (a *association) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	for _, pc := range a.out {
		if pc != nil {
			pc.Close()
		}
	}
}

func readAddr(r io.Reader, atyp byte) (string, uint16, error) {
	var host string
	switch atyp {
	case 1:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", 0, err
		}
		host = netip.AddrFrom4([4]byte(ip)).String()
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return "", 0, err
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return "", 0, err
		}
		host = string(name)
	case 4:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", 0, err
		}
		host = netip.AddrFrom16([16]byte(ip)).String()
	default:
		return "", 0, fmt.Errorf("address type %d", atyp)
	}
	p := make([]byte, 2)
	if _, err := io.ReadFull(r, p); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(p), nil
}

// ParseUDPHeader splits a SOCKS5 UDP datagram: RSV(2) FRAG(1) ATYP ADDR PORT DATA.
func ParseUDPHeader(b []byte) (string, uint16, []byte, error) {
	if len(b) < 4 || b[2] != 0 {
		return "", 0, nil, errors.New("short or fragmented datagram")
	}
	r := &sliceReader{b: b[4:]}
	host, port, err := readAddr(r, b[3])
	if err != nil {
		return "", 0, nil, err
	}
	return host, port, r.b, nil
}

// UDPHeader is the SOCKS5 UDP header for a datagram from src.
func UDPHeader(src netip.AddrPort) []byte {
	addr := src.Addr().Unmap()
	h := []byte{0, 0, 0}
	if addr.Is4() {
		ip := addr.As4()
		h = append(h, 1)
		h = append(h, ip[:]...)
	} else {
		ip := addr.As16()
		h = append(h, 4)
		h = append(h, ip[:]...)
	}
	return binary.BigEndian.AppendUint16(h, src.Port())
}

// reply sends a SOCKS5 reply; bound may be nil (0.0.0.0:0).
func reply(c net.Conn, code byte, bound *net.UDPAddr) error {
	msg := []byte{5, code, 0}
	if bound == nil {
		msg = append(msg, 1, 0, 0, 0, 0, 0, 0)
	} else {
		msg = append(msg, UDPHeader(bound.AddrPort())[3:]...)
	}
	_, err := c.Write(msg)
	return err
}

type sliceReader struct{ b []byte }

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

func contains(b []byte, v byte) bool {
	for _, x := range b {
		if x == v {
			return true
		}
	}
	return false
}

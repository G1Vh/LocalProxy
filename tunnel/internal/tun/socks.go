package tun

// Minimal SOCKS5 client (RFC 1928): what the TUN engine needs to hand
// connections to LocalProxy, which then applies its rules. The program behind
// a connection goes as username/password (RFC 1929): user "process",
// password = its exe path; LocalProxy does not check them.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"
)

const socksTimeout = 10 * time.Second

const (
	// processUser is the username that names the program; see socksHandshake.
	processUser = "process"
	// tunUser names it too and says we open direct routes ourselves (see
	// direct.go): LocalProxy then answers repDirect instead of dialing.
	tunUser = "tun"
	// cmdUDPRoute is LocalProxy's own command: a UDP flow to the address,
	// answered with repDirect or an ordinary association.
	cmdUDPRoute = 0x83
	repDirect   = 0x80
)

// errDirect: LocalProxy left the route to us; the connection stays open
// for the report.
var errDirect = errors.New("SOCKS5: direct route")

// processName fits an exe path into the 255 bytes a password may take.
func processName(path string) string {
	if len(path) <= 255 {
		return path
	}
	name := path[strings.LastIndexByte(path, '\\')+1:]
	if len(name) > 255 {
		return ""
	}
	return name
}

// socksAddr encodes host:port as a SOCKS5 address (domain or IP).
func socksAddr(host string, port uint16) []byte {
	var b []byte
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			a := ip.As4()
			b = append([]byte{1}, a[:]...)
		} else {
			a := ip.As16()
			b = append([]byte{4}, a[:]...)
		}
	} else {
		b = append([]byte{3, byte(len(host))}, host...)
	}
	return binary.BigEndian.AppendUint16(b, port)
}

// socksHandshake connects to the proxy and sends the request; process (an
// exe path, may be empty) names the program behind it, and delegate asks for
// direct routes to be left to us (errDirect, with the connection open). The
// greeting, login and request go in one write: LocalProxy reads them in turn.
func socksHandshake(ctx context.Context, proxy, process string, delegate bool, cmd byte, host string, port uint16) (net.Conn, []byte, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	} else {
		c.SetDeadline(time.Now().Add(socksTimeout))
	}
	fail := func(err error) (net.Conn, []byte, error) {
		c.Close()
		return nil, nil, err
	}
	process = processName(process)
	user := processUser
	if delegate {
		user = tunUser
	}
	method := byte(0)
	if process != "" || delegate {
		method = 2
	}
	msg := []byte{5, 1, method}
	if method == 2 {
		msg = append(append(msg, 1, byte(len(user))), user...)
		msg = append(append(msg, byte(len(process))), process...)
	}
	msg = append(append(msg, 5, cmd, 0), socksAddr(host, port)...)
	if _, err := c.Write(msg); err != nil {
		return fail(err)
	}
	var m [2]byte
	if _, err := io.ReadFull(c, m[:]); err != nil {
		return fail(err)
	}
	if m[0] != 5 || m[1] != method {
		return fail(errors.New("SOCKS5: способ входа не принят"))
	}
	if method == 2 {
		if _, err := io.ReadFull(c, m[:]); err != nil {
			return fail(err)
		}
		if m[1] != 0 {
			return fail(errors.New("SOCKS5: вход не принят"))
		}
	}
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return fail(err)
	}
	direct := delegate && h[1] == repDirect
	if h[1] != 0 && !direct {
		return fail(fmt.Errorf("SOCKS5: отказ %d", h[1]))
	}
	var n int
	switch h[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return fail(err)
		}
		n = int(l[0])
	default:
		return fail(errors.New("SOCKS5: неизвестный тип адреса"))
	}
	bound := make([]byte, n+2)
	if _, err := io.ReadFull(c, bound); err != nil {
		return fail(err)
	}
	c.SetDeadline(time.Time{})
	if direct {
		return c, nil, errDirect
	}
	return c, append([]byte{h[3]}, bound...), nil
}

// socksConnect opens a TCP tunnel to host:port through the proxy; with
// delegate, errDirect hands the dial to us.
func socksConnect(ctx context.Context, proxy, process string, delegate bool, host string, port uint16) (net.Conn, error) {
	c, _, err := socksHandshake(ctx, proxy, process, delegate, 1, host, port)
	return c, err
}

// socksAssociation is a SOCKS5 UDP ASSOCIATE: datagrams to the relay carry
// a header with the destination. It ends when the control connection closes.
type socksAssociation struct {
	control net.Conn
	udp     *net.UDPConn
	relay   *net.UDPAddr
}

func socksAssociate(ctx context.Context, proxy, process string) (*socksAssociation, error) {
	control, bound, err := socksHandshake(ctx, proxy, process, false, 3, "0.0.0.0", 0)
	if err != nil {
		return nil, err
	}
	return associated(control, bound, proxy)
}

// socksUDPRoute asks about one UDP flow to host:port: an association if it
// goes through LocalProxy, or errDirect and the control connection if it is
// ours to relay.
func socksUDPRoute(ctx context.Context, proxy, process, host string, port uint16) (*socksAssociation, net.Conn, error) {
	control, bound, err := socksHandshake(ctx, proxy, process, true, cmdUDPRoute, host, port)
	if errors.Is(err, errDirect) {
		return nil, control, err
	}
	if err != nil {
		return nil, nil, err
	}
	a, err := associated(control, bound, proxy)
	return a, nil, err
}

// associated finishes an association the proxy granted.
func associated(control net.Conn, bound []byte, proxy string) (*socksAssociation, error) {
	relay, err := relayAddr(bound, proxy)
	if err != nil {
		control.Close()
		return nil, err
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		control.Close()
		return nil, err
	}
	return &socksAssociation{control: control, udp: udp, relay: relay}, nil
}

// relayAddr: the relay the server announced; 0.0.0.0 means "the proxy's address".
func relayAddr(bound []byte, proxy string) (*net.UDPAddr, error) {
	port := int(binary.BigEndian.Uint16(bound[len(bound)-2:]))
	var ip net.IP
	switch bound[0] {
	case 1:
		ip = net.IP(bound[1:5])
	case 4:
		ip = net.IP(bound[1:17])
	}
	if ip == nil || ip.IsUnspecified() {
		h, _, err := net.SplitHostPort(proxy)
		if err != nil {
			return nil, err
		}
		ip = net.ParseIP(h)
	}
	if ip == nil {
		return nil, errors.New("SOCKS5: непонятный адрес UDP-релея")
	}
	return &net.UDPAddr{IP: ip, Port: port}, nil
}

func (a *socksAssociation) send(host string, port uint16, payload []byte) error {
	d := append([]byte{0, 0, 0}, socksAddr(host, port)...)
	d = append(d, payload...)
	_, err := a.udp.WriteToUDP(d, a.relay)
	return err
}

// recv returns the payload of the next datagram from the relay.
func (a *socksAssociation) recv(buf []byte) ([]byte, error) {
	for {
		n, from, err := a.udp.ReadFromUDP(buf)
		if err != nil {
			return nil, err
		}
		if !from.IP.Equal(a.relay.IP) {
			continue
		}
		d := buf[:n]
		if len(d) < 4 || d[2] != 0 {
			continue
		}
		var skip int
		switch d[3] {
		case 1:
			skip = 4 + 4 + 2
		case 4:
			skip = 4 + 16 + 2
		case 3:
			if len(d) < 5 {
				continue
			}
			skip = 4 + 1 + int(d[4]) + 2
		default:
			continue
		}
		if len(d) < skip {
			continue
		}
		return d[skip:], nil
	}
}

func (a *socksAssociation) Close() {
	a.control.Close()
	a.udp.Close()
}

package core

import (
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/windows"
)

// Bind pins sockets to the physical interface while LocalProxy's TUN
// adapter takes the rest of the traffic, so a tunnel's own packets (to its
// VPN server) do not loop back into the TUN. Zero leaves a family as is.
type Bind struct {
	V4 uint32 `json:"v4"`
	V6 uint32 `json:"v6"`
}

const (
	ipUnicastIf   = 31
	ipv6UnicastIf = 31
)

func (b Bind) Active() bool { return b.V4 != 0 || b.V6 != 0 }

// Control is a net.Dialer / net.ListenConfig hook.
func (b Bind) Control(network, address string, c syscall.RawConn) error {
	if !b.Active() {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip, _ := netip.ParseAddr(host)
	if ip.IsLoopback() {
		return nil
	}
	v6 := ip.Is6() && !ip.Is4In6()
	if !ip.IsValid() {
		v6 = network == "tcp6" || network == "udp6"
	}
	var serr error
	err = c.Control(func(fd uintptr) { serr = b.Pin(windows.Handle(fd), v6) })
	if err != nil {
		return err
	}
	return serr
}

// Pin sets the interface on one socket.
func (b Bind) Pin(fd windows.Handle, v6 bool) error {
	if v6 {
		if b.V6 == 0 {
			return nil
		}
		return windows.SetsockoptInt(fd, windows.IPPROTO_IPV6, ipv6UnicastIf, int(b.V6))
	}
	if b.V4 == 0 {
		return nil
	}
	// The IPv4 option takes the index in network byte order.
	v := b.V4
	be := v>>24 | (v>>8)&0xff00 | (v<<8)&0xff0000 | v<<24
	return windows.SetsockoptInt(fd, windows.IPPROTO_IP, ipUnicastIf, int(be))
}

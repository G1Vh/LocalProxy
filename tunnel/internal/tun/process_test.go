package tun

import (
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func me(t *testing.T) string {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func TestProcessOfTCP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	src := c.LocalAddr().(*net.TCPAddr).AddrPort()
	dst := c.RemoteAddr().(*net.TCPAddr).AddrPort()
	if got := ProcessOf(src, dst, false); !strings.EqualFold(got, me(t)) {
		t.Fatalf("got %q, want %q", got, me(t))
	}
	if got := ProcessOf(dst, netip.MustParseAddrPort("127.0.0.1:1"), false); got != "" {
		t.Fatalf("no such connection, got %q", got)
	}
}

func TestProcessOfUDP(t *testing.T) {
	// Bound to any address, as most programs do; the flow is seen from a
	// concrete source address.
	u, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	port := uint16(u.LocalAddr().(*net.UDPAddr).Port)
	src := netip.AddrPortFrom(netip.MustParseAddr("198.18.0.1"), port)
	if got := ProcessOf(src, netip.MustParseAddrPort("1.1.1.1:53"), true); !strings.EqualFold(got, me(t)) {
		t.Fatalf("got %q, want %q", got, me(t))
	}
}

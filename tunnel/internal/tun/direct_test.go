package tun

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// delegatingProxy answers every request from the user "tun" with repDirect
// and records the dial report and byte counts that follow.
type delegatingProxy struct {
	addr string
	mu   sync.Mutex
	// "tcp 1.2.3.4:443 by app.exe: dial 0, up 2, down 2"
	seen []string
	done chan struct{}
}

func startDelegatingProxy(t *testing.T) *delegatingProxy {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	p := &delegatingProxy{addr: l.Addr().String(), done: make(chan struct{}, 8)}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go p.serve(c)
		}
	}()
	return p
}

func (p *delegatingProxy) serve(c net.Conn) {
	defer c.Close()
	h := make([]byte, 3)
	io.ReadFull(c, h[:2])
	io.ReadFull(c, make([]byte, h[1]))
	c.Write([]byte{5, 2})
	user, pass := readAuth(c)
	c.Write([]byte{1, 0})
	io.ReadFull(c, h)
	host, port, err := readSocksAddr(c)
	if err != nil || user != tunUser {
		return
	}
	kind := map[byte]string{1: "tcp", cmdUDPRoute: "udp"}[h[1]]
	c.Write([]byte{5, repDirect, 0, 1, 0, 0, 0, 0, 0, 0})
	var status [1]byte
	io.ReadFull(c, status[:])
	var up, down uint64
	var report [16]byte
	for {
		if _, err := io.ReadFull(c, report[:]); err != nil {
			break
		}
		up += binary.BigEndian.Uint64(report[:8])
		down += binary.BigEndian.Uint64(report[8:])
	}
	p.mu.Lock()
	p.seen = append(p.seen, kind+" "+joinHostPort(host, port)+" by "+pass+
		": dial "+string('0'+status[0])+", up "+strconv.FormatUint(up, 10)+", down "+strconv.FormatUint(down, 10))
	p.mu.Unlock()
	p.done <- struct{}{}
}

func TestDirectRoutesAreOurs(t *testing.T) {
	proxy := startDelegatingProxy(t)
	tcpEcho := startEcho(t)
	udpEcho, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := udpEcho.ReadFromUDP(buf)
			if err != nil {
				return
			}
			udpEcho.WriteToUDP(buf[:n], from)
		}
	}()
	var mu sync.Mutex
	var dialed []string
	// Stands in for the physical interface: every destination is an echo.
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, network+" "+addr)
		mu.Unlock()
		target := tcpEcho
		if network == "udp" {
			target = udpEcho.LocalAddr().String()
		}
		return (&net.Dialer{}).DialContext(ctx, network, target)
	}
	dev, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, []netip.Addr{DNSAddr}, 1500)
	if err != nil {
		t.Fatal(err)
	}
	owner := func(src, dst netip.AddrPort, udp bool) string { return "app.exe" }
	e, err := Start(dev, Options{Socks: proxy.addr, DNS: fakeDNS, Owner: owner, Dial: dial, MTU: 1500})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := tnet.DialContext(ctx, "tcp", "1.2.3.4:443")
	if err != nil {
		t.Fatal(err)
	}
	echoOver(t, c, "hi")
	c.Close()
	waitDone(t, proxy)

	u, err := tnet.DialUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), 40002),
		netip.MustParseAddrPort("5.6.7.8:9000"))
	if err != nil {
		t.Fatal(err)
	}
	u.SetDeadline(time.Now().Add(5 * time.Second))
	u.Write([]byte("ping"))
	if _, err := u.Read(make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	// The flow ends when the engine sees it idle; close it from our side.
	u.Close()
	e.Close()
	waitDone(t, proxy)

	mu.Lock()
	defer mu.Unlock()
	if len(dialed) != 2 || dialed[0] != "tcp 1.2.3.4:443" || dialed[1] != "udp 5.6.7.8:9000" {
		t.Fatalf("dialed %v", dialed)
	}
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	want := []string{
		"tcp 1.2.3.4:443 by app.exe: dial 0, up 2, down 2",
		"udp 5.6.7.8:9000 by app.exe: dial 0, up 4, down 4",
	}
	if len(proxy.seen) != 2 || proxy.seen[0] != want[0] || proxy.seen[1] != want[1] {
		t.Fatalf("proxy saw %q, want %q", proxy.seen, want)
	}
}

func waitDone(t *testing.T, p *delegatingProxy) {
	t.Helper()
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		t.Fatal("no report reached the proxy")
	}
}

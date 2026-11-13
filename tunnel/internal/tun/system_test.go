package tun

// Parts of the Windows setup that work without administrator rights.

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"golang.org/x/net/dns/dnsmessage"
)

func TestFindsPhysicalInterfaceAndItsDNS(t *testing.T) {
	p, err := findPhysical(0)
	if err != nil {
		t.Skip("no network:", err)
	}
	if p.Index4 == 0 || len(p.DNS) == 0 {
		t.Fatalf("physical %+v", p)
	}
	t.Logf("physical interface %d (IPv6 %d), DNS %v", p.Index4, p.Index6, p.DNS)
}

func TestUpstreamDNSBypassesTheTUN(t *testing.T) {
	p, err := findPhysical(0)
	if err != nil {
		t.Skip("no network:", err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := p.UpstreamDNS()(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	r := &resolver{cache: newHostCache()}
	if rcode, ok := r.record(resp, "example.com"); !ok || rcode != dnsmessage.RCodeSuccess {
		t.Fatalf("rcode %v", rcode)
	}
	if len(r.cache.byIP) == 0 {
		t.Fatal("no address remembered for example.com")
	}
}

func TestAdapterNeedsAdmin(t *testing.T) {
	sys, err := CreateAdapter()
	if err == nil {
		// Running elevated: the adapter works, take it down again.
		sys.Close()
		t.Skip("elevated: adapter created and removed")
	}
	if !strings.Contains(err.Error(), "администратора") {
		t.Fatalf("unclear error: %v", err)
	}
	t.Logf("as expected without rights: %v", err)
}

// Through a real LocalProxy and the real internet; only the Windows adapter
// is replaced by a userspace stack. Needs LocalProxy running:
// LOCALPROXY_SOCKS=127.0.0.1:3128 go test ./internal/tun -run Live -v
func TestLiveThroughLocalProxy(t *testing.T) {
	socks := os.Getenv("LOCALPROXY_SOCKS")
	if socks == "" {
		t.Skip("LOCALPROXY_SOCKS not set")
	}
	p, err := findPhysical(0)
	if err != nil {
		t.Skip("no network:", err)
	}
	dev, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, []netip.Addr{DNSAddr}, 1500)
	if err != nil {
		t.Fatal(err)
	}
	e, err := Start(dev, Options{Socks: socks, DNS: p.UpstreamDNS(), MTU: 1500})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// TCP: plain HTTP by name.
	addrs, err := tnet.LookupContextHost(ctx, "example.com")
	if err != nil || len(addrs) == 0 {
		t.Fatalf("lookup: %v %v", addrs, err)
	}
	c, err := tnet.DialContext(ctx, "tcp", net.JoinHostPort(addrs[0], "80"))
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(15 * time.Second))
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	head := make([]byte, 12)
	if _, err := io.ReadFull(c, head); err != nil || !strings.HasPrefix(string(head), "HTTP/1.1 ") {
		t.Fatalf("http: %q %v", head, err)
	}
	c.Close()

	// UDP: an NTP query through SOCKS5 UDP ASSOCIATE.
	ntp, err := tnet.LookupContextHost(ctx, "time.windows.com")
	if err != nil || len(ntp) == 0 {
		t.Fatalf("ntp lookup: %v %v", ntp, err)
	}
	u, err := tnet.DialUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), 40123),
		netip.AddrPortFrom(netip.MustParseAddr(ntp[0]), 123))
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	u.SetDeadline(time.Now().Add(10 * time.Second))
	req := make([]byte, 48)
	req[0] = 0x1b
	u.Write(req)
	resp := make([]byte, 128)
	n, err := u.Read(resp)
	if err != nil || n < 48 {
		t.Fatalf("ntp: %d %v", n, err)
	}
	t.Logf("HTTP and NTP through LocalProxy: %+v", e.Stats())
}

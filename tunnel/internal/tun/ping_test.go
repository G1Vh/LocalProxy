package tun

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func TestEchoReplyIsValid(t *testing.T) {
	body, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 7, Seq: 3, Data: []byte("ping")}}).Marshal(nil)
	h := ipv4.Header{Version: 4, Len: 20, TotalLen: 20 + len(body), TTL: 128, Protocol: 1,
		Src: netipToIP("10.0.0.2"), Dst: netipToIP("1.1.1.1")}
	hb, _ := h.Marshal()
	binaryPutChecksum(hb)
	req := append(hb, body...)

	r := echoReply(req, 20)
	if checksum(r[:20]) != 0 || checksum(r[20:]) != 0 {
		t.Fatal("bad checksums in the reply")
	}
	if netip.AddrFrom4([4]byte(r[12:16])).String() != "1.1.1.1" || netip.AddrFrom4([4]byte(r[16:20])).String() != "10.0.0.2" {
		t.Fatal("addresses not swapped")
	}
	m, err := icmp.ParseMessage(1, r[20:])
	if err != nil || m.Type != ipv4.ICMPTypeEchoReply || string(m.Body.(*icmp.Echo).Data) != "ping" {
		t.Fatalf("reply %+v %v", m, err)
	}
}

func netipToIP(s string) []byte { a := netip.MustParseAddr(s).As4(); return a[:] }

func binaryPutChecksum(h []byte) {
	h[10], h[11] = 0, 0
	c := checksum(h)
	h[10], h[11] = byte(c>>8), byte(c)
}

// A program pings through the engine; only hosts the real ping reaches answer.
func TestPingThroughEngine(t *testing.T) {
	dev, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, []netip.Addr{DNSAddr}, 1500)
	if err != nil {
		t.Fatal(err)
	}
	up := netip.MustParseAddr("1.1.1.1")
	pinger := func(_ context.Context, dst netip.Addr, _ []byte, _ uint8) bool { return dst == up }
	e, err := Start(dev, Options{Socks: "127.0.0.1:1", DNS: fakeDNS, Ping: pinger})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	ping := func(dst string) error {
		c, err := tnet.DialPingAddr(netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr(dst))
		if err != nil {
			return err
		}
		defer c.Close()
		msg, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 1, Seq: 1, Data: []byte("hi")}}).Marshal(nil)
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write(msg); err != nil {
			return err
		}
		buf := make([]byte, 1500)
		_, err = c.Read(buf)
		return err
	}
	if err := ping("1.1.1.1"); err != nil {
		t.Fatalf("reachable host: %v", err)
	}
	if err := ping("2.2.2.2"); err == nil {
		t.Fatal("an unreachable host must not answer (the stack would fake it)")
	}
}

// The real thing, from the physical interface (no admin rights needed).
func TestRealPing(t *testing.T) {
	p, err := findPhysical(0)
	if err != nil || !p.Addr4.IsValid() {
		t.Skip("no network")
	}
	var pinger IcmpPinger
	pinger.SetSource(p.Addr4)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !pinger.Ping(ctx, netip.MustParseAddr("1.1.1.1"), []byte("localproxy"), 64) {
		t.Skip("1.1.1.1 does not answer pings from here")
	}
	if pinger.Ping(ctx, netip.MustParseAddr("192.0.2.1"), []byte("x"), 64) {
		t.Fatal("TEST-NET-1 answered")
	}
	t.Logf("real ping from %v works", p.Addr4)
}

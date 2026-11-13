package tun

// End to end without an adapter or admin rights: a "program" on its own
// userspace network stack sends its packets into the engine exactly as
// Windows would through the TUN adapter, and a fake LocalProxy (SOCKS5)
// records what it is asked for.

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"golang.org/x/net/dns/dnsmessage"
)

// fakeProxy is a SOCKS5 server: CONNECT goes to an echo server whatever the
// host, UDP datagrams are echoed back; "blocked.test" is refused.
type fakeProxy struct {
	addr string
	mu   sync.Mutex
	seen []string
}

func (p *fakeProxy) saw(s string) {
	p.mu.Lock()
	p.seen = append(p.seen, s)
	p.mu.Unlock()
}

func (p *fakeProxy) requests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.seen...)
}

func startEcho(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return l.Addr().String()
}

func readSocksAddr(r io.Reader) (string, uint16, error) {
	var t [1]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return "", 0, err
	}
	var host string
	switch t[0] {
	case 1, 4:
		b := make([]byte, map[byte]int{1: 4, 4: 16}[t[0]])
		io.ReadFull(r, b)
		ip, _ := netip.AddrFromSlice(b)
		host = ip.String()
	case 3:
		var l [1]byte
		io.ReadFull(r, l[:])
		b := make([]byte, l[0])
		io.ReadFull(r, b)
		host = string(b)
	default:
		return "", 0, errors.New("atyp")
	}
	var pb [2]byte
	_, err := io.ReadFull(r, pb[:])
	return host, binary.BigEndian.Uint16(pb[:]), err
}

func startFakeProxy(t *testing.T, echo string) *fakeProxy {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	p := &fakeProxy{addr: l.Addr().String()}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go p.serve(c, echo)
		}
	}()
	return p
}

func (p *fakeProxy) serve(c net.Conn, echo string) {
	defer c.Close()
	h := make([]byte, 3)
	if _, err := io.ReadFull(c, h[:2]); err != nil {
		return
	}
	methods := make([]byte, h[1])
	io.ReadFull(c, methods)
	by := ""
	if len(methods) == 1 && methods[0] == 2 {
		c.Write([]byte{5, 2})
		user, pass := readAuth(c)
		if user != processUser {
			return
		}
		by = " by " + pass
		c.Write([]byte{1, 0})
	} else {
		c.Write([]byte{5, 0})
	}
	if _, err := io.ReadFull(c, h); err != nil {
		return
	}
	host, port, err := readSocksAddr(c)
	if err != nil {
		return
	}
	switch h[1] {
	case 1:
		p.saw("tcp " + joinHostPort(host, port) + by)
		if host == "blocked.test" {
			c.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		up, err := net.Dial("tcp", echo)
		if err != nil {
			return
		}
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		go io.Copy(up, c)
		io.Copy(c, up)
		up.Close()
	case 3:
		relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return
		}
		defer relay.Close()
		port := relay.LocalAddr().(*net.UDPAddr).Port
		c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)})
		go func() {
			buf := make([]byte, 2048)
			for {
				n, from, err := relay.ReadFromUDP(buf)
				if err != nil {
					return
				}
				r := &sliceReader{buf[3:n]}
				host, port, err := readSocksAddr(r)
				if err != nil {
					continue
				}
				p.saw("udp " + joinHostPort(host, port) + by)
				reply := append([]byte{0, 0, 0}, socksAddr(host, port)...)
				relay.WriteToUDP(append(reply, r.b...), from)
			}
		}()
		io.Copy(io.Discard, c)
	}
}

func readAuth(r io.Reader) (user, pass string) {
	field := func() string {
		var l [1]byte
		io.ReadFull(r, l[:])
		b := make([]byte, l[0])
		io.ReadFull(r, b)
		return string(b)
	}
	io.ReadFull(r, make([]byte, 1))
	user = field()
	return user, field()
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

// fakeDNS answers example.test with a public-looking address and knows
// nothing about anything else.
func fakeDNS(_ context.Context, query []byte) ([]byte, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: hdr.ID, Response: true})
	b.StartQuestions()
	b.Question(q)
	b.StartAnswers()
	if q.Name.String() == "example.test." && q.Type == dnsmessage.TypeA {
		b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 300},
			dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}})
	} else if q.Name.String() != "example.test." {
		b = dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: hdr.ID, Response: true, RCode: dnsmessage.RCodeNameError})
		b.StartQuestions()
		b.Question(q)
	}
	return b.Finish()
}

func startEngine(t *testing.T) (*netstack.Net, *fakeProxy, *Engine) {
	return startEngineWith(t, nil)
}

func startEngineWith(t *testing.T, owner func(src, dst netip.AddrPort, udp bool) string) (*netstack.Net, *fakeProxy, *Engine) {
	t.Helper()
	proxy := startFakeProxy(t, startEcho(t))
	dev, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.0.0.2")},
		[]netip.Addr{DNSAddr},
		1500,
	)
	if err != nil {
		t.Fatal(err)
	}
	e, err := Start(dev, Options{Socks: proxy.addr, DNS: fakeDNS, Owner: owner, MTU: 1500})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return tnet, proxy, e
}

func echoOver(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != msg {
		t.Fatalf("echo %q, want %q", buf, msg)
	}
}

func TestTCPReachesProxyByName(t *testing.T) {
	tnet, proxy, e := startEngine(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := tnet.LookupContextHost(ctx, "example.test")
	if err != nil || len(addrs) == 0 || addrs[0] != "93.184.216.34" {
		t.Fatalf("lookup: %v %v (the real answer must pass through)", addrs, err)
	}
	c, err := tnet.DialContext(ctx, "tcp", "93.184.216.34:443")
	if err != nil {
		t.Fatal(err)
	}
	echoOver(t, c, "hello through tun")
	c.Close()

	// A name only the channel knows: a fake address, the proxy gets the name.
	addrs, err = tnet.LookupContextHost(ctx, "mysql.office.lan")
	if err != nil || len(addrs) == 0 || !strings.HasPrefix(addrs[0], "198.19.") {
		t.Fatalf("office name: %v %v", addrs, err)
	}
	c, err = tnet.DialContext(ctx, "tcp", addrs[0]+":3306")
	if err != nil {
		t.Fatal(err)
	}
	echoOver(t, c, "select 1")
	c.Close()

	// No name known: the bare address.
	c, err = tnet.DialContext(ctx, "tcp", "1.2.3.4:22")
	if err != nil {
		t.Fatal(err)
	}
	echoOver(t, c, "ssh")
	c.Close()

	want := []string{"tcp example.test:443", "tcp mysql.office.lan:3306", "tcp 1.2.3.4:22"}
	if got := proxy.requests(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("proxy saw %v, want %v", got, want)
	}
	if s := e.Stats(); s.TCP != 3 || s.DNS < 2 {
		t.Fatalf("stats %+v", s)
	}
}

func TestBlockedTCPIsResetQuickly(t *testing.T) {
	tnet, _, e := startEngine(t)
	e.dns.cache.remember(netip.MustParseAddr("5.6.7.8"), "blocked.test", time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	c, err := tnet.DialContext(ctx, "tcp", "5.6.7.8:443")
	if err == nil {
		c.Close()
		t.Fatal("a refused connection must not be accepted")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("refusal took %v", time.Since(start))
	}
	if e.Stats().Refused != 1 {
		t.Fatalf("stats %+v", e.Stats())
	}
}

func TestUDPGoesThroughAssociate(t *testing.T) {
	tnet, proxy, _ := startEngine(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := tnet.LookupContextHost(ctx, "example.test"); err != nil {
		t.Fatal(err)
	}
	c, err := tnet.DialUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), 40000),
		netip.MustParseAddrPort("93.184.216.34:5000"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	for _, msg := range []string{"one", "two"} {
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 100)
		n, err := c.Read(buf)
		if err != nil || string(buf[:n]) != msg {
			t.Fatalf("udp echo %q %v", buf[:n], err)
		}
	}
	got := proxy.requests()
	if len(got) != 2 || got[0] != "udp example.test:5000" {
		t.Fatalf("proxy saw %v", got)
	}
}

func TestHostCacheFakes(t *testing.T) {
	c := newHostCache()
	a, b := c.fake("a.lan"), c.fake("b.lan")
	if a == b || !isFake(a) || c.fake("a.lan") != a {
		t.Fatalf("fakes %v %v", a, b)
	}
	if n, ok := c.name(b); !ok || n != "b.lan" {
		t.Fatalf("name %q %v", n, ok)
	}
	if isFake(netip.MustParseAddr("93.184.216.34")) {
		t.Fatal("real address taken for fake")
	}
}

func joinHostPort(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

func TestProgramIsNamedToProxy(t *testing.T) {
	type flow struct {
		src, dst netip.AddrPort
		udp      bool
	}
	var mu sync.Mutex
	var asked []flow
	owner := func(src, dst netip.AddrPort, udp bool) string {
		mu.Lock()
		asked = append(asked, flow{src, dst, udp})
		mu.Unlock()
		if udp {
			return `C:\Games\game.exe`
		}
		return `C:\Apps\` + strings.Repeat("x", 300) + `\Discord.exe`
	}
	tnet, proxy, _ := startEngineWith(t, owner)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := tnet.DialContext(ctx, "tcp", "1.2.3.4:443")
	if err != nil {
		t.Fatal(err)
	}
	echoOver(t, c, "hi")
	c.Close()
	u, err := tnet.DialUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), 40001),
		netip.MustParseAddrPort("5.6.7.8:9000"))
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	u.SetDeadline(time.Now().Add(5 * time.Second))
	u.Write([]byte("ping"))
	if _, err := u.Read(make([]byte, 10)); err != nil {
		t.Fatal(err)
	}

	// A path too long for SOCKS goes as the file name.
	want := []string{`tcp 1.2.3.4:443 by Discord.exe`, `udp 5.6.7.8:9000 by C:\Games\game.exe`}
	if got := proxy.requests(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("proxy saw %v, want %v", got, want)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(asked) != 2 || asked[0].src.Addr() != netip.MustParseAddr("10.0.0.2") ||
		asked[0].dst != netip.MustParseAddrPort("1.2.3.4:443") || asked[0].udp ||
		asked[1].src != netip.MustParseAddrPort("10.0.0.2:40001") || !asked[1].udp {
		t.Fatalf("owner asked about %+v", asked)
	}
}

package tun

// DNS for the TUN: queries are answered by the real DNS servers (so every
// program, LocalProxy included, gets real addresses), and the answers are
// remembered address → name. When a connection to such an address comes
// through the TUN, LocalProxy gets the name and applies its domain rules.
//
// A name the real DNS does not know (NXDOMAIN: an office name such as
// mysql.office.lan reachable only through a channel) gets a fake address;
// connections to it reach LocalProxy by name, and the channel resolves it.
// A failed lookup is answered SERVFAIL, never faked: a fake address for a
// real name would outlive the TUN in the program's cache.

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	// Answers are remembered at least this long: programs keep addresses
	// longer than the TTL says.
	minRemember  = 30 * time.Minute
	maxNames     = 100_000
	fakeTTL      = 60
	queryTimeout = 3 * time.Second
)

// fakeBase: fake addresses come from 198.19.0.0/16 (inside the TUN's
// 198.18.0.0/15, reserved for benchmarks, never on the internet).
var fakeBase = netip.MustParseAddr("198.19.0.0")

type named struct {
	name    string
	expires time.Time
}

// hostCache maps addresses seen in DNS answers (and fake ones) to names.
type hostCache struct {
	mu    sync.Mutex
	byIP  map[netip.Addr]named
	fakes map[string]netip.Addr
	next  uint32
}

func newHostCache() *hostCache {
	return &hostCache{byIP: map[netip.Addr]named{}, fakes: map[string]netip.Addr{}}
}

func (c *hostCache) remember(ip netip.Addr, name string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.byIP) >= maxNames {
		now := time.Now()
		for k, v := range c.byIP {
			if v.expires.Before(now) {
				delete(c.byIP, k)
			}
		}
		if len(c.byIP) >= maxNames {
			c.byIP = map[netip.Addr]named{}
		}
	}
	c.byIP[ip.Unmap()] = named{name: name, expires: time.Now().Add(max(ttl, minRemember))}
}

// name returns the remembered name of an address, if any.
func (c *hostCache) name(ip netip.Addr) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.byIP[ip.Unmap()]
	return n.name, ok
}

// fake returns the fake address of a name, allocating one if needed.
func (c *hostCache) fake(name string) netip.Addr {
	c.mu.Lock()
	if ip, ok := c.fakes[name]; ok {
		c.mu.Unlock()
		c.remember(ip, name, 0)
		return ip
	}
	c.next = c.next%65533 + 1
	b := fakeBase.As4()
	ip := netip.AddrFrom4([4]byte{b[0], b[1], byte(c.next >> 8), byte(c.next)})
	c.fakes[name] = ip
	c.mu.Unlock()
	c.remember(ip, name, 0)
	return ip
}

func isFake(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.Is4() && ip.As4()[0] == 198 && ip.As4()[1] == 19
}

// Exchange sends a raw DNS query to the real servers.
type Exchange func(ctx context.Context, query []byte) ([]byte, error)

type resolver struct {
	cache    *hostCache
	upstream atomic.Pointer[Exchange]
}

func newResolver(x Exchange) *resolver {
	r := &resolver{cache: newHostCache()}
	r.setExchange(x)
	return r
}

func (r *resolver) setExchange(x Exchange) { r.upstream.Store(&x) }

func (r *resolver) exchange(ctx context.Context, q []byte) ([]byte, error) {
	if x := r.upstream.Load(); x != nil && *x != nil {
		return (*x)(ctx, q)
	}
	return nil, errors.New("нет DNS")
}

// answer handles one DNS query from a program behind the TUN.
func (r *resolver) answer(ctx context.Context, query []byte) []byte {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	name := strings.TrimSuffix(strings.ToLower(q.Name.String()), ".")

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	unknown := false
	if resp, err := r.exchange(ctx, query); err == nil {
		rcode, ok := r.record(resp, name)
		if ok && rcode != dnsmessage.RCodeNameError {
			return resp
		}
		unknown = ok
	}
	// Unknown to the real DNS: a fake address for A, nothing for the rest.
	// No usable answer at all: SERVFAIL, so the program asks again.
	rcode := dnsmessage.RCodeSuccess
	if !unknown {
		rcode = dnsmessage.RCodeServerFailure
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: hdr.ID, Response: true, RecursionDesired: hdr.RecursionDesired, RecursionAvailable: true, RCode: rcode,
	})
	b.EnableCompression()
	b.StartQuestions()
	b.Question(q)
	b.StartAnswers()
	if unknown && q.Type == dnsmessage.TypeA && q.Class == dnsmessage.ClassINET && name != "" {
		b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: fakeTTL},
			dnsmessage.AResource{A: r.cache.fake(name).As4()})
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

// record remembers the addresses of an answer under the asked name (not a
// CNAME target: programs connect by the name they asked for).
func (r *resolver) record(resp []byte, name string) (dnsmessage.RCode, bool) {
	var p dnsmessage.Parser
	hdr, err := p.Start(resp)
	if err != nil {
		return 0, false
	}
	if err := p.SkipAllQuestions(); err != nil {
		return 0, false
	}
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			break
		}
		ttl := time.Duration(h.TTL) * time.Second
		switch h.Type {
		case dnsmessage.TypeA:
			a, err := p.AResource()
			if err == nil {
				r.cache.remember(netip.AddrFrom4(a.A), name, ttl)
			}
		case dnsmessage.TypeAAAA:
			a, err := p.AAAAResource()
			if err == nil {
				r.cache.remember(netip.AddrFrom16(a.AAAA), name, ttl)
			}
		default:
			if err := p.SkipAnswer(); err != nil {
				return hdr.RCode, true
			}
		}
	}
	return hdr.RCode, true
}

// udpExchange asks the servers in turn over UDP, falling back to TCP for
// truncated answers. dial opens sockets that bypass the TUN.
func udpExchange(servers []netip.AddrPort, dial func(ctx context.Context, network, addr string) (net.Conn, error)) Exchange {
	return func(ctx context.Context, query []byte) ([]byte, error) {
		var last error = errors.New("нет DNS-серверов")
		for _, s := range servers {
			resp, err := exchangeOne(ctx, dial, "udp", s.String(), query)
			if err == nil && len(resp) > 2 && resp[2]&0x02 != 0 { // TC bit
				resp, err = exchangeOne(ctx, dial, "tcp", s.String(), query)
			}
			if err == nil {
				return resp, nil
			}
			last = err
		}
		return nil, last
	}
}

func exchangeOne(ctx context.Context, dial func(ctx context.Context, network, addr string) (net.Conn, error), network, addr string, query []byte) ([]byte, error) {
	c, err := dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if network == "tcp" {
		msg := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
		if _, err := c.Write(append(msg, query...)); err != nil {
			return nil, err
		}
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return nil, err
		}
		resp := make([]byte, binary.BigEndian.Uint16(l[:]))
		_, err := io.ReadFull(c, resp)
		return resp, err
	}
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

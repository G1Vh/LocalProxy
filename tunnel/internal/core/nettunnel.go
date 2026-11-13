package core

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// Status is what LocalProxy polls to tell whether a tunnel is alive.
type Status struct {
	// Unix seconds of the last sign of life from the server (WireGuard: the
	// latest handshake); 0 if none yet.
	LastHandshake int64 `json:"lastHandshake"`
	RxBytes       int64 `json:"rx"`
	TxBytes       int64 `json:"tx"`
}

// NetTunnel is a userspace network stack inside a tunnel, as the SOCKS
// server sees it.
type NetTunnel struct {
	net    *netstack.Net
	hasDNS bool
	// Our addresses inside the tunnel.
	local   []netip.Addr
	started time.Time
	alive   func() bool
}

// NewNetTunnel wraps a network stack; alive tells whether the server answers.
// With no DNS servers names are resolved by the system, outside the tunnel.
func NewNetTunnel(n *netstack.Net, local, dns []netip.Addr, alive func() bool) *NetTunnel {
	return &NetTunnel{net: n, hasDNS: len(dns) > 0, local: local, started: time.Now(), alive: alive}
}

// Up reports that the server answers.
func (t *NetTunnel) Up() bool { return t.alive() }

// WarmingUp is true right after start, while the first handshake may still
// be in flight: connections get the full timeout then.
func (t *NetTunnel) WarmingUp() bool {
	return time.Since(t.started) < WarmUp
}

// WarmUp is a variable so tests can shorten it.
var WarmUp = 20 * time.Second

// DialContext resolves the name itself and dials one address of a family the
// tunnel actually has: dialing an IPv6 address through an IPv4-only tunnel
// would only wait for a timeout.
func (t *NetTunnel) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addr, err := t.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	return t.net.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
}

// Resolve looks a name up with the DNS servers from the config, through the
// tunnel (or with the system resolver if the config has none) and picks an
// address our tunnel can reach.
func (t *NetTunnel) Resolve(ctx context.Context, host string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap(), nil
	}
	var addrs []netip.Addr
	if t.hasDNS {
		names, err := t.net.LookupContextHost(ctx, host)
		if err != nil {
			return netip.Addr{}, err
		}
		for _, n := range names {
			if a, err := netip.ParseAddr(n); err == nil {
				addrs = append(addrs, a.Unmap())
			}
		}
	} else {
		var err error
		if addrs, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host); err != nil {
			return netip.Addr{}, err
		}
	}
	return pickAddr(t.reachable(addrs), host)
}

// reachable keeps addresses of the families we have an address for in the tunnel.
func (t *NetTunnel) reachable(addrs []netip.Addr) []netip.Addr {
	has4, has6 := false, false
	for _, a := range t.local {
		has4 = has4 || a.Is4()
		has6 = has6 || a.Is6()
	}
	out := addrs[:0:0]
	for _, a := range addrs {
		if (a.Is4() && has4) || (a.Is6() && has6) {
			out = append(out, a)
		}
	}
	return out
}

// ListenUDP binds to our own tunnel address of that family: the netstack has
// no route for a socket bound to 0.0.0.0.
func (t *NetTunnel) ListenUDP(v6 bool) (net.PacketConn, error) {
	for _, a := range t.local {
		if a.Is6() == v6 {
			return t.net.ListenUDPAddrPort(netip.AddrPortFrom(a, 0))
		}
	}
	return nil, errors.New("в туннеле нет адреса этого семейства (IPv4/IPv6)")
}

// pickAddr prefers IPv4: most tunnels carry it, not all carry IPv6.
func pickAddr(addrs []netip.Addr, host string) (netip.Addr, error) {
	for _, a := range addrs {
		if a.Unmap().Is4() {
			return a.Unmap(), nil
		}
	}
	if len(addrs) > 0 {
		return addrs[0], nil
	}
	return netip.Addr{}, errors.New("нет адресов для " + host)
}

// ResolveSystem looks a name up outside the tunnel, preferring IPv4.
func ResolveSystem(host string) (netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	return pickAddr(addrs, host)
}

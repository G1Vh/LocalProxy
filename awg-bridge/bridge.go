package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// Bridge is a running userspace AmneziaWG tunnel with a SOCKS5 front door.
type Bridge struct {
	dev      *device.Device
	listener net.Listener
	tunnel   *netTunnel
	stop     chan struct{}
	Port     int
}

// Status is what LocalProxy polls to tell whether the tunnel is alive.
type Status struct {
	// Unix seconds of the latest handshake with any peer; 0 if none yet.
	LastHandshake int64 `json:"lastHandshake"`
	RxBytes       int64 `json:"rx"`
	TxBytes       int64 `json:"tx"`
}

// StartBridge brings the tunnel up and starts the SOCKS5 server on listen
// (use "127.0.0.1:0" for a free port).
func StartBridge(cfg *Config, user, pass, listen string) (*Bridge, error) {
	tunDev, tnet, err := netstack.CreateNetTUN(cfg.Addresses, cfg.DNS, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("сетевой стек туннеля: %w", err)
	}
	logger := &device.Logger{
		Verbosef: device.DiscardLogf,
		// stdout carries the protocol with LocalProxy: errors go to stderr.
		Errorf: func(format string, args ...any) { log.Printf("awg: "+format, args...) },
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	uapi, err := cfg.UAPI(resolveSystem)
	if err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("параметры туннеля не приняты: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("туннель не поднялся: %w", err)
	}

	l, err := net.Listen("tcp", listen)
	if err != nil {
		dev.Close()
		return nil, err
	}
	tunnel := &netTunnel{tnet: tnet, hasDNS: len(cfg.DNS) > 0, local: cfg.Addresses, started: time.Now()}
	b := &Bridge{
		dev:      dev,
		listener: l,
		tunnel:   tunnel,
		stop:     make(chan struct{}),
		Port:     l.Addr().(*net.TCPAddr).Port,
	}
	go b.trackHandshakes()
	server := &SocksServer{User: user, Pass: pass, Tunnel: tunnel}
	go server.Serve(l)
	return b, nil
}

func (b *Bridge) Status() (Status, error) {
	text, err := b.dev.IpcGet()
	if err != nil {
		return Status{}, err
	}
	var s Status
	for _, line := range strings.Split(text, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(value, 10, 64)
		switch key {
		case "last_handshake_time_sec":
			s.LastHandshake = max(s.LastHandshake, n)
		case "rx_bytes":
			s.RxBytes += n
		case "tx_bytes":
			s.TxBytes += n
		}
	}
	return s, nil
}

// trackHandshakes keeps the tunnel's idea of "up" fresh for the SOCKS server.
func (b *Bridge) trackHandshakes() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if s, err := b.Status(); err == nil {
			b.tunnel.lastHandshake.Store(s.LastHandshake)
		}
		select {
		case <-b.stop:
			return
		case <-ticker.C:
		}
	}
}

func (b *Bridge) Close() {
	close(b.stop)
	b.listener.Close()
	b.dev.Close()
}

type netTunnel struct {
	tnet   *netstack.Net
	hasDNS bool
	// Our addresses inside the tunnel (Address from the config).
	local []netip.Addr
	// Unix seconds of the last handshake, updated by the bridge.
	lastHandshake atomic.Int64
	started       time.Time
}

// WireGuard re-handshakes every two minutes while traffic flows; older than
// this means the server stopped answering.
const handshakeFresh = 180 * time.Second

func (t *netTunnel) Up() bool {
	last := t.lastHandshake.Load()
	return last > 0 && time.Since(time.Unix(last, 0)) < handshakeFresh
}

// WarmingUp is true right after start, while the first handshake may still
// be in flight: connections get the full timeout then.
func (t *netTunnel) WarmingUp() bool {
	return time.Since(t.started) < warmUp
}

// warmUp is a variable so tests can shorten it.
var warmUp = 20 * time.Second

// DialContext resolves the name itself and dials one address of a family the
// tunnel actually has: dialing an IPv6 address through an IPv4-only tunnel
// would only wait for a timeout.
func (t *netTunnel) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addr, err := t.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	return t.tnet.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
}

// Resolve looks a name up with the DNS servers from the config, through the
// tunnel (or with the system resolver if the config has none) and picks an
// address our tunnel can reach.
func (t *netTunnel) Resolve(ctx context.Context, host string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap(), nil
	}
	var addrs []netip.Addr
	if t.hasDNS {
		names, err := t.tnet.LookupContextHost(ctx, host)
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
func (t *netTunnel) reachable(addrs []netip.Addr) []netip.Addr {
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
func (t *netTunnel) ListenUDP(v6 bool) (net.PacketConn, error) {
	for _, a := range t.local {
		if a.Is6() == v6 {
			return t.tnet.ListenUDPAddrPort(netip.AddrPortFrom(a, 0))
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

func resolveSystem(host string) (netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	return pickAddr(addrs, host)
}

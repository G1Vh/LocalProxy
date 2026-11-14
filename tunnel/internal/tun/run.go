package tun

// The TUN mode runs as its own elevated process (creating an adapter and
// routes needs administrator rights), started by LocalProxy through UAC.
// Without stdin, it talks to LocalProxy over a loopback TCP connection,
// one JSON object per line:
//
//	→ {"event":"hello","token":"..."}            proves it is the one started
//	→ {"event":"interface","v4":10,"v6":0}       physical interface: LocalProxy
//	                                             pins its own sockets to it
//	← "routes"                                   pinned, take the traffic
//	→ {"event":"ready"} | {"event":"error","message":"..."}
//	← "status" → {"event":"status","tcp":..,"udp":..,"dns":..,"refused":..}
//	→ {"event":"interface",...} again whenever the network changes
//
// Closing the connection, or LocalProxy exiting, removes the adapter and
// with it every route and DNS setting.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/windows"

	"github.com/G1Vh/LocalProxy/tunnel/internal/core"
)

// Run serves one TUN session until LocalProxy lets go (or stop closes).
func Run(control, token, socks string, parentPID int, stop <-chan struct{}) error {
	for _, addr := range []string{control, socks} {
		host, _, err := net.SplitHostPort(addr)
		if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
			return errors.New("TUN работает только с LocalProxy на этом компьютере (loopback)")
		}
	}
	c, err := net.Dial("tcp", control)
	if err != nil {
		return err
	}
	defer c.Close()
	if stop != nil {
		go func() {
			<-stop
			c.Close()
		}()
	}
	out := json.NewEncoder(c)
	in := bufio.NewReader(c)
	var sendMu sync.Mutex
	send := func(m map[string]any) {
		sendMu.Lock()
		out.Encode(m)
		sendMu.Unlock()
	}
	fail := func(err error) error {
		send(map[string]any{"event": "error", "message": err.Error()})
		return err
	}
	send(map[string]any{"event": "hello", "token": token})

	sys, err := CreateAdapter()
	if err != nil {
		return fail(err)
	}
	defer sys.Close()
	pinger := &IcmpPinger{}
	pinger.SetSource(sys.Physical.Addr4)
	// Direct routes we open ourselves, pinned to the physical interface (or
	// they would come back into the TUN); the pin follows network changes.
	var bind atomic.Pointer[core.Bind]
	bind.Store(&core.Bind{V4: sys.Physical.Index4, V6: sys.Physical.Index6})
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := net.Dialer{Control: bind.Load().Control}
		return d.DialContext(ctx, network, addr)
	}
	eng, err := Start(sys.Dev, Options{Socks: socks, DNS: sys.Physical.UpstreamDNS(), Ping: pinger.Ping, Owner: ProcessOf, Dial: dial, MTU: mtu})
	if err != nil {
		return fail(err)
	}
	// Routes go first, so programs reconnect around the TUN; then the
	// engine resets what is still open through it; then the adapter goes.
	defer func() {
		sys.ReleaseTraffic()
		eng.Close()
	}()
	log.Printf("tun: адаптер готов, физический интерфейс %d/%d, DNS %v", sys.Physical.Index4, sys.Physical.Index6, sys.Physical.DNS)
	send(map[string]any{"event": "interface", "v4": sys.Physical.Index4, "v6": sys.Physical.Index6})

	if parentPID > 0 {
		go watchParent(uint32(parentPID), c)
	}
	line, err := in.ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "routes" {
		return nil // LocalProxy changed its mind
	}
	if err := sys.TakeTraffic(); err != nil {
		return fail(err)
	}
	send(map[string]any{"event": "ready"})
	log.Printf("tun: весь трафик идёт через LocalProxy (%s)", socks)

	// Another network: new DNS and ping source here, a new pin in LocalProxy.
	stopWatch := sys.Watch(func(p Physical) {
		bind.Store(&core.Bind{V4: p.Index4, V6: p.Index6})
		eng.SetDNS(p.UpstreamDNS())
		pinger.SetSource(p.Addr4)
		send(map[string]any{"event": "interface", "v4": p.Index4, "v6": p.Index6})
	})
	defer stopWatch()

	for {
		line, err := in.ReadString('\n')
		if strings.TrimSpace(line) == "status" {
			s := eng.Stats()
			send(map[string]any{"event": "status", "tcp": s.TCP, "udp": s.UDP, "dns": s.DNS, "refused": s.Refused})
		}
		if err != nil {
			log.Printf("tun: LocalProxy отключился, адаптер убран")
			return nil
		}
	}
}

// watchParent drops the session when LocalProxy exits, even if it crashed.
func watchParent(pid uint32, c net.Conn) {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	windows.WaitForSingleObject(h, windows.INFINITE)
	c.Close()
}

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
	"encoding/json"
	"errors"
	"log"
	"net"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
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
	eng, err := Start(sys.Dev, Options{Socks: socks, DNS: sys.Physical.UpstreamDNS(), Ping: pinger.Ping, Owner: ProcessOf, MTU: mtu})
	if err != nil {
		return fail(err)
	}
	defer eng.Close()
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

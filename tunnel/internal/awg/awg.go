// Package awg runs a WireGuard / AmneziaWG tunnel in userspace.
package awg

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"

	"github.com/G1Vh/LocalProxy/tunnel/internal/core"
)

// Tunnel is a running userspace AmneziaWG tunnel with a SOCKS5 front door.
type Tunnel struct {
	dev      *device.Device
	listener net.Listener
	stop     chan struct{}
	Port     int
	// Unix seconds of the latest handshake, refreshed every second.
	lastHandshake atomic.Int64
}

// WireGuard re-handshakes every two minutes while traffic flows; older than
// this means the server stopped answering.
const handshakeFresh = 180 * time.Second

// Start brings the tunnel up and starts the SOCKS5 server on listen
// (use "127.0.0.1:0" for a free port).
// bind pins the tunnel's UDP socket to the physical interface (TUN mode).
func Start(cfg *Config, user, pass, listen string, bind core.Bind) (*Tunnel, error) {
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

	uapi, err := cfg.UAPI(core.ResolveSystem)
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
	if b, ok := dev.Bind().(conn.BindSocketToInterface); ok && bind.Active() {
		if err := b.BindSocketToInterface4(bind.V4, false); err != nil {
			log.Printf("awg: привязка к интерфейсу: %v", err)
		}
		if bind.V6 != 0 {
			b.BindSocketToInterface6(bind.V6, false)
		}
	}

	l, err := net.Listen("tcp", listen)
	if err != nil {
		dev.Close()
		return nil, err
	}
	b := &Tunnel{
		dev:      dev,
		listener: l,
		stop:     make(chan struct{}),
		Port:     l.Addr().(*net.TCPAddr).Port,
	}
	go b.trackHandshakes()
	tunnel := core.NewNetTunnel(tnet, cfg.Addresses, cfg.DNS, b.up)
	server := &core.SocksServer{User: user, Pass: pass, Tunnel: tunnel}
	go server.Serve(l)
	return b, nil
}

func (b *Tunnel) Status() (core.Status, error) {
	text, err := b.dev.IpcGet()
	if err != nil {
		return core.Status{}, err
	}
	var s core.Status
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
func (b *Tunnel) trackHandshakes() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if s, err := b.Status(); err == nil {
			b.lastHandshake.Store(s.LastHandshake)
		}
		select {
		case <-b.stop:
			return
		case <-ticker.C:
		}
	}
}

func (b *Tunnel) up() bool {
	last := b.lastHandshake.Load()
	return last > 0 && time.Since(time.Unix(last, 0)) < handshakeFresh
}

func (b *Tunnel) Close() {
	close(b.stop)
	b.listener.Close()
	b.dev.Close()
}

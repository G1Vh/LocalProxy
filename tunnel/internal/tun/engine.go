// Package tun sends the whole system's traffic through LocalProxy: a TUN
// adapter takes every packet, a userspace network stack (gVisor) turns them
// back into TCP connections and UDP flows, and each is handed to
// LocalProxy's SOCKS5 port by name, so the usual rules and channels apply.
// DNS queries are answered here (see dns.go) to learn the names.
package tun

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID      = 1
	udpIdle    = 60 * time.Second
	dnsIdle    = 10 * time.Second
	maxPending = 2048
	// Packets the stack may queue for the adapter; a full queue drops them
	// and costs a retransmit.
	queueLen = 4096
)

// Options of the engine.
type Options struct {
	// LocalProxy's SOCKS5 address, e.g. 127.0.0.1:3128.
	Socks string
	// Real DNS servers, reached outside the TUN.
	DNS Exchange
	// Real ping from the physical interface; nil leaves pings unanswered.
	Ping Pinger
	// Owner names the program behind a flow (src is its side): an exe path
	// or "". Nil leaves programs unnamed.
	Owner func(src, dst netip.AddrPort, udp bool) string
	// Dial opens a direct route from the physical interface, so that such
	// routes skip LocalProxy (see direct.go); nil sends everything there.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	MTU  int
}

// Stats for the window.
type Stats struct {
	TCP     int64 `json:"tcp"`
	UDP     int64 `json:"udp"`
	DNS     int64 `json:"dns"`
	Refused int64 `json:"refused"`
}

type Engine struct {
	dev       tun.Device
	stack     *stack.Stack
	ep        *channel.Endpoint
	opts      Options
	dns       *resolver
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once
	wmu       sync.Mutex
	pings     chan struct{}

	tcpCount, udpCount, dnsCount, refused atomic.Int64
}

// Start runs the engine on dev until Close.
func Start(dev tun.Device, opts Options) (*Engine, error) {
	if opts.MTU == 0 {
		opts.MTU = 1500
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(queueLen, uint32(opts.MTU), "")
	// Packets from the TUN come from Windows' own stack with valid
	// checksums: checking them again is wasted work.
	ep.LinkEPCapabilities |= stack.CapabilityRXChecksumOffload
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, errors.New(err.String())
	}
	// Accept packets for any address and answer from it: every destination
	// on the internet "lives" here.
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})
	tuneTCP(s)

	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{
		dev:    dev,
		stack:  s,
		ep:     ep,
		opts:   opts,
		dns:    newResolver(opts.DNS),
		ctx:    ctx,
		cancel: cancel,
		pings:  make(chan struct{}, maxPings),
	}
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(s, 0, maxPending, e.handleTCP).HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udp.NewForwarder(s, e.handleUDP).HandlePacket)

	e.wg.Add(2)
	go e.fromDevice()
	go e.toDevice()
	return e, nil
}

// tuneTCP sets the stack's TCP the way other userspace stacks on Windows
// do (Tailscale, sing-box, Xray): CUBIC with buffers that may grow to 8 MiB
// suits fast links better than gVisor's Reno capped at 4 MiB; RACK loss
// detection is off, as it stalls connections under load.
func tuneTCP(s *stack.Stack) {
	opts := []tcpip.SettableTransportProtocolOption{
		ptr(tcpip.TCPSACKEnabled(true)),
		ptr(tcpip.CongestionControlOption("cubic")),
		ptr(tcpip.TCPModerateReceiveBufferOption(true)),
		ptr(tcpip.TCPDelayEnabled(false)),
		ptr(tcpip.TCPRecovery(0)),
		&tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 1 << 20, Max: 8 << 20},
		&tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 1 << 20, Max: 8 << 20},
	}
	for _, o := range opts {
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, o); err != nil {
			log.Printf("tun: TCP option %T: %v", o, err)
		}
	}
}

func ptr[T any](v T) *T { return &v }

// SetDNS switches the real DNS servers (the network changed).
func (e *Engine) SetDNS(x Exchange) { e.dns.setExchange(x) }

func (e *Engine) Stats() Stats {
	return Stats{TCP: e.tcpCount.Load(), UDP: e.udpCount.Load(), DNS: e.dnsCount.Load(), Refused: e.refused.Load()}
}

// Close stops the engine; the device is closed too.
func (e *Engine) Close() {
	e.closeOnce.Do(func() {
		e.cancel()
		e.dev.Close()
		e.ep.Close()
		e.stack.Close()
		e.wg.Wait()
	})
}

func (e *Engine) fromDevice() {
	defer e.wg.Done()
	batch := e.dev.BatchSize()
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	sizes := make([]int, batch)
	for {
		n, err := e.dev.Read(bufs, sizes, 0)
		if err != nil {
			if e.ctx.Err() == nil {
				log.Printf("tun: чтение адаптера: %v", err)
			}
			return
		}
		for i := range n {
			pkt := bufs[i][:sizes[i]]
			if len(pkt) == 0 || e.interceptPing(pkt) {
				continue
			}
			var proto tcpip.NetworkProtocolNumber
			switch pkt[0] >> 4 {
			case 4:
				proto = header.IPv4ProtocolNumber
			case 6:
				proto = header.IPv6ProtocolNumber
			default:
				continue
			}
			pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
			e.ep.InjectInbound(proto, pkb)
			pkb.DecRef()
		}
	}
}

func (e *Engine) toDevice() {
	defer e.wg.Done()
	for {
		pkb := e.ep.ReadContext(e.ctx)
		if pkb.IsNil() {
			return
		}
		view := pkb.ToView()
		pkb.DecRef()
		e.write(view.AsSlice())
		view.Release()
	}
}

func (e *Engine) write(pkt []byte) {
	e.wmu.Lock()
	_, err := e.dev.Write([][]byte{pkt}, 0)
	e.wmu.Unlock()
	if err != nil && e.ctx.Err() == nil {
		log.Printf("tun: запись в адаптер: %v", err)
	}
}

func addrOf(a tcpip.Address) netip.Addr {
	ip, _ := netip.AddrFromSlice(a.AsSlice())
	return ip.Unmap()
}

// target is what LocalProxy is asked to connect to: the name the program
// looked up, or the bare address. A fake address without a name is stale.
func (e *Engine) target(ip netip.Addr) (string, bool) {
	if name, ok := e.dns.cache.name(ip); ok {
		return name, true
	}
	if isFake(ip) {
		return "", false
	}
	return ip.String(), true
}

// owner names the program behind a flow, if the engine can.
func (e *Engine) owner(src, dst netip.AddrPort, udp bool) string {
	if e.opts.Owner == nil {
		return ""
	}
	return e.opts.Owner(src, dst, udp)
}

func (e *Engine) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dst, port := addrOf(id.LocalAddress), id.LocalPort
	src := netip.AddrPortFrom(addrOf(id.RemoteAddress), id.RemotePort)
	go func() {
		if port == 53 && isDNSAddr(dst) {
			e.acceptTCP(r, nil, nil)
			return
		}
		host, ok := e.target(dst)
		if !ok {
			e.refused.Add(1)
			r.Complete(true)
			return
		}
		// Connect upstream first: a blocked site gets a reset right away
		// instead of an accepted connection that goes nowhere.
		ctx, cancel := context.WithTimeout(e.ctx, socksTimeout)
		process := e.owner(src, netip.AddrPortFrom(dst, port), false)
		up, err := socksConnect(ctx, e.opts.Socks, process, e.delegate(dst), host, port)
		cancel()
		var ctl net.Conn
		if errors.Is(err, errDirect) {
			ctl, err = up, nil
			if up = e.dialDirect(ctl, "tcp", netip.AddrPortFrom(dst, port)); up == nil {
				err = errDirect
			}
		}
		if err != nil {
			e.refused.Add(1)
			r.Complete(true)
			return
		}
		e.acceptTCP(r, up, ctl)
	}()
}

// delegate: whether a direct route to dst may be ours to open. A fake
// address has no real destination behind it: LocalProxy resolves the name.
func (e *Engine) delegate(dst netip.Addr) bool {
	return e.opts.Dial != nil && !isFake(dst)
}

// acceptTCP completes the handshake with the program and pipes the
// connection to up (or serves DNS over TCP when up is nil). A direct route
// we opened ourselves has ctl, LocalProxy's connection for the byte counts.
func (e *Engine) acceptTCP(r *tcp.ForwarderRequest, up, ctl net.Conn) {
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		if up != nil {
			up.Close()
		}
		if ctl != nil {
			ctl.Close()
		}
		r.Complete(true)
		return
	}
	r.Complete(false)
	ep.SocketOptions().SetKeepAlive(true)
	conn := gonet.NewTCPConn(&wq, ep)
	if up == nil {
		e.serveDNSOverTCP(conn)
		return
	}
	e.tcpCount.Add(1)
	if ctl == nil {
		pipe(conn, up, nil)
		return
	}
	t := newTally(ctl)
	pipe(conn, up, t)
	t.close()
}

// copyBufs: 256 KiB per direction moves a bulk transfer in a few large
// writes instead of many 32 KiB ones (io.Copy's default).
var copyBufs = sync.Pool{New: func() any { b := make([]byte, 256<<10); return &b }}

// pipe joins the program's connection a to b; t, if any, counts the bytes
// (a → b is "up").
func pipe(a, b net.Conn, t *tally) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn, n *atomic.Uint64) {
		buf := copyBufs.Get().(*[]byte)
		// Hidden behind plain Reader/Writer so that io.CopyBuffer uses buf
		// rather than the connections' own ReadFrom/WriteTo with small buffers.
		var r io.Reader = struct{ io.Reader }{src}
		if n != nil {
			r = counted{src, n}
		}
		io.CopyBuffer(struct{ io.Writer }{dst}, r, *buf)
		copyBufs.Put(buf)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
		done <- struct{}{}
	}
	var up, down *atomic.Uint64
	if t != nil {
		up, down = &t.up, &t.down
	}
	go cp(b, a, up)
	go cp(a, b, down)
	<-done
	<-done
	a.Close()
	b.Close()
}

func (e *Engine) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	dst, port := addrOf(id.LocalAddress), id.LocalPort
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		return
	}
	conn := gonet.NewUDPConn(e.stack, &wq, ep)
	if port == 53 {
		// Any DNS query, to whatever server, is answered here.
		go e.serveDNS(conn)
		return
	}
	src := netip.AddrPortFrom(addrOf(id.RemoteAddress), id.RemotePort)
	go e.relayUDP(conn, src, dst, port)
}

func (e *Engine) serveDNS(conn *gonet.UDPConn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	for {
		conn.SetReadDeadline(time.Now().Add(dnsIdle))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		e.dnsCount.Add(1)
		if resp := e.dns.answer(e.ctx, append([]byte(nil), buf[:n]...)); resp != nil {
			conn.Write(resp)
		}
	}
}

func (e *Engine) serveDNSOverTCP(conn *gonet.TCPConn) {
	defer conn.Close()
	for {
		conn.SetReadDeadline(time.Now().Add(dnsIdle))
		var l [2]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return
		}
		q := make([]byte, int(l[0])<<8|int(l[1]))
		if _, err := io.ReadFull(conn, q); err != nil {
			return
		}
		e.dnsCount.Add(1)
		resp := e.dns.answer(e.ctx, q)
		if resp == nil {
			return
		}
		if _, err := conn.Write(append([]byte{byte(len(resp) >> 8), byte(len(resp))}, resp...)); err != nil {
			return
		}
	}
}

func (e *Engine) relayUDP(conn *gonet.UDPConn, src netip.AddrPort, dst netip.Addr, port uint16) {
	defer conn.Close()
	host, ok := e.target(dst)
	if !ok {
		e.refused.Add(1)
		return
	}
	ctx, cancel := context.WithTimeout(e.ctx, socksTimeout)
	process := e.owner(src, netip.AddrPortFrom(dst, port), true)
	var assoc *socksAssociation
	var err error
	if e.delegate(dst) {
		var ctl net.Conn
		assoc, ctl, err = socksUDPRoute(ctx, e.opts.Socks, process, host, port)
		if errors.Is(err, errDirect) {
			cancel()
			e.relayUDPDirect(conn, ctl, netip.AddrPortFrom(dst, port))
			return
		}
	} else {
		assoc, err = socksAssociate(ctx, e.opts.Socks, process)
	}
	cancel()
	if err != nil {
		e.refused.Add(1)
		return
	}
	defer assoc.Close()
	e.udpCount.Add(1)

	var last atomic.Int64
	touch := func() { last.Store(time.Now().UnixNano()) }
	touch()
	go func() {
		buf := make([]byte, 65535)
		for {
			payload, err := assoc.recv(buf)
			if err != nil {
				conn.Close()
				return
			}
			touch()
			conn.Write(payload)
		}
	}()
	buf := make([]byte, 65535)
	for {
		conn.SetReadDeadline(time.Now().Add(udpIdle))
		n, err := conn.Read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || time.Since(time.Unix(0, last.Load())) >= udpIdle {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue // replies are still coming
			}
			return
		}
		touch()
		if err := assoc.send(host, port, buf[:n]); err != nil {
			return
		}
	}
}

// DNSAddr is the DNS server Windows is told to use: an address on the TUN
// that nothing else answers for.
var DNSAddr = netip.MustParseAddr("198.18.0.2")

func isDNSAddr(ip netip.Addr) bool { return ip == DNSAddr }

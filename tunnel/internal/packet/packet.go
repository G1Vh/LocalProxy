// Package packet runs a tunnel whose protocol hands over IP packets (SSTP;
// L2TP or OpenConnect would fit as well): a userspace network stack on our
// side, the SOCKS5 server for LocalProxy, keepalive and reconnects. A
// protocol only has to connect and move packets.
package packet

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"

	"github.com/G1Vh/LocalProxy/tunnel/internal/core"
)

// Conn is one live connection to the server.
type Conn interface {
	// ReadPacket returns the next IP packet from the server.
	ReadPacket() ([]byte, error)
	// WritePacket sends an IP packet; a protocol may drop what it cannot carry.
	WritePacket(pkt []byte) error
	// Idle is how long the server has been silent.
	Idle() time.Duration
	// Ping asks the server for a sign of life.
	Ping() error
	Close()
}

// Session is a connection and what the server granted on it.
type Session struct {
	Conn Conn
	IP   netip.Addr
	DNS  []netip.Addr
	MTU  int
}

// Dial connects to the server; wantIP asks for the previous address again.
type Dial func(ctx context.Context, wantIP netip.Addr) (*Session, error)

const (
	connectTimeout = 20 * time.Second
	// A quiet server is pinged after this much silence...
	pingAfter = 20 * time.Second
	// ...and given up on after this much.
	deadAfter = 60 * time.Second
)

// Backoff between reconnect attempts; a variable so tests can shorten it.
var Backoff = []time.Duration{time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second, 30 * time.Second}

// Tunnel reconnects on its own. If the server then hands out another
// address, the network stack would be stuck with the old one: the process
// exits and LocalProxy starts it anew.
type Tunnel struct {
	name     string
	dial     Dial
	ip       netip.Addr
	dev      tun.Device
	listener net.Listener
	Port     int

	// The live connection; nil while reconnecting.
	conn     atomic.Pointer[Conn]
	rx, tx   atomic.Int64
	stop     chan struct{}
	stopOnce sync.Once
	fatal    atomic.Pointer[func(error)]
}

// Start connects, builds the network stack with the granted address and
// starts the SOCKS5 server on listen. name prefixes log lines.
func Start(name string, dial Dial, user, pass, listen string) (*Tunnel, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	sess, err := dial(ctx, netip.Addr{})
	if err != nil {
		return nil, err
	}
	dev, tnet, err := netstack.CreateNetTUN([]netip.Addr{sess.IP}, sess.DNS, sess.MTU)
	if err != nil {
		sess.Conn.Close()
		return nil, fmt.Errorf("сетевой стек туннеля: %w", err)
	}
	l, err := net.Listen("tcp", listen)
	if err != nil {
		sess.Conn.Close()
		dev.Close()
		return nil, err
	}
	t := &Tunnel{
		name:     name,
		dial:     dial,
		ip:       sess.IP,
		dev:      dev,
		listener: l,
		Port:     l.Addr().(*net.TCPAddr).Port,
		stop:     make(chan struct{}),
	}
	t.SetFatal(func(err error) {
		log.Printf("%s: %v", name, err)
		os.Exit(3)
	})
	log.Printf("%s: подключено, адрес %s, DNS %v, MTU %d", name, sess.IP, sess.DNS, sess.MTU)
	t.conn.Store(&sess.Conn)
	go t.supervise(sess.Conn)
	go t.fromStack()
	go t.keepalive()
	tunnel := core.NewNetTunnel(tnet, []netip.Addr{sess.IP}, sess.DNS, t.Connected)
	server := &core.SocksServer{User: user, Pass: pass, Tunnel: tunnel}
	go server.Serve(l)
	return t, nil
}

// SetFatal replaces what happens on an unrecoverable error (tests).
func (t *Tunnel) SetFatal(f func(error)) { t.fatal.Store(&f) }

func (t *Tunnel) current() Conn {
	if p := t.conn.Load(); p != nil {
		return *p
	}
	return nil
}

// Connected: a live connection whose server still answers.
func (t *Tunnel) Connected() bool {
	c := t.current()
	return c != nil && c.Idle() < deadAfter
}

func (t *Tunnel) stopped() bool {
	select {
	case <-t.stop:
		return true
	default:
		return false
	}
}

// supervise reads the connection and replaces it when it dies.
func (t *Tunnel) supervise(conn Conn) {
	for {
		err := t.toStack(conn)
		t.conn.Store(nil)
		conn.Close()
		if t.stopped() {
			return
		}
		log.Printf("%s: соединение потеряно (%v), переподключение", t.name, err)
		if conn = t.reconnect(); conn == nil {
			return
		}
	}
}

func (t *Tunnel) reconnect() Conn {
	for attempt := 0; ; attempt++ {
		select {
		case <-t.stop:
			return nil
		case <-time.After(Backoff[min(attempt, len(Backoff)-1)]):
		}
		ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
		sess, err := t.dial(ctx, t.ip)
		cancel()
		if err != nil {
			log.Printf("%s: переподключение не удалось: %v", t.name, err)
			continue
		}
		if sess.IP != t.ip {
			sess.Conn.Close()
			(*t.fatal.Load())(fmt.Errorf("после переподключения сервер выдал другой адрес (%s вместо %s)", sess.IP, t.ip))
			return nil
		}
		if t.stopped() {
			sess.Conn.Close()
			return nil
		}
		log.Printf("%s: снова подключено", t.name)
		t.conn.Store(&sess.Conn)
		return sess.Conn
	}
}

// toStack hands the server's packets to the network stack until the
// connection ends.
func (t *Tunnel) toStack(conn Conn) error {
	for {
		pkt, err := conn.ReadPacket()
		if err != nil {
			return err
		}
		t.rx.Add(int64(len(pkt)))
		if _, err := t.dev.Write([][]byte{pkt}, 0); err != nil && !t.stopped() {
			log.Printf("%s: сетевой стек: %v", t.name, err)
		}
	}
}

// fromStack sends what the network stack emits to the server.
func (t *Tunnel) fromStack() {
	batch := t.dev.BatchSize()
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	sizes := make([]int, batch)
	for {
		n, err := t.dev.Read(bufs, sizes, 0)
		if err != nil {
			return // device closed
		}
		conn := t.current()
		if conn == nil {
			continue // reconnecting: dropped, TCP inside will resend
		}
		for i := range n {
			pkt := bufs[i][:sizes[i]]
			if err := conn.WritePacket(pkt); err != nil {
				conn.Close() // toStack notices and reconnects
				break
			}
			t.tx.Add(int64(len(pkt)))
		}
	}
}

// keepalive pings a quiet server and drops a connection that stays silent.
func (t *Tunnel) keepalive() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-ticker.C:
		}
		conn := t.current()
		if conn == nil {
			continue
		}
		switch idle := conn.Idle(); {
		case idle > deadAfter:
			log.Printf("%s: сервер молчит %v", t.name, idle.Round(time.Second))
			conn.Close()
		case idle > pingAfter:
			conn.Ping()
		}
	}
}

// Status: "handshake" is the last sign of life from the server.
func (t *Tunnel) Status() (core.Status, error) {
	s := core.Status{RxBytes: t.rx.Load(), TxBytes: t.tx.Load()}
	if c := t.current(); c != nil && t.Connected() {
		s.LastHandshake = time.Now().Add(-c.Idle()).Unix()
	}
	return s, nil
}

func (t *Tunnel) Close() {
	t.stopOnce.Do(func() {
		close(t.stop)
		t.listener.Close()
		if c := t.current(); c != nil {
			c.Close()
		}
		t.dev.Close()
	})
}

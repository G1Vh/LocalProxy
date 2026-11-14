package tun

// Direct routes the engine opens itself. LocalProxy still decides every
// route (rules, programs, the feed), but when the answer is "direct" it
// leaves the dial to us: the bytes then go straight from the TUN to a socket
// on the physical interface instead of taking a lap through LocalProxy over
// loopback. Over the SOCKS5 connection that asked, we tell LocalProxy how
// the dial went and keep reporting the bytes, for its traffic statistics.

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

const (
	dialTimeout = 10 * time.Second
	// How often bytes are reported while a connection is busy.
	reportEvery = time.Second
	// WSAETIMEDOUT: what LocalProxy shows for a dial that ran out of time.
	errTimedOut = 10060
)

// reportDial tells LocalProxy how the dial went: 0, or 1 and the OS error.
func reportDial(ctl net.Conn, err error) {
	msg := []byte{0}
	if err != nil {
		msg = binary.BigEndian.AppendUint32([]byte{1}, osCode(err))
	}
	ctl.SetWriteDeadline(time.Now().Add(socksTimeout))
	ctl.Write(msg)
	ctl.SetWriteDeadline(time.Time{})
}

// osCode is the Windows error behind a failed dial, so that LocalProxy words
// it as it does its own; 0 if there is none.
func osCode(err error) uint32 {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return uint32(errno)
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return errTimedOut
	}
	return 0
}

// tally counts a direct connection's bytes and reports them to LocalProxy
// over ctl: every second while they change, and once more at the end.
type tally struct {
	up, down atomic.Uint64
	ctl      net.Conn
	stop     chan struct{}
	done     sync.WaitGroup
}

func newTally(ctl net.Conn) *tally {
	t := &tally{ctl: ctl, stop: make(chan struct{})}
	t.done.Add(1)
	go t.run()
	return t
}

func (t *tally) run() {
	defer t.done.Done()
	tick := time.NewTicker(reportEvery)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			t.flush()
		case <-t.stop:
			t.flush()
			return
		}
	}
}

func (t *tally) flush() {
	up, down := t.up.Swap(0), t.down.Swap(0)
	if up == 0 && down == 0 {
		return
	}
	var msg [16]byte
	binary.BigEndian.PutUint64(msg[:8], up)
	binary.BigEndian.PutUint64(msg[8:], down)
	// LocalProxy gone (restarting): the connection itself goes on.
	t.ctl.SetWriteDeadline(time.Now().Add(socksTimeout))
	t.ctl.Write(msg[:])
}

// close sends the last report and lets LocalProxy go.
func (t *tally) close() {
	close(t.stop)
	t.done.Wait()
	t.ctl.Close()
}

// counted adds what is read through it to n.
type counted struct {
	r io.Reader
	n *atomic.Uint64
}

func (c counted) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(uint64(n))
	return n, err
}

// dialDirect opens the program's own destination from the physical
// interface and reports the result to LocalProxy; nil if it failed (ctl is
// then closed).
func (e *Engine) dialDirect(ctl net.Conn, network string, dst netip.AddrPort) net.Conn {
	ctx, cancel := context.WithTimeout(e.ctx, dialTimeout)
	out, err := e.opts.Dial(ctx, network, dst.String())
	cancel()
	reportDial(ctl, err)
	if err != nil {
		ctl.Close()
		return nil
	}
	return out
}

// relayUDPDirect carries one UDP flow between the program and its
// destination by ourselves.
func (e *Engine) relayUDPDirect(conn *gonet.UDPConn, ctl net.Conn, dst netip.AddrPort) {
	out := e.dialDirect(ctl, "udp", dst)
	if out == nil {
		e.refused.Add(1)
		return
	}
	defer out.Close()
	t := newTally(ctl)
	defer t.close()
	e.udpCount.Add(1)

	var last atomic.Int64
	touch := func() { last.Store(time.Now().UnixNano()) }
	touch()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := out.Read(buf)
			if err != nil {
				var errno syscall.Errno
				if errors.As(err, &errno) {
					continue // a "port unreachable" bounced back; the flow goes on
				}
				conn.Close()
				return
			}
			touch()
			t.down.Add(uint64(n))
			conn.Write(buf[:n])
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
		t.up.Add(uint64(n))
		if _, err := out.Write(buf[:n]); err != nil {
			var errno syscall.Errno
			if errors.As(err, &errno) {
				continue // e.g. an ICMP "port unreachable" for an earlier datagram
			}
			return
		}
	}
}

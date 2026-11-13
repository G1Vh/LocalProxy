package tun

// Ping through the TUN. ICMP cannot go through SOCKS5, so echo requests are
// taken out before the network stack (which would happily answer every one
// itself), sent for real from the physical interface, and answered only if
// the real host answers. A ping to a name known only to a channel (a fake
// address) gets no answer: the channel cannot carry it.

import (
	"context"
	"encoding/binary"
	"net/netip"
	"time"
)

const pingTimeout = 4 * time.Second

// Pinger sends one real echo request; true if the host answered.
type Pinger func(ctx context.Context, dst netip.Addr, payload []byte, ttl uint8) bool

// maxPings in flight; more are dropped like a lossy link would.
const maxPings = 64

// interceptPing handles an IPv4 echo request; reports whether it took the
// packet.
func (e *Engine) interceptPing(pkt []byte) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != 1 {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+8 || pkt[ihl] != 8 || pkt[ihl+1] != 0 {
		return false
	}
	// Fragments are left alone.
	if binary.BigEndian.Uint16(pkt[6:8])&0x3fff != 0 {
		return true
	}
	if e.opts.Ping == nil {
		return true
	}
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	if isFake(dst) {
		return true
	}
	select {
	case e.pings <- struct{}{}:
	default:
		return true
	}
	req := append([]byte(nil), pkt...)
	go func() {
		defer func() { <-e.pings }()
		ctx, cancel := context.WithTimeout(e.ctx, pingTimeout)
		defer cancel()
		if !e.opts.Ping(ctx, dst, req[ihl+8:], pkt[8]) {
			return
		}
		e.write(echoReply(req, ihl))
	}()
	return true
}

// echoReply turns an IPv4 echo request into its reply.
func echoReply(req []byte, ihl int) []byte {
	r := append([]byte(nil), req...)
	copy(r[12:16], req[16:20])
	copy(r[16:20], req[12:16])
	r[8] = 64  // TTL
	r[ihl] = 0 // echo reply
	r[ihl+2], r[ihl+3] = 0, 0
	binary.BigEndian.PutUint16(r[ihl+2:], checksum(r[ihl:]))
	r[10], r[11] = 0, 0
	binary.BigEndian.PutUint16(r[10:], checksum(r[:ihl]))
	return r
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

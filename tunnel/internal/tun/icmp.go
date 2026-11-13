package tun

// Real ping from the physical interface (iphlpapi IcmpSendEcho2Ex, no admin
// rights needed). The source address pins it to that interface, so it does
// not come back into the TUN.

import (
	"context"
	"net/netip"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho2Ex = iphlpapi.NewProc("IcmpSendEcho2Ex")
)

type ipOptionInformation struct {
	TTL         uint8
	TOS         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr
}

type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInformation
}

// IcmpPinger pings from a source address that can change with the network.
type IcmpPinger struct {
	source atomic.Uint32 // IPv4 in memory order of in_addr; 0: any
}

// SetSource sets the address of the physical interface.
func (p *IcmpPinger) SetSource(a netip.Addr) {
	if !a.Is4() {
		p.source.Store(0)
		return
	}
	b := a.As4()
	p.source.Store(*(*uint32)(unsafe.Pointer(&b)))
}

func inAddr(a netip.Addr) uint32 {
	b := a.As4()
	return *(*uint32)(unsafe.Pointer(&b))
}

// Ping is a Pinger.
func (p *IcmpPinger) Ping(ctx context.Context, dst netip.Addr, payload []byte, ttl uint8) bool {
	if !dst.Is4() {
		return false
	}
	timeout := uint32(pingTimeout.Milliseconds())
	if dl, ok := ctx.Deadline(); ok {
		if left := dl.Sub(time.Now()).Milliseconds(); left > 0 && left < int64(timeout) {
			timeout = uint32(left)
		}
	}
	h, _, err := procIcmpCreateFile.Call()
	if windows.Handle(h) == windows.InvalidHandle {
		_ = err
		return false
	}
	defer procIcmpCloseHandle.Call(h)
	if len(payload) == 0 {
		payload = []byte{0}
	}
	if ttl == 0 {
		ttl = 128
	}
	opts := ipOptionInformation{TTL: ttl}
	reply := make([]byte, int(unsafe.Sizeof(icmpEchoReply{}))+len(payload)+8+16)
	n, _, _ := procIcmpSendEcho2Ex.Call(
		h, 0, 0, 0,
		uintptr(p.source.Load()),
		uintptr(inAddr(dst)),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(len(reply)),
		uintptr(timeout),
	)
	if n == 0 {
		return false
	}
	r := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
	return r.Status == 0 // IP_SUCCESS
}

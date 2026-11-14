package tun

// Which program a flow from the TUN belongs to: Windows keeps the owning
// process of every TCP connection and UDP socket (GetExtendedTcpTable /
// GetExtendedUdpTable); the program's side of the flow is its own socket,
// with the TUN address as the source. The service runs as LocalSystem, so
// every process can be named.

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	// Connections only, without listening sockets: a shorter table to fetch
	// and scan for every new connection.
	tcpTableOwnerPidConnections = 4
	udpTableOwnerPid            = 1
	afInet                      = 2
	afInet6                     = 23
	// A process id may be reused by another program after a while.
	pathTTL = 30 * time.Second
)

// ProcessOf returns the exe path of the program that owns the flow
// src → dst (src is the program's side), or "" if it is not found.
func ProcessOf(src, dst netip.AddrPort, udp bool) string {
	src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
	dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	// A dual-stack socket may sit in the other family's table.
	families := [2]uint32{afInet, afInet6}
	if src.Addr().Is6() {
		families = [2]uint32{afInet6, afInet}
	}
	for _, f := range families {
		var pid uint32
		var ok bool
		if udp {
			pid, ok = udpOwner(f, src)
		} else {
			pid, ok = tcpOwner(f, src, dst)
		}
		if ok {
			return imagePath(pid)
		}
	}
	return ""
}

// ownerTable fetches a table with its rows after the 4-byte count.
func ownerTable(proc *windows.LazyProc, family, class uint32) (rows []byte, count int) {
	size := uint32(16 << 10)
	for range 4 {
		buf := make([]byte, size)
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
			0, uintptr(family), uintptr(class), 0)
		if r == 0 {
			buf = buf[:size]
			if len(buf) < 4 {
				return nil, 0
			}
			return buf[4:], int(binary.LittleEndian.Uint32(buf))
		}
		if windows.Errno(r) != windows.ERROR_INSUFFICIENT_BUFFER {
			return nil, 0
		}
		size += 4096 // the table may grow before the next call
	}
	return nil, 0
}

// The tables keep addresses and ports in network byte order.
func rowAddr(b []byte, family uint32) netip.AddrPort {
	if family == afInet {
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[:4])), binary.BigEndian.Uint16(b[4:6]))
	}
	// 16 address bytes, 4 scope id bytes, then the port.
	return netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[:16])).Unmap(), binary.BigEndian.Uint16(b[20:22]))
}

func tcpOwner(family uint32, local, remote netip.AddrPort) (uint32, bool) {
	rows, n := ownerTable(procGetExtendedTcpTable, family, tcpTableOwnerPidConnections)
	// MIB_TCPROW_OWNER_PID: state, local addr+port, remote addr+port, pid.
	// MIB_TCP6ROW_OWNER_PID: local (addr, scope, port), remote (same), state, pid.
	size, l, r, pid := 24, 4, 12, 20
	if family == afInet6 {
		size, l, r, pid = 56, 0, 24, 52
	}
	for i := 0; i < n && (i+1)*size <= len(rows); i++ {
		row := rows[i*size : (i+1)*size]
		if rowAddr(row[l:], family) == local && rowAddr(row[r:], family) == remote {
			return binary.LittleEndian.Uint32(row[pid:]), true
		}
	}
	return 0, false
}

func udpOwner(family uint32, local netip.AddrPort) (uint32, bool) {
	rows, n := ownerTable(procGetExtendedUdpTable, family, udpTableOwnerPid)
	// MIB_UDPROW_OWNER_PID: addr, port, pid; MIB_UDP6ROW_OWNER_PID: addr,
	// scope, port, pid.
	size, pid := 12, 8
	if family == afInet6 {
		size, pid = 28, 24
	}
	var found uint32
	var ok bool
	for i := 0; i < n && (i+1)*size <= len(rows); i++ {
		row := rows[i*size : (i+1)*size]
		a := rowAddr(row, family)
		if a.Port() != local.Port() {
			continue
		}
		// A socket bound to this very address beats one bound to any.
		if a.Addr() == local.Addr() {
			return binary.LittleEndian.Uint32(row[pid:]), true
		}
		if a.Addr().IsUnspecified() {
			found, ok = binary.LittleEndian.Uint32(row[pid:]), true
		}
	}
	return found, ok
}

var paths struct {
	sync.Mutex
	m map[uint32]cachedPath
}

type cachedPath struct {
	at   time.Time
	path string
}

// imagePath is the full exe path of a process, cached briefly.
func imagePath(pid uint32) string {
	if pid == 0 || pid == 4 {
		return "System"
	}
	paths.Lock()
	defer paths.Unlock()
	if c, ok := paths.m[pid]; ok && time.Since(c.at) < pathTTL {
		return c.path
	}
	if paths.m == nil || len(paths.m) > 4096 {
		paths.m = map[uint32]cachedPath{}
	}
	p := queryImage(pid)
	paths.m[pid] = cachedPath{time.Now(), p}
	return p
}

func queryImage(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

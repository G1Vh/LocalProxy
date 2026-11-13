package tun

// Windows side of the TUN mode: the Wintun adapter, its addresses, routes
// and DNS server. Needs administrator rights. Everything set here belongs to
// the adapter and disappears with it when the process ends.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/G1Vh/LocalProxy/tunnel/internal/core"
)

const (
	adapterName = "LocalProxy"
	mtu         = 1500
)

// A fixed GUID keeps Windows from piling up "LocalProxy 2", "3"... network
// profiles across runs.
var adapterGUID = windows.GUID{Data1: 0x6c6f6361, Data2: 0x6c70, Data3: 0x7278, Data4: [8]byte{0x79, 0x2d, 0x74, 0x75, 0x6e, 0x00, 0x00, 0x01}}

var (
	tunAddr4 = netip.MustParsePrefix("198.18.0.1/15")
	tunAddr6 = netip.MustParsePrefix("fdfe:dcba:9876::1/126")
	// Two halves beat the default route without replacing it.
	routes4 = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}
	routes6 = []netip.Prefix{netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1")}
)

// Physical is the interface the internet goes through without us.
type Physical struct {
	Index4, Index6 uint32
	DNS            []netip.Addr
	// IPv4 address of the interface: the source of real pings.
	Addr4 netip.Addr
}

// System is the adapter while it is up.
type System struct {
	Dev      tun.Device
	luid     winipcfg.LUID
	Physical Physical
}

// CreateAdapter brings up the Wintun adapter (wintun.dll next to the exe)
// and finds the physical interface before routes change anything.
func CreateAdapter() (*System, error) {
	dev, err := tun.CreateTUNWithRequestedGUID(adapterName, &adapterGUID, mtu)
	if err != nil {
		return nil, fmt.Errorf("адаптер Wintun не создан (нужны права администратора и wintun.dll): %w", err)
	}
	luid := winipcfg.LUID(dev.(*tun.NativeTun).LUID())
	phys, err := findPhysical(luid)
	if err != nil {
		dev.Close()
		return nil, err
	}
	if err := luid.SetIPAddressesForFamily(windows.AF_INET, []netip.Prefix{tunAddr4}); err != nil {
		dev.Close()
		return nil, fmt.Errorf("адрес адаптера: %w", err)
	}
	if phys.Index6 != 0 {
		luid.SetIPAddressesForFamily(windows.AF_INET6, []netip.Prefix{tunAddr6})
	}
	return &System{Dev: dev, luid: luid, Physical: phys}, nil
}

// findPhysical: the interface of the best default route other than ours,
// per family, and its DNS servers.
func findPhysical(exclude winipcfg.LUID) (Physical, error) {
	var p Physical
	idx4, luid4, err := bestDefault(windows.AF_INET, exclude)
	if err != nil {
		return p, errors.New("нет подключения к сети: не найден маршрут по умолчанию")
	}
	p.Index4 = idx4
	if idx6, _, err := bestDefault(windows.AF_INET6, exclude); err == nil {
		p.Index6 = idx6
	}
	p.Addr4 = interfaceAddr4(luid4)
	dns, _ := luid4.DNS()
	for _, a := range dns {
		if a.IsValid() && !a.IsUnspecified() && !(a.Is6() && a.IsLinkLocalUnicast()) {
			p.DNS = append(p.DNS, a)
		}
	}
	if len(p.DNS) == 0 {
		// The interface gets DNS from nowhere: public resolvers then.
		p.DNS = []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}
	}
	return p, nil
}

func interfaceAddr4(luid winipcfg.LUID) netip.Addr {
	rows, err := winipcfg.GetUnicastIPAddressTable(windows.AF_INET)
	if err != nil {
		return netip.Addr{}
	}
	for _, r := range rows {
		a := r.Address.Addr()
		if r.InterfaceLUID == luid && a.Is4() && !a.IsLinkLocalUnicast() {
			return a
		}
	}
	return netip.Addr{}
}

func bestDefault(family winipcfg.AddressFamily, exclude winipcfg.LUID) (uint32, winipcfg.LUID, error) {
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return 0, 0, err
	}
	type cand struct {
		index  uint32
		luid   winipcfg.LUID
		metric uint32
	}
	var cs []cand
	for _, r := range rows {
		if r.DestinationPrefix.PrefixLength != 0 || r.InterfaceLUID == exclude {
			continue
		}
		iface, err := r.InterfaceLUID.IPInterface(family)
		if err != nil || !iface.Connected {
			continue
		}
		cs = append(cs, cand{r.InterfaceIndex, r.InterfaceLUID, r.Metric + iface.Metric})
	}
	if len(cs) == 0 {
		return 0, 0, errors.New("no default route")
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].metric < cs[j].metric })
	return cs[0].index, cs[0].luid, nil
}

// TakeTraffic adds the routes that send everything into the adapter and
// makes its DNS server the first Windows asks.
func (s *System) TakeTraffic() error {
	// Only add: SetRoutes would first flush the routes Windows itself keeps
	// on the adapter (its subnet, broadcast, multicast) and trip over them.
	add := func(p netip.Prefix, hop netip.Addr) error {
		err := s.luid.AddRoute(p, hop, 0)
		if err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			return fmt.Errorf("маршрут %s: %w", p, err)
		}
		return nil
	}
	for _, p := range routes4 {
		if err := add(p, netip.IPv4Unspecified()); err != nil {
			return err
		}
	}
	if s.Physical.Index6 != 0 {
		for _, p := range routes6 {
			if err := add(p, netip.IPv6Unspecified()); err != nil {
				return err
			}
		}
	}
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		iface, err := s.luid.IPInterface(family)
		if err != nil {
			continue
		}
		iface.UseAutomaticMetric = false
		iface.Metric = 1
		iface.Set()
	}
	if err := s.luid.SetDNS(windows.AF_INET, []netip.Addr{DNSAddr}, nil); err != nil {
		return fmt.Errorf("DNS адаптера: %w", err)
	}
	return nil
}

// Close removes the adapter, and with it its routes and DNS.
func (s *System) Close() { s.Dev.Close() }

// UpstreamDNS asks the physical interface's DNS servers, outside the TUN.
func (p Physical) UpstreamDNS() Exchange {
	bind := core.Bind{V4: p.Index4, V6: p.Index6}
	d := &net.Dialer{Control: bind.Control}
	var servers []netip.AddrPort
	for _, a := range p.DNS {
		servers = append(servers, netip.AddrPortFrom(a, 53))
	}
	return udpExchange(servers, func(ctx context.Context, network, addr string) (net.Conn, error) {
		return d.DialContext(ctx, network, addr)
	})
}

// Watch reports a new physical interface (Wi-Fi instead of cable, a dock,
// a VPN client of the system) after routes or addresses settle. Our own
// routes on the TUN never count.
func (s *System) Watch(onChange func(Physical)) (stop func()) {
	changed := make(chan struct{}, 1)
	poke := func() {
		select {
		case changed <- struct{}{}:
		default:
		}
	}
	rcb, _ := winipcfg.RegisterRouteChangeCallback(func(_ winipcfg.MibNotificationType, r *winipcfg.MibIPforwardRow2) {
		if r != nil && r.InterfaceLUID != s.luid && r.DestinationPrefix.PrefixLength == 0 {
			poke()
		}
	})
	acb, _ := winipcfg.RegisterUnicastAddressChangeCallback(func(_ winipcfg.MibNotificationType, a *winipcfg.MibUnicastIPAddressRow) {
		if a != nil && a.InterfaceLUID != s.luid {
			poke()
		}
	})
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-changed:
			}
			// Windows changes routes in bursts: wait for the dust to settle.
			time.Sleep(settleDelay)
			select {
			case <-changed:
			default:
			}
			p, err := findPhysical(s.luid)
			if err != nil || samePhysical(p, s.Physical) {
				continue // no network at all keeps the old pin: nothing to reach anyway
			}
			log.Printf("tun: сеть сменилась: интерфейс %d/%d → %d/%d, DNS %v", s.Physical.Index4, s.Physical.Index6, p.Index4, p.Index6, p.DNS)
			s.Physical = p
			onChange(p)
		}
	}()
	return func() {
		close(done)
		if rcb != nil {
			rcb.Unregister()
		}
		if acb != nil {
			acb.Unregister()
		}
	}
}

// settleDelay is a variable so tests can shorten it.
var settleDelay = 2 * time.Second

func samePhysical(a, b Physical) bool {
	if a.Index4 != b.Index4 || a.Index6 != b.Index6 || a.Addr4 != b.Addr4 || len(a.DNS) != len(b.DNS) {
		return false
	}
	for i := range a.DNS {
		if a.DNS[i] != b.DNS[i] {
			return false
		}
	}
	return true
}

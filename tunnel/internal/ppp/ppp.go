// Package ppp is the client side of PPP (RFC 1661, 1332, 1334, 2759) for
// tunnels that carry it (SSTP; L2TP would too): link setup, login, IPv4
// address negotiation, then IPv4 packets. Only what a client needs: no
// compression, no IPv6, no multilink.
package ppp

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/G1Vh/LocalProxy/tunnel/internal/mschap"
)

const (
	ProtoIPv4 uint16 = 0x0021
	ProtoIPCP uint16 = 0x8021
	ProtoLCP  uint16 = 0xc021
	ProtoPAP  uint16 = 0xc023
	ProtoCHAP uint16 = 0xc223
)

// Control protocol codes (LCP, IPCP); PAP and CHAP reuse 1–4 their own way.
const (
	ConfReq  = 1
	ConfAck  = 2
	ConfNak  = 3
	ConfRej  = 4
	TermReq  = 5
	TermAck  = 6
	ProtoRej = 8
	EchoReq  = 9
	EchoRep  = 10
)

const CHAPMSv2 = 0x81

// Link carries whole PPP frames; the SSTP connection implements it.
type Link interface {
	ReadFrame() ([]byte, error)
	WriteFrame(frame []byte) error
	SetReadDeadline(t time.Time) error
}

func EncodeFrame(proto uint16, payload []byte) []byte {
	b := make([]byte, 4+len(payload))
	b[0], b[1] = 0xff, 0x03
	binary.BigEndian.PutUint16(b[2:], proto)
	copy(b[4:], payload)
	return b
}

// DecodeFrame accepts frames with and without the address/control bytes and
// with a compressed (one-byte) protocol field.
func DecodeFrame(b []byte) (uint16, []byte, error) {
	if len(b) >= 2 && b[0] == 0xff && b[1] == 0x03 {
		b = b[2:]
	}
	if len(b) >= 1 && b[0]&1 == 1 {
		return uint16(b[0]), b[1:], nil
	}
	if len(b) < 2 {
		return 0, nil, errors.New("PPP: короткий кадр")
	}
	return binary.BigEndian.Uint16(b), b[2:], nil
}

// Packet is an LCP/IPCP/PAP/CHAP packet.
type Packet struct {
	Code, ID byte
	Data     []byte
}

func ParsePacket(b []byte) (Packet, error) {
	if len(b) < 4 {
		return Packet{}, errors.New("PPP: короткий пакет")
	}
	n := int(binary.BigEndian.Uint16(b[2:]))
	if n < 4 || n > len(b) {
		return Packet{}, errors.New("PPP: неверная длина пакета")
	}
	return Packet{Code: b[0], ID: b[1], Data: b[4:n]}, nil
}

// Bytes encodes the packet.
func (p Packet) Bytes() []byte {
	b := make([]byte, 4+len(p.Data))
	b[0], b[1] = p.Code, p.ID
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	copy(b[4:], p.Data)
	return b
}

// Option is a configuration option of LCP or IPCP.
type Option struct {
	Type byte
	Data []byte
}

func ParseOptions(b []byte) ([]Option, error) {
	var out []Option
	for len(b) > 0 {
		if len(b) < 2 || b[1] < 2 || int(b[1]) > len(b) {
			return nil, errors.New("PPP: неверный формат параметров")
		}
		out = append(out, Option{Type: b[0], Data: b[2:b[1]]})
		b = b[b[1]:]
	}
	return out, nil
}

func EncodeOptions(opts []Option) []byte {
	var b []byte
	for _, o := range opts {
		b = append(b, o.Type, byte(2+len(o.Data)))
		b = append(b, o.Data...)
	}
	return b
}

// Result is what the server granted.
type Result struct {
	IP  netip.Addr
	DNS []netip.Addr
	// MTU: the server's MRU, at most 1500.
	MTU   int
	magic uint32
}

// negotiation runs the PPP setup to the point where IPv4 can flow.
type negotiation struct {
	link       Link
	user, pass string
	wantIP     netip.Addr
	// onAuth runs once the login succeeded, with the HLAK (zeros if the
	// method yields no keys): SSTP sends its crypto binding there.
	onAuth func(hlak []byte) error

	nextID byte

	lcpOurs                      []Option
	lcpOursID                    byte
	lcpAckedByPeer, lcpAckedPeer bool
	lcpOpen                      bool
	lcpSent                      time.Time
	lcpTries                     int
	auth                         uint16 // protocol the server asked for; 0 = none
	peerMRU                      int
	authDone                     bool
	papID                        byte
	papSent                      time.Time
	// MS-CHAPv2 exchange in progress: our and the server's challenge, our answer.
	chap                           struct{ peer, auth, resp []byte }
	ipcpOurs                       []Option
	ipcpOursID                     byte
	ipcpAckedByPeer, ipcpAckedPeer bool
	ipcpSent                       time.Time
	ipcpTries                      int

	result Result
}

const (
	pppRetry    = 3 * time.Second
	pppMaxTries = 10
)

func randUint32() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

func (n *negotiation) id() byte {
	n.nextID++
	return n.nextID
}

func (n *negotiation) send(proto uint16, p Packet) error {
	return n.link.WriteFrame(EncodeFrame(proto, p.Bytes()))
}

// Config is the client's side of the negotiation.
type Config struct {
	User, Password string
	// Address to ask for (after a reconnect); zero lets the server choose.
	WantIP netip.Addr
	// OnAuth runs once the login succeeded, with the key it yields (32 zero
	// bytes for methods without keys): SSTP sends its crypto binding there.
	OnAuth func(hlak []byte) error
}

// Negotiate runs PPP over link until IPCP is open or the deadline passes.
func Negotiate(link Link, cfg Config, deadline time.Time) (*Result, error) {
	n := &negotiation{link: link, user: cfg.User, pass: cfg.Password, wantIP: cfg.WantIP, onAuth: cfg.OnAuth, peerMRU: 1500}
	n.result.magic = randUint32()
	n.lcpOurs = []Option{{Type: 5, Data: binary.BigEndian.AppendUint32(nil, n.result.magic)}}
	if err := n.sendLCPReq(); err != nil {
		return nil, err
	}
	defer link.SetReadDeadline(time.Time{})
	for !(n.lcpOpen && n.authDone && n.ipcpAckedByPeer && n.ipcpAckedPeer) {
		if time.Now().After(deadline) {
			return nil, n.stuck()
		}
		if err := n.retransmit(); err != nil {
			return nil, err
		}
		link.SetReadDeadline(minTime(time.Now().Add(time.Second), deadline))
		frame, err := link.ReadFrame()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		if err != nil {
			return nil, err
		}
		proto, payload, err := DecodeFrame(frame)
		if err != nil {
			continue
		}
		if err := n.handle(proto, payload); err != nil {
			return nil, err
		}
	}
	n.result.MTU = min(n.peerMRU, 1500)
	return &n.result, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (n *negotiation) stuck() error {
	switch {
	case !n.lcpOpen:
		return errors.New("сервер не согласовал PPP-соединение")
	case !n.authDone:
		return errors.New("сервер не ответил на вход по логину и паролю")
	default:
		return errors.New("сервер не выдал IP-адрес")
	}
}

func (n *negotiation) retransmit() error {
	now := time.Now()
	switch {
	case !n.lcpAckedByPeer && now.Sub(n.lcpSent) > pppRetry:
		if n.lcpTries >= pppMaxTries {
			return n.stuck()
		}
		return n.sendLCPReq()
	case n.lcpOpen && n.auth == ProtoPAP && !n.authDone && now.Sub(n.papSent) > pppRetry:
		return n.sendPAP()
	case n.authDone && !n.ipcpAckedByPeer && now.Sub(n.ipcpSent) > pppRetry:
		if n.ipcpTries >= pppMaxTries {
			return n.stuck()
		}
		return n.sendIPCPReq()
	}
	return nil
}

func (n *negotiation) sendLCPReq() error {
	n.lcpOursID = n.id()
	n.lcpSent = time.Now()
	n.lcpTries++
	return n.send(ProtoLCP, Packet{Code: ConfReq, ID: n.lcpOursID, Data: EncodeOptions(n.lcpOurs)})
}

func (n *negotiation) handle(proto uint16, payload []byte) error {
	switch proto {
	case ProtoLCP:
		return n.handleLCP(payload)
	case ProtoCHAP:
		if n.lcpOpen {
			return n.handleCHAP(payload)
		}
	case ProtoPAP:
		if n.lcpOpen {
			return n.handlePAP(payload)
		}
	case ProtoIPCP:
		if n.authDone {
			return n.handleIPCP(payload)
		}
	case ProtoIPv4:
		// Too early: dropped, the sender retries.
	default:
		if n.lcpOpen {
			return n.protocolReject(proto, payload)
		}
	}
	return nil
}

// protocolReject tells the server we do not speak this protocol (IPv6,
// compression and the like): it then stops offering it.
func (n *negotiation) protocolReject(proto uint16, payload []byte) error {
	return rejectProtocol(n.link, n.id(), proto, payload, n.peerMRU)
}

func rejectProtocol(link Link, id byte, proto uint16, payload []byte, mru int) error {
	data := binary.BigEndian.AppendUint16(nil, proto)
	data = append(data, payload[:min(len(payload), max(mru-10, 0))]...)
	return link.WriteFrame(EncodeFrame(ProtoLCP, Packet{Code: ProtoRej, ID: id, Data: data}.Bytes()))
}

func (n *negotiation) handleLCP(payload []byte) error {
	p, err := ParsePacket(payload)
	if err != nil {
		return nil
	}
	switch p.Code {
	case ConfReq:
		return n.answerLCPReq(p)
	case ConfAck:
		if p.ID == n.lcpOursID {
			n.lcpAckedByPeer = true
		}
	case ConfNak, ConfRej:
		if p.ID != n.lcpOursID {
			return nil
		}
		opts, err := ParseOptions(p.Data)
		if err != nil {
			return nil
		}
		// We only ask for a magic number: drop or renew it as told.
		for _, o := range opts {
			if o.Type == 5 && p.Code == ConfNak {
				n.result.magic = randUint32()
				n.lcpOurs = []Option{{Type: 5, Data: binary.BigEndian.AppendUint32(nil, n.result.magic)}}
			} else {
				n.lcpOurs = removeOption(n.lcpOurs, o.Type)
			}
		}
		return n.sendLCPReq()
	case TermReq:
		n.send(ProtoLCP, Packet{Code: TermAck, ID: p.ID})
		return errors.New("сервер закрыл PPP-соединение")
	case EchoReq:
		return n.send(ProtoLCP, echoReply(p, n.result.magic))
	}
	n.lcpOpen = n.lcpAckedByPeer && n.lcpAckedPeer
	if n.lcpOpen && n.auth == 0 && !n.authDone {
		return n.finishAuth(make([]byte, 32))
	}
	if n.lcpOpen && n.auth == ProtoPAP && n.papSent.IsZero() {
		return n.sendPAP()
	}
	return nil
}

func echoReply(p Packet, magic uint32) Packet {
	data := binary.BigEndian.AppendUint32(nil, magic)
	if len(p.Data) > 4 {
		data = append(data, p.Data[4:]...)
	}
	return Packet{Code: EchoRep, ID: p.ID, Data: data}
}

func removeOption(opts []Option, typ byte) []Option {
	out := opts[:0:0]
	for _, o := range opts {
		if o.Type != typ {
			out = append(out, o)
		}
	}
	return out
}

// answerLCPReq accepts what is harmless, steers the login to MS-CHAPv2 or
// PAP and refuses callback and multilink.
func (n *negotiation) answerLCPReq(p Packet) error {
	opts, err := ParseOptions(p.Data)
	if err != nil {
		return nil
	}
	var nak, rej []Option
	auth := uint16(0)
	mru := 1500
	for _, o := range opts {
		switch o.Type {
		case 1: // MRU
			if len(o.Data) == 2 {
				mru = int(binary.BigEndian.Uint16(o.Data))
			}
		case 2, 5, 7, 8, 19: // ACCM, magic number, PFC, ACFC, endpoint discriminator
		case 3: // authentication protocol
			if len(o.Data) >= 2 {
				ap := binary.BigEndian.Uint16(o.Data)
				switch {
				case ap == ProtoCHAP && len(o.Data) == 3 && o.Data[2] == CHAPMSv2, ap == ProtoPAP:
					auth = ap
					continue
				}
			}
			nak = append(nak, Option{Type: 3, Data: []byte{0xc2, 0x23, CHAPMSv2}})
		default: // callback, multilink and anything unknown
			rej = append(rej, o)
		}
	}
	switch {
	case len(rej) > 0:
		return n.send(ProtoLCP, Packet{Code: ConfRej, ID: p.ID, Data: EncodeOptions(rej)})
	case len(nak) > 0:
		return n.send(ProtoLCP, Packet{Code: ConfNak, ID: p.ID, Data: EncodeOptions(nak)})
	}
	n.auth, n.peerMRU = auth, mru
	n.lcpAckedPeer = true
	return n.send(ProtoLCP, Packet{Code: ConfAck, ID: p.ID, Data: p.Data})
}

func (n *negotiation) sendPAP() error {
	if n.papID == 0 || !n.papSent.IsZero() {
		n.papID = n.id()
	}
	n.papSent = time.Now()
	data := append([]byte{byte(len(n.user))}, n.user...)
	data = append(data, byte(len(n.pass)))
	data = append(data, n.pass...)
	return n.send(ProtoPAP, Packet{Code: 1, ID: n.papID, Data: data})
}

func (n *negotiation) handlePAP(payload []byte) error {
	p, err := ParsePacket(payload)
	if err != nil || n.authDone {
		return nil
	}
	switch p.Code {
	case 2: // Authenticate-Ack
		return n.finishAuth(make([]byte, 32))
	case 3: // Authenticate-Nak
		msg := ""
		if len(p.Data) > 0 && int(p.Data[0]) < len(p.Data) {
			msg = string(p.Data[1 : 1+int(p.Data[0])])
		}
		return loginError(msg)
	}
	return nil
}

func loginError(serverMsg string) error {
	if s := strings.TrimSpace(serverMsg); s != "" {
		return fmt.Errorf("неверный логин или пароль (сервер: %s)", s)
	}
	return errors.New("неверный логин или пароль")
}

func (n *negotiation) handleCHAP(payload []byte) error {
	p, err := ParsePacket(payload)
	if err != nil || n.authDone {
		return nil
	}
	switch p.Code {
	case 1: // Challenge
		if n.auth != ProtoCHAP {
			return errors.New("сервер требует вход, который не поддерживается (нужен MS-CHAPv2 или PAP)")
		}
		if len(p.Data) < 17 || p.Data[0] != 16 {
			return errors.New("PPP: неверный запрос MS-CHAPv2")
		}
		auth := append([]byte(nil), p.Data[1:17]...)
		peer := make([]byte, 16)
		rand.Read(peer)
		resp := mschap.NTResponse(auth, peer, n.user, n.pass)
		n.chap.peer, n.chap.auth, n.chap.resp = peer, auth, resp
		value := append(append(append(append([]byte{49}, peer...), make([]byte, 8)...), resp...), 0)
		return n.send(ProtoCHAP, Packet{Code: 2, ID: p.ID, Data: append(value, n.user...)})
	case 3: // Success: "S=<auth response> M=<message>"
		if n.chap.resp == nil {
			return nil
		}
		want := mschap.AuthenticatorResponse(n.pass, n.chap.resp, n.chap.peer, n.chap.auth, n.user)
		if !strings.HasPrefix(strings.ToUpper(string(p.Data)), want) {
			return errors.New("сервер не подтвердил, что знает пароль: возможно, это не тот сервер")
		}
		return n.finishAuth(mschap.ClientHLAK(n.pass, n.chap.resp))
	case 4: // Failure: "E=691 R=0 C=... V=3 M=..."
		return chapFailure(string(p.Data))
	}
	return nil
}

var chapErrorRe = regexp.MustCompile(`E=(\d+)`)

func chapFailure(msg string) error {
	code := ""
	if m := chapErrorRe.FindStringSubmatch(msg); m != nil {
		code = m[1]
	}
	text := ""
	if i := strings.Index(msg, "M="); i >= 0 {
		text = msg[i+2:]
	}
	switch code {
	case "646":
		return errors.New("вход запрещён в это время суток")
	case "647":
		return errors.New("учётная запись отключена")
	case "648":
		return errors.New("срок действия пароля истёк")
	case "649":
		return errors.New("у учётной записи нет права удалённого доступа")
	default:
		return loginError(text)
	}
}

func (n *negotiation) finishAuth(hlak []byte) error {
	n.authDone = true
	if n.onAuth != nil {
		if err := n.onAuth(hlak); err != nil {
			return err
		}
	}
	n.ipcpOurs = []Option{
		{Type: 3, Data: addr4(n.wantIP)},
		{Type: 129, Data: make([]byte, 4)}, // primary DNS
		{Type: 131, Data: make([]byte, 4)}, // secondary DNS
	}
	return n.sendIPCPReq()
}

func addr4(a netip.Addr) []byte {
	if a.Is4() {
		b := a.As4()
		return b[:]
	}
	return make([]byte, 4)
}

func (n *negotiation) sendIPCPReq() error {
	n.ipcpOursID = n.id()
	n.ipcpSent = time.Now()
	n.ipcpTries++
	return n.send(ProtoIPCP, Packet{Code: ConfReq, ID: n.ipcpOursID, Data: EncodeOptions(n.ipcpOurs)})
}

func (n *negotiation) handleIPCP(payload []byte) error {
	p, err := ParsePacket(payload)
	if err != nil {
		return nil
	}
	switch p.Code {
	case ConfReq:
		opts, err := ParseOptions(p.Data)
		if err != nil {
			return nil
		}
		var rej []Option
		for _, o := range opts {
			if o.Type != 3 { // only the server's own address is welcome
				rej = append(rej, o)
			}
		}
		if len(rej) > 0 {
			return n.send(ProtoIPCP, Packet{Code: ConfRej, ID: p.ID, Data: EncodeOptions(rej)})
		}
		n.ipcpAckedPeer = true
		return n.send(ProtoIPCP, Packet{Code: ConfAck, ID: p.ID, Data: p.Data})
	case ConfAck:
		if p.ID != n.ipcpOursID {
			return nil
		}
		n.ipcpAckedByPeer = true
		n.result.DNS = nil
		for _, o := range n.ipcpOurs {
			if len(o.Data) != 4 {
				continue
			}
			a := netip.AddrFrom4([4]byte(o.Data))
			switch {
			case o.Type == 3:
				n.result.IP = a
			case (o.Type == 129 || o.Type == 131) && !a.IsUnspecified():
				n.result.DNS = append(n.result.DNS, a)
			}
		}
		if !n.result.IP.IsValid() || n.result.IP.IsUnspecified() {
			return errors.New("сервер не выдал IP-адрес")
		}
	case ConfNak, ConfRej:
		if p.ID != n.ipcpOursID {
			return nil
		}
		opts, err := ParseOptions(p.Data)
		if err != nil {
			return nil
		}
		for _, o := range opts {
			if p.Code == ConfRej {
				if o.Type == 3 {
					return errors.New("сервер не выдаёт IP-адрес")
				}
				n.ipcpOurs = removeOption(n.ipcpOurs, o.Type)
				continue
			}
			for i := range n.ipcpOurs {
				if n.ipcpOurs[i].Type == o.Type && len(o.Data) == 4 {
					n.ipcpOurs[i].Data = o.Data
				}
			}
		}
		return n.sendIPCPReq()
	case TermReq:
		n.send(ProtoIPCP, Packet{Code: TermAck, ID: p.ID})
		return errors.New("сервер закрыл IP-соединение")
	}
	return nil
}

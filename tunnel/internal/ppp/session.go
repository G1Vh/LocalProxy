package ppp

import "errors"

// Session carries IPv4 over a negotiated link and keeps the link healthy:
// answers LCP echoes, refuses protocols we do not speak and reports a server
// that starts the negotiation over (the caller then reconnects).
type Session struct {
	link  Link
	magic uint32
	id    byte
}

func NewSession(link Link, res *Result) *Session {
	return &Session{link: link, magic: res.magic}
}

// ReadIP returns the next IPv4 packet from the server.
func (s *Session) ReadIP() ([]byte, error) {
	for {
		frame, err := s.link.ReadFrame()
		if err != nil {
			return nil, err
		}
		proto, payload, err := DecodeFrame(frame)
		if err != nil {
			continue
		}
		switch proto {
		case ProtoIPv4:
			return payload, nil
		case ProtoLCP:
			p, err := ParsePacket(payload)
			if err != nil {
				continue
			}
			switch p.Code {
			case EchoReq:
				if err := s.link.WriteFrame(EncodeFrame(ProtoLCP, echoReply(p, s.magic).Bytes())); err != nil {
					return nil, err
				}
			case TermReq:
				s.link.WriteFrame(EncodeFrame(ProtoLCP, Packet{Code: TermAck, ID: p.ID}.Bytes()))
				return nil, errors.New("сервер закрыл PPP-соединение")
			case ConfReq:
				return nil, errors.New("сервер начал согласование PPP заново")
			}
		case ProtoIPCP:
			if p, err := ParsePacket(payload); err == nil && (p.Code == ConfReq || p.Code == TermReq) {
				return nil, errors.New("сервер начал согласование IP заново")
			}
		default:
			s.id++
			if err := rejectProtocol(s.link, s.id, proto, payload, 1500); err != nil {
				return nil, err
			}
		}
	}
}

// WriteIP sends an IPv4 packet; anything else (IPv6) is dropped, since
// only IPv4 was negotiated.
func (s *Session) WriteIP(pkt []byte) error {
	if len(pkt) == 0 || pkt[0]>>4 != 4 {
		return nil
	}
	return s.link.WriteFrame(EncodeFrame(ProtoIPv4, pkt))
}

package awg

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
)

// Config is a parsed wg-quick / AmneziaWG .conf file.
type Config struct {
	Addresses []netip.Addr
	DNS       []netip.Addr
	MTU       int
	// Device-level UAPI lines (private key, AmneziaWG obfuscation, timings).
	device []string
	Peers  []Peer
}

type Peer struct {
	PublicKey string // hex
	// Endpoint as written in the file; resolved when building UAPI.
	Endpoint string
	lines    []string
}

const defaultMTU = 1420

// Keys that only make sense to wg-quick on a real interface.
var ignoredInterfaceKeys = map[string]bool{
	"table": true, "preup": true, "postup": true, "predown": true, "postdown": true,
	"saveconfig": true, "fwmark": true,
}

// ParseConf reads a WireGuard or AmneziaWG config. AmneziaWG parameters
// (Jc, S1, H1, I1, HeaderProtectionKey, ContentPaddingAddition, ...) are passed
// to the device under their UAPI names, so new ones work without changes here;
// plain WireGuard files simply have none of them.
func ParseConf(text string) (*Config, error) {
	cfg := &Config{MTU: defaultMTU}
	var section string
	var peer *Peer
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(stripComment(sc.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch section {
			case "interface":
			case "peer":
				cfg.Peers = append(cfg.Peers, Peer{})
				peer = &cfg.Peers[len(cfg.Peers)-1]
			default:
				return nil, fmt.Errorf("строка %d: неизвестный раздел [%s]", lineNo, section)
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("строка %d: ожидалось «Ключ = значение»", lineNo)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		var err error
		switch section {
		case "interface":
			err = cfg.interfaceKey(key, value)
		case "peer":
			err = peer.key(key, value)
		default:
			err = errors.New("параметр вне раздела [Interface] или [Peer]")
		}
		if err != nil {
			return nil, fmt.Errorf("строка %d (%s): %w", lineNo, key, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return cfg, cfg.validate()
}

func (c *Config) interfaceKey(key, value string) error {
	lower := strings.ToLower(key)
	switch lower {
	case "privatekey":
		h, err := keyToHex(value)
		if err != nil {
			return err
		}
		c.device = append(c.device, "private_key="+h)
	case "address":
		for _, part := range splitList(value) {
			addr, err := parseAddr(part)
			if err != nil {
				return err
			}
			c.Addresses = append(c.Addresses, addr)
		}
	case "dns":
		for _, part := range splitList(value) {
			// Search domains are allowed here by wg-quick; we only need servers.
			if addr, err := netip.ParseAddr(part); err == nil {
				c.DNS = append(c.DNS, addr)
			}
		}
	case "mtu":
		mtu, err := strconv.Atoi(value)
		if err != nil || mtu < 576 || mtu > 65535 {
			return errors.New("MTU должен быть числом от 576 до 65535")
		}
		c.MTU = mtu
	case "listenport":
		c.device = append(c.device, "listen_port="+value)
	case "headerprotectionkey":
		h, err := keyToHex(value)
		if err != nil {
			return err
		}
		c.device = append(c.device, "header_protection_key="+h)
	default:
		if ignoredInterfaceKeys[lower] {
			return nil
		}
		// AmneziaWG and future device parameters: Jc → jc, S1 → s1,
		// ContentPaddingAddition → content_padding_addition.
		uapiKey := snakeCase(key)
		c.device = append(c.device, uapiKey+"="+uapiValue(uapiKey, value))
	}
	return nil
}

func (p *Peer) key(key, value string) error {
	switch strings.ToLower(key) {
	case "publickey":
		h, err := keyToHex(value)
		if err != nil {
			return err
		}
		p.PublicKey = h
	case "presharedkey":
		h, err := keyToHex(value)
		if err != nil {
			return err
		}
		p.lines = append(p.lines, "preshared_key="+h)
	case "endpoint":
		p.Endpoint = value
	case "allowedips":
		for _, part := range splitList(value) {
			prefix, err := netip.ParsePrefix(part)
			if err != nil {
				return fmt.Errorf("неверная сеть %q", part)
			}
			p.lines = append(p.lines, "allowed_ip="+prefix.String())
		}
	case "persistentkeepalive":
		if strings.EqualFold(value, "off") {
			value = "0"
		}
		p.lines = append(p.lines, "persistent_keepalive_interval="+value)
	default:
		// Unknown peer keys would be rejected by the device: skip them.
	}
	return nil
}

func (c *Config) validate() error {
	hasKey := false
	for _, l := range c.device {
		hasKey = hasKey || strings.HasPrefix(l, "private_key=")
	}
	switch {
	case !hasKey:
		return errors.New("в [Interface] нет PrivateKey")
	case len(c.Addresses) == 0:
		return errors.New("в [Interface] нет Address")
	case len(c.Peers) == 0:
		return errors.New("нет ни одного раздела [Peer]")
	}
	for i, p := range c.Peers {
		if p.PublicKey == "" {
			return fmt.Errorf("в [Peer] №%d нет PublicKey", i+1)
		}
		if p.Endpoint == "" {
			return fmt.Errorf("в [Peer] №%d нет Endpoint", i+1)
		}
	}
	return nil
}

// UAPI builds the configuration for device.IpcSet. Endpoint host names are
// resolved here, with the system resolver: the tunnel is not up yet.
func (c *Config) UAPI(resolve func(host string) (netip.Addr, error)) (string, error) {
	var b strings.Builder
	for _, l := range c.device {
		b.WriteString(l + "\n")
	}
	for _, p := range c.Peers {
		endpoint, err := resolveEndpoint(p.Endpoint, resolve)
		if err != nil {
			return "", err
		}
		b.WriteString("public_key=" + p.PublicKey + "\n")
		b.WriteString("endpoint=" + endpoint.String() + "\n")
		for _, l := range p.lines {
			b.WriteString(l + "\n")
		}
	}
	return b.String(), nil
}

func resolveEndpoint(endpoint string, resolve func(string) (netip.Addr, error)) (netip.AddrPort, error) {
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("неверный Endpoint %q", endpoint)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("неверный порт в Endpoint %q", endpoint)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		addr, err = resolve(host)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("не удалось найти сервер %s: %w", host, err)
		}
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), nil
}

// AmneziaWG 3.1 switches written as on/off in .conf files; the device wants
// true/false.
var boolKeys = map[string]bool{"random_trailers": true, "disable_cookies": true}

func uapiValue(key, value string) string {
	if !boolKeys[key] {
		return value
	}
	switch strings.ToLower(value) {
	case "on", "yes", "enable", "enabled":
		return "true"
	case "off", "no", "disable", "disabled":
		return "false"
	}
	return value
}

func keyToHex(value string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) != 32 {
		// Already hex (as some tools print it)?
		if h, herr := hex.DecodeString(value); herr == nil && len(h) == 32 {
			return strings.ToLower(value), nil
		}
		return "", errors.New("ключ должен быть 32 байта в base64")
	}
	return hex.EncodeToString(raw), nil
}

func parseAddr(s string) (netip.Addr, error) {
	if prefix, err := netip.ParsePrefix(s); err == nil {
		return prefix.Addr(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("неверный адрес %q", s)
	}
	return addr, nil
}

func splitList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func stripComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}

// snakeCase turns ContentPaddingAddition into content_padding_addition and
// S1 into s1.
func snakeCase(key string) string {
	var b strings.Builder
	runes := []rune(key)
	for i, r := range runes {
		if unicode.IsUpper(r) {
			if i > 0 && (unicode.IsLower(runes[i-1]) ||
				(i+1 < len(runes) && unicode.IsLower(runes[i+1]) && unicode.IsUpper(runes[i-1]))) {
				b.WriteByte('_')
			}
			b.WriteRune(unicode.ToLower(r))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

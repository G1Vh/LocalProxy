package main

// End-to-end: a "server" AmneziaWG node and the bridge as its client, both in
// this process, talking over loopback UDP. The server runs an HTTP server and
// a UDP echo inside its own tunnel network; the test reaches them through the
// bridge's SOCKS5, so every byte crosses a real obfuscated tunnel.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"golang.org/x/crypto/curve25519"
)

// AmneziaWG 3 obfuscation: junk, paddings, header ranges, header protection,
// content padding, a signature packet. Server-side values must match.
var awgParams = map[string]string{
	"Jc": "3", "Jmin": "10", "Jmax": "50",
	"S1": "24", "S2": "40", "S3": "16", "S4": "12",
	"H1": "100000-100100", "H2": "200000-200100", "H3": "300000-300100", "H4": "400000-400100",
	"ContentPaddingAddition": "0-16",
	"RandomTrailers":         "on",
	"DisableCookies":         "on",
	"I1":                     "<b 0xdeadbeef><r 16><t>",
}

const (
	serverIP = "10.66.0.1"
	clientIP = "10.66.0.2"
)

type keyPair struct{ priv, pub [32]byte }

func newKey(t *testing.T) keyPair {
	var k keyPair
	if _, err := rand.Read(k.priv[:]); err != nil {
		t.Fatal(err)
	}
	k.priv[0] &= 248
	k.priv[31] = (k.priv[31] & 127) | 64
	pub, err := curve25519.X25519(k.priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(k.pub[:], pub)
	return k
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// startServer brings up the server node; params are AmneziaWG settings
// (CamelCase keys), hpKey the header protection key or nil.
func startServer(t *testing.T, server, client keyPair, params map[string]string, hpKey []byte) int {
	t.Helper()
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(serverIP)}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	logger := &device.Logger{Verbosef: device.DiscardLogf, Errorf: device.DiscardLogf}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	t.Cleanup(dev.Close)

	free, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := free.LocalAddr().(*net.UDPAddr).Port
	free.Close()

	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%s\nlisten_port=%d\n", hex.EncodeToString(server.priv[:]), port)
	for k, v := range params {
		if k == "Jc" || k == "Jmin" || k == "Jmax" || k == "I1" {
			continue // client-side only
		}
		fmt.Fprintf(&uapi, "%s=%s\n", snakeCase(k), uapiValue(snakeCase(k), v))
	}
	if hpKey != nil {
		fmt.Fprintf(&uapi, "header_protection_key=%s\n", hex.EncodeToString(hpKey))
	}
	fmt.Fprintf(&uapi, "public_key=%s\nallowed_ip=%s/32\n", hex.EncodeToString(client.pub[:]), clientIP)
	if err := dev.IpcSet(uapi.String()); err != nil {
		t.Fatalf("server IpcSet: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}

	ln, err := tnet.ListenTCP(&net.TCPAddr{IP: net.ParseIP(serverIP), Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bulk" {
			chunk := make([]byte, 64*1024)
			for i := 0; i < bulkSize/len(chunk); i++ {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
			return
		}
		fmt.Fprint(w, "hello through the tunnel")
	}))

	echo, err := tnet.ListenUDPAddrPort(netip.MustParseAddrPort(serverIP + ":7"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			echo.WriteTo(buf[:n], from)
		}
	}()
	return port
}

func clientConf(client, server keyPair, port int, params map[string]string, hpKey []byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s/32\n", b64(client.priv[:]), clientIP)
	for k, v := range params {
		fmt.Fprintf(&b, "%s = %s\n", k, v)
	}
	if hpKey != nil {
		fmt.Fprintf(&b, "HeaderProtectionKey = %s\n", b64(hpKey))
	}
	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:%d\nAllowedIPs = 10.66.0.0/24\nPersistentKeepalive = 25\n",
		b64(server.pub[:]), port)
	return b.String()
}

func startClient(t *testing.T, conf string) *Bridge {
	t.Helper()
	cfg, err := ParseConf(conf)
	if err != nil {
		t.Fatalf("conf: %v\n%s", err, conf)
	}
	bridge, err := StartBridge(cfg, "u", "secret", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bridge.Close)
	return bridge
}

// socksHandshake connects and authenticates; returns the control connection.
func socksHandshake(t *testing.T, port int, user, pass string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(15 * time.Second))
	c.Write([]byte{5, 1, 2})
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil || resp[1] != 2 {
		c.Close()
		return nil, fmt.Errorf("method: %v %v", resp, err)
	}
	auth := append([]byte{1, byte(len(user))}, user...)
	auth = append(append(auth, byte(len(pass))), pass...)
	c.Write(auth)
	if _, err := io.ReadFull(c, resp); err != nil || resp[1] != 0 {
		c.Close()
		return nil, fmt.Errorf("auth rejected: %v %v", resp, err)
	}
	return c, nil
}

func socksConnect(t *testing.T, port int, host string, dport uint16) (net.Conn, byte) {
	t.Helper()
	c, err := socksHandshake(t, port, "u", "secret")
	if err != nil {
		t.Fatal(err)
	}
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, dport)
	c.Write(req)
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatal(err)
	}
	return c, rep[1]
}

func TestBridgeCarriesTCPAndUDPOverAmneziaWG(t *testing.T) {
	log.SetOutput(io.Discard)
	server, client := newKey(t), newKey(t)
	hpKey := make([]byte, 32)
	rand.Read(hpKey)
	port := startServer(t, server, client, awgParams, hpKey)
	bridge := startClient(t, clientConf(client, server, port, awgParams, hpKey))

	// TCP: HTTP GET to a server inside the tunnel.
	c, code := socksConnect(t, bridge.Port, serverIP, 80)
	if code != 0 {
		t.Fatalf("CONNECT failed with code %d", code)
	}
	c.Write([]byte("GET / HTTP/1.0\r\nHost: x\r\n\r\n"))
	body, _ := io.ReadAll(c)
	c.Close()
	if !strings.Contains(string(body), "hello through the tunnel") {
		t.Fatalf("unexpected response: %q", body)
	}

	// UDP ASSOCIATE: echo through the tunnel.
	ctl, err := socksHandshake(t, bridge.Port, "u", "secret")
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()
	ctl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	rep := make([]byte, 10)
	if _, err := io.ReadFull(ctl, rep); err != nil || rep[1] != 0 {
		t.Fatalf("UDP ASSOCIATE: %v %v", rep, err)
	}
	relay := &net.UDPAddr{IP: net.IP(rep[4:8]), Port: int(binary.BigEndian.Uint16(rep[8:10]))}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	dgram := append(udpHeader(netip.MustParseAddrPort(serverIP+":7")), "ping-udp"...)
	if _, err := udp.WriteToUDP(dgram, relay); err != nil {
		t.Fatal(err)
	}
	udp.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := udp.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no UDP echo: %v", err)
	}
	host, sport, payload, err := parseUDPHeader(buf[:n])
	if err != nil || host != serverIP || sport != 7 || string(payload) != "ping-udp" {
		t.Fatalf("bad UDP reply: host=%s port=%d payload=%q err=%v", host, sport, payload, err)
	}

	s, err := bridge.Status()
	if err != nil {
		t.Fatal(err)
	}
	if s.LastHandshake == 0 || s.RxBytes == 0 || s.TxBytes == 0 {
		t.Fatalf("status shows no traffic: %+v", s)
	}
}

func TestPlainWireGuardWorksToo(t *testing.T) {
	log.SetOutput(io.Discard)
	server, client := newKey(t), newKey(t)
	port := startServer(t, server, client, nil, nil)
	bridge := startClient(t, clientConf(client, server, port, nil, nil))
	c, code := socksConnect(t, bridge.Port, serverIP, 80)
	defer c.Close()
	if code != 0 {
		t.Fatalf("CONNECT failed with code %d", code)
	}
}

// With mismatched obfuscation the handshake must fail: proves the params are
// really applied, not silently ignored.
func TestMismatchedObfuscationDoesNotConnect(t *testing.T) {
	log.SetOutput(io.Discard)
	server, client := newKey(t), newKey(t)
	port := startServer(t, server, client, awgParams, nil)
	wrong := map[string]string{}
	for k, v := range awgParams {
		wrong[k] = v
	}
	wrong["H1"] = "900000-900100"
	bridge := startClient(t, clientConf(client, server, port, wrong, nil))

	c, err := socksHandshake(t, bridge.Port, "u", "secret")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(6 * time.Second))
	req := binary.BigEndian.AppendUint16([]byte{5, 1, 0, 1, 10, 66, 0, 1}, 80)
	c.Write(req)
	rep := make([]byte, 10)
	_, err = io.ReadFull(c, rep)
	if err == nil && rep[1] == 0 {
		t.Fatal("connected despite mismatched H1")
	}
}

func TestWrongSocksPasswordIsRejected(t *testing.T) {
	log.SetOutput(io.Discard)
	server, client := newKey(t), newKey(t)
	port := startServer(t, server, client, nil, nil)
	bridge := startClient(t, clientConf(client, server, port, nil, nil))
	if c, err := socksHandshake(t, bridge.Port, "u", "wrong"); err == nil {
		c.Close()
		t.Fatal("wrong password accepted")
	}
}

// A dead server must look like a dead outbound to LocalProxy: the SOCKS
// connection is closed without a reply instead of "connection refused".
func TestDeadServerClosesWithoutReply(t *testing.T) {
	log.SetOutput(io.Discard)
	// Past the start-up grace period a dead tunnel must fail fast.
	saved := warmUp
	warmUp = 0
	t.Cleanup(func() { warmUp = saved })
	server, client := newKey(t), newKey(t)
	free, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := free.LocalAddr().(*net.UDPAddr).Port
	free.Close() // nobody answers on this port
	bridge := startClient(t, clientConf(client, server, port, nil, nil))

	c, err := socksHandshake(t, bridge.Port, "u", "secret")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	started := time.Now()
	c.Write(binary.BigEndian.AppendUint16([]byte{5, 1, 0, 1, 10, 66, 0, 1}, 80))
	rep := make([]byte, 10)
	_, err = io.ReadFull(c, rep)
	if err == nil {
		t.Fatalf("got a reply %v, want the connection closed", rep)
	}
	if took := time.Since(started); took > 10*time.Second {
		t.Fatalf("took %v, a dead tunnel should fail fast", took)
	}
}

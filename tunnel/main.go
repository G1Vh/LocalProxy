// localproxy-tunnel runs a VPN tunnel entirely in userspace (no driver, no
// admin rights) and exposes it as a SOCKS5 proxy on loopback for LocalProxy.
// Protocols live in internal/: awg (WireGuard / AmneziaWG) and sstp, which
// runs on the shared packet tunnel; core is what all of them share.
//
// Protocol on stdin/stdout, one JSON object per line:
//
//	stdin  (first line): {"awg": {"conf": "<.conf text>"}, "user": "...", "pass": "..."}
//	                  or {"sstp": {"server": "...", "user": "...", ...}, "user": "...", "pass": "..."}
//	                     (user/pass: the SOCKS5 credentials LocalProxy will use)
//	stdout:              {"event": "ready", "port": 12345}
//	                     {"event": "error", "message": "..."}
//	stdin  "status":     {"event": "status", "lastHandshake": ..., "rx": ..., "tx": ...}
//
// When stdin closes (LocalProxy exited or crashed) the tunnel shuts down, so
// it never outlives its parent.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/netip"
	"os"
	"strings"

	"github.com/G1Vh/LocalProxy/tunnel/internal/awg"
	"github.com/G1Vh/LocalProxy/tunnel/internal/core"
	"github.com/G1Vh/LocalProxy/tunnel/internal/packet"
	"github.com/G1Vh/LocalProxy/tunnel/internal/sstp"
)

type startRequest struct {
	Awg  *struct{ Conf string } `json:"awg"`
	Sstp *sstp.Options          `json:"sstp"`
	User string                 `json:"user"`
	Pass string                 `json:"pass"`
}

// tunnel is what every protocol gives back once it runs.
type tunnel interface {
	Status() (core.Status, error)
	Close()
}

const listen = "127.0.0.1:0"

// start picks the protocol; returns the tunnel and its SOCKS5 port.
func start(req startRequest) (tunnel, int, error) {
	switch {
	case req.Awg != nil:
		cfg, err := awg.ParseConf(req.Awg.Conf)
		if err != nil {
			return nil, 0, errors.New("конфиг: " + err.Error())
		}
		t, err := awg.Start(cfg, req.User, req.Pass, listen)
		if err != nil {
			return nil, 0, err
		}
		return t, t.Port, nil
	case req.Sstp != nil:
		opts := *req.Sstp
		dial := func(ctx context.Context, ip netip.Addr) (*packet.Session, error) { return sstp.Dial(ctx, opts, ip) }
		t, err := packet.Start("sstp", dial, req.User, req.Pass, listen)
		if err != nil {
			return nil, 0, err
		}
		return t, t.Port, nil
	}
	return nil, 0, errors.New("не указан протокол туннеля")
}

func main() {
	log.SetFlags(log.Ltime)
	log.SetOutput(os.Stderr)
	out := json.NewEncoder(os.Stdout)
	fail := func(msg string) {
		out.Encode(map[string]any{"event": "error", "message": msg})
		os.Exit(1)
	}

	in := bufio.NewReader(os.Stdin)
	line, err := in.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		fail("нет параметров на stdin")
	}
	var req startRequest
	if err := json.Unmarshal(line, &req); err != nil {
		fail("параметры не JSON: " + err.Error())
	}
	if req.User == "" || req.Pass == "" {
		fail("не заданы логин и пароль SOCKS5")
	}
	t, port, err := start(req)
	if err != nil {
		fail(err.Error())
	}
	out.Encode(map[string]any{"event": "ready", "port": port})

	for {
		line, err := in.ReadString('\n')
		if strings.TrimSpace(line) == "status" {
			s, serr := t.Status()
			if serr != nil {
				out.Encode(map[string]any{"event": "error", "message": serr.Error()})
			} else {
				out.Encode(map[string]any{"event": "status", "lastHandshake": s.LastHandshake, "rx": s.RxBytes, "tx": s.TxBytes})
			}
		}
		if err != nil {
			break
		}
	}
	t.Close()
}

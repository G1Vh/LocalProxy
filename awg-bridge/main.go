// awg-bridge runs a WireGuard / AmneziaWG tunnel entirely in userspace
// (no driver, no admin rights) and exposes it as a SOCKS5 proxy on loopback
// for LocalProxy.
//
// Protocol on stdin/stdout, one JSON object per line:
//
//	stdin  (first line): {"conf": "<.conf text>", "user": "...", "pass": "..."}
//	stdout:              {"event": "ready", "port": 12345}
//	                     {"event": "error", "message": "..."}
//	stdin  "status":     {"event": "status", "lastHandshake": ..., "rx": ..., "tx": ...}
//
// When stdin closes (LocalProxy exited or crashed) the bridge shuts down, so
// it never outlives its parent.
package main

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"strings"
)

type startRequest struct {
	Conf string `json:"conf"`
	User string `json:"user"`
	Pass string `json:"pass"`
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

	cfg, err := ParseConf(req.Conf)
	if err != nil {
		fail("конфиг: " + err.Error())
	}
	bridge, err := StartBridge(cfg, req.User, req.Pass, "127.0.0.1:0")
	if err != nil {
		fail(err.Error())
	}
	out.Encode(map[string]any{"event": "ready", "port": bridge.Port})

	for {
		line, err := in.ReadString('\n')
		if strings.TrimSpace(line) == "status" {
			s, serr := bridge.Status()
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
	bridge.Close()
}

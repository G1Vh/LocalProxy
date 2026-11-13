// Package coretest has SOCKS5 client helpers for the tunnel tests.
package coretest

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// Credentials the tests start tunnels with.
const (
	User = "u"
	Pass = "secret"
)

// SocksHandshake connects and authenticates; returns the control connection.
func SocksHandshake(port int, user, pass string) (net.Conn, error) {
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

// SocksConnect opens a CONNECT to host:dport; returns the reply code.
func SocksConnect(t *testing.T, port int, host string, dport uint16) (net.Conn, byte) {
	t.Helper()
	c, err := SocksHandshake(port, User, Pass)
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

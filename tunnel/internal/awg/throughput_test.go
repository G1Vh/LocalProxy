package awg

import (
	"github.com/G1Vh/LocalProxy/tunnel/internal/core/coretest"
	"io"
	"log"
	"testing"
	"time"
)

const bulkSize = 20 << 20

// TestThroughputLoopback downloads 20 MB through the tunnel with both tunnel
// ends on this machine: no network in the way, only our stack. Guards
// against regressions that make the tunnel crawl.
func TestThroughputLoopback(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	log.SetOutput(io.Discard)
	server, client := newKey(t), newKey(t)
	port := startServer(t, server, client, awgParams, nil)
	tunnel := startClient(t, clientConf(client, server, port, awgParams, nil))

	c, code := coretest.SocksConnect(t, tunnel.Port, serverIP, 80)
	if code != 0 {
		t.Fatalf("CONNECT failed with code %d", code)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(60 * time.Second))
	started := time.Now()
	c.Write([]byte("GET /bulk HTTP/1.0\r\nHost: x\r\n\r\n"))
	n, err := io.Copy(io.Discard, c)
	took := time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	mbps := float64(n) / took.Seconds() / (1 << 20)
	t.Logf("%d bytes in %v: %.1f MB/s", n, took, mbps)
	if n < bulkSize {
		t.Fatalf("short read: %d", n)
	}
	if mbps < 5 {
		t.Fatalf("throughput %.1f MB/s is far too low for loopback", mbps)
	}
}

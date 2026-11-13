package awg

import (
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
)

const sampleAWG = `
# Exported from the Amnezia app
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.8.1.2/32, fd00::2/128
DNS = 1.1.1.1, 2606:4700:4700::1111, corp.local
MTU = 1280
Jc = 4
Jmin = 10
Jmax = 50
S1 = 86
S2 = 109
S3 = 12
S4 = 8
H1 = 1755269708-1755269800
H2 = 2109172399
H3 = 1214834733
H4 = 1103461497
I1 = <b 0xc6000000010843290a47ba8ba2ed000044d0e3efd9326adb60561baa3bc4b52471b2d459ddcc9a508dffddc97e4ff><r 16>
HeaderProtectionKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=
ContentPaddingAddition = 0-16
RekeyAfterTime = 112-135
MaxHandshakeAttempts = 24-31
RandomTrailers = on
DisableCookies = off
PostUp = iptables -A FORWARD -i %i -j ACCEPT
Table = off

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
PresharedKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 127.0.0.1:51820
PersistentKeepalive = 25
`

func TestParseAmneziaConf(t *testing.T) {
	cfg, err := ParseConf(sampleAWG)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Addresses; len(got) != 2 || got[0] != netip.MustParseAddr("10.8.1.2") {
		t.Fatalf("addresses: %v", got)
	}
	if len(cfg.DNS) != 2 {
		t.Fatalf("dns (search domain must be skipped): %v", cfg.DNS)
	}
	if cfg.MTU != 1280 {
		t.Fatalf("mtu: %d", cfg.MTU)
	}
	uapi, err := cfg.UAPI(nil)
	if err != nil {
		t.Fatal(err)
	}
	hexOf := func(b64 string) string {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(raw)
	}
	for _, want := range []string{
		"private_key=" + hexOf("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=") + "\n",
		"jc=4\n", "jmin=10\n", "jmax=50\n", "s1=86\n", "s2=109\n", "s3=12\n", "s4=8\n",
		"h1=1755269708-1755269800\n", "h2=2109172399\n",
		"i1=<b 0xc6000000010843290a47ba8ba2ed000044d0e3efd9326adb60561baa3bc4b52471b2d459ddcc9a508dffddc97e4ff><r 16>\n",
		"header_protection_key=" + hexOf("HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=") + "\n",
		"content_padding_addition=0-16\n",
		"rekey_after_time=112-135\n", "max_handshake_attempts=24-31\n",
		"random_trailers=true\n", "disable_cookies=false\n",
		"public_key=" + hexOf("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=") + "\n",
		"preshared_key=" + hexOf("TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=") + "\n",
		"endpoint=127.0.0.1:51820\n",
		"allowed_ip=0.0.0.0/0\n", "allowed_ip=::/0\n",
		"persistent_keepalive_interval=25\n",
	} {
		if !strings.Contains(uapi, want) {
			t.Errorf("UAPI is missing %q:\n%s", want, uapi)
		}
	}
	for _, unwanted := range []string{"post_up", "table", "address", "dns", "mtu"} {
		if strings.Contains(uapi, unwanted+"=") {
			t.Errorf("UAPI must not carry %s:\n%s", unwanted, uapi)
		}
	}
	// Peer keys must follow the peer's public_key line.
	if strings.Index(uapi, "public_key=") > strings.Index(uapi, "endpoint=") {
		t.Errorf("endpoint before public_key:\n%s", uapi)
	}
}

func TestParsePlainWireGuard(t *testing.T) {
	conf := `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/24
[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0`
	cfg, err := ParseConf(conf)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MTU != defaultMTU || len(cfg.DNS) != 0 {
		t.Fatalf("defaults: mtu=%d dns=%v", cfg.MTU, cfg.DNS)
	}
	uapi, err := cfg.UAPI(func(host string) (netip.Addr, error) {
		if host != "vpn.example.com" {
			t.Fatalf("resolved %q", host)
		}
		return netip.MustParseAddr("203.0.113.9"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(uapi, "endpoint=203.0.113.9:51820\n") {
		t.Fatalf("endpoint not resolved:\n%s", uapi)
	}
	if strings.Contains(uapi, "jc=") {
		t.Fatalf("plain WireGuard must have no AmneziaWG params:\n%s", uapi)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"no key":      "[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = 1.2.3.4:1",
		"bad key":     "[Interface]\nPrivateKey = nope\n",
		"no peer":     "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.0.0.2/32",
		"no endpoint": "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
		"garbage":     "hello",
		"bad section": "[Wat]\n",
	}
	for name, conf := range cases {
		if _, err := ParseConf(conf); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestSnakeCase(t *testing.T) {
	for in, want := range map[string]string{
		"Jc": "jc", "S1": "s1", "H4": "h4", "Jmin": "jmin",
		"ContentPaddingAddition": "content_padding_addition",
		"MaxHandshakeAttempts":   "max_handshake_attempts",
		"RekeyAfterTime":         "rekey_after_time",
	} {
		if got := snakeCase(in); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
}

package mschap

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Sample values from RFC 2759 section 9.2 and RFC 3079 section 3.5.
func TestMSCHAPv2Vectors(t *testing.T) {
	const user, pass = "User", "clientPass"
	authChallenge := unhex(t, "5B 5D 7C 7D 7B 3F 2F 3E 3C 2C 60 21 32 26 26 28")
	peerChallenge := unhex(t, "21 40 23 24 25 5E 26 2A 28 29 5F 2B 3A 33 7C 7E")

	if got, want := ChallengeHash(peerChallenge, authChallenge, user), unhex(t, "D0 2E 43 86 BC E9 12 26"); !bytes.Equal(got, want) {
		t.Fatalf("challenge hash %X, want %X", got, want)
	}
	if got, want := NTPasswordHash(pass), unhex(t, "44 EB BA 8D 53 12 B8 D6 11 47 44 11 F5 69 89 AE"); !bytes.Equal(got, want) {
		t.Fatalf("password hash %X, want %X", got, want)
	}
	resp := NTResponse(authChallenge, peerChallenge, user, pass)
	if want := unhex(t, "82 30 9E CD 8D 70 8B 5E A0 8F AA 39 81 CD 83 54 42 33 11 4A 3D 85 D6 DF"); !bytes.Equal(resp, want) {
		t.Fatalf("NT response %X, want %X", resp, want)
	}
	if got, want := AuthenticatorResponse(pass, resp, peerChallenge, authChallenge, user), "S=407A5589115FD0D6209F510FE9C04566932CDA56"; got != want {
		t.Fatalf("authenticator response %s, want %s", got, want)
	}
	if got, want := MasterKey(pass, resp), unhex(t, "FD EC E3 71 7A 8C 83 8C B3 88 E5 27 AE 3C DD 31"); !bytes.Equal(got, want) {
		t.Fatalf("master key %X, want %X", got, want)
	}
	// A domain prefix does not take part in the challenge hash.
	if !bytes.Equal(NTResponse(authChallenge, peerChallenge, `CORP\User`, pass), resp) {
		t.Fatal(`"CORP\User" must hash like "User"`)
	}
	hlak := ClientHLAK(pass, resp)
	if len(hlak) != 32 || bytes.Equal(hlak[:16], hlak[16:]) {
		t.Fatalf("HLAK %X", hlak)
	}
}

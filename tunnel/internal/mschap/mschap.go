// Package mschap is MS-CHAPv2 (RFC 2759) and the MPPE master keys derived
// from it (RFC 3079), which SSTP uses to bind TLS to the PPP login.
package mschap

import (
	"crypto/des"
	"crypto/sha1"
	"encoding/hex"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4" //nolint:staticcheck // MD4 is what MS-CHAPv2 is built on
)

// NTPasswordHash is MD4 over the UTF-16LE password.
func NTPasswordHash(password string) []byte {
	h := md4.New()
	for _, u := range utf16.Encode([]rune(password)) {
		h.Write([]byte{byte(u), byte(u >> 8)})
	}
	return h.Sum(nil)
}

func md4Sum(b []byte) []byte {
	h := md4.New()
	h.Write(b)
	return h.Sum(nil)
}

// ChallengeHash takes the user name without a "DOMAIN\" prefix, as Windows does.
func ChallengeHash(peerChallenge, authChallenge []byte, username string) []byte {
	if i := strings.LastIndexByte(username, '\\'); i >= 0 {
		username = username[i+1:]
	}
	h := sha1.New()
	h.Write(peerChallenge)
	h.Write(authChallenge)
	h.Write([]byte(username))
	return h.Sum(nil)[:8]
}

// challengeResponse encrypts the 8-byte challenge with three DES keys cut
// from the zero-padded 21-byte password hash.
func challengeResponse(challenge, passwordHash []byte) []byte {
	key := make([]byte, 21)
	copy(key, passwordHash)
	out := make([]byte, 0, 24)
	for i := range 3 {
		out = append(out, desEncrypt(key[i*7:i*7+7], challenge)...)
	}
	return out
}

// desEncrypt spreads 7 key bytes over 8 (the low bit of each is parity, ignored).
func desEncrypt(key7, block []byte) []byte {
	k := make([]byte, 8)
	k[0] = key7[0]
	for i := 1; i < 7; i++ {
		k[i] = key7[i-1]<<(8-i) | key7[i]>>i
	}
	k[7] = key7[6] << 1
	c, err := des.NewCipher(k)
	if err != nil {
		panic(err) // the key is always 8 bytes
	}
	out := make([]byte, 8)
	c.Encrypt(out, block)
	return out
}

// NTResponse is the 24-byte answer to the server's challenge.
func NTResponse(authChallenge, peerChallenge []byte, username, password string) []byte {
	return challengeResponse(ChallengeHash(peerChallenge, authChallenge, username), NTPasswordHash(password))
}

var (
	authMagic1 = []byte("Magic server to client signing constant")
	authMagic2 = []byte("Pad to make it do more than one iteration")
)

// AuthenticatorResponse is the "S=..." string a server that knows the
// password sends back: checking it proves the server is the real one.
func AuthenticatorResponse(password string, ntResp, peerChallenge, authChallenge []byte, username string) string {
	hashHash := md4Sum(NTPasswordHash(password))
	h := sha1.New()
	h.Write(hashHash)
	h.Write(ntResp)
	h.Write(authMagic1)
	digest := h.Sum(nil)
	h = sha1.New()
	h.Write(digest)
	h.Write(ChallengeHash(peerChallenge, authChallenge, username))
	h.Write(authMagic2)
	return "S=" + strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

var (
	mppeMagicMaster = []byte("This is the MPPE Master Key")
	mppeMagicSend   = []byte("On the client side, this is the send key; on the server side, it is the receive key.")
	mppeMagicRecv   = []byte("On the client side, this is the receive key; on the server side, it is the send key.")
)

func MasterKey(password string, ntResp []byte) []byte {
	h := sha1.New()
	h.Write(md4Sum(NTPasswordHash(password)))
	h.Write(ntResp)
	h.Write(mppeMagicMaster)
	return h.Sum(nil)[:16]
}

func mppeStartKey(master, magic []byte) []byte {
	h := sha1.New()
	h.Write(master)
	h.Write(make([]byte, 40))
	h.Write(magic)
	pad := make([]byte, 40)
	for i := range pad {
		pad[i] = 0xf2
	}
	h.Write(pad)
	return h.Sum(nil)[:16]
}

// ClientHLAK is the SSTP higher-layer authentication key of the client:
// its MPPE send key followed by its receive key (MS-SSTP 3.2.5.2.2).
func ClientHLAK(password string, ntResp []byte) []byte {
	master := MasterKey(password, ntResp)
	return append(mppeStartKey(master, mppeMagicSend), mppeStartKey(master, mppeMagicRecv)...)
}

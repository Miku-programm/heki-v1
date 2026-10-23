package ssr

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
)

// Protocol is the SSR "protocol" plugin layer. Its main server-side job is to
// recover the per-connection user id (UID) from the auth header, which selects
// which user's key decrypts the stream.
type Protocol interface {
	Name() string
	// ExtractUID parses the auth header with the shared server key and returns
	// the embedded user id plus how many header bytes it consumed. ok=false
	// means the header did not authenticate against serverKey.
	ExtractUID(header, serverKey []byte) (uid uint32, consumed int, ok bool)
}

// hmacMD5 returns the first `n` bytes of HMAC-MD5(key, data).
func hmacMD5(key, data []byte, n int) []byte {
	m := hmac.New(md5.New, key)
	m.Write(data)
	return m.Sum(nil)[:n]
}

// hmacSHA1 returns the first `n` bytes of HMAC-SHA1(key, data).
func hmacSHA1(key, data []byte, n int) []byte {
	m := hmac.New(sha1.New, key)
	m.Write(data)
	return m.Sum(nil)[:n]
}

// --- origin: no auth, no UID (single user) ---

type originProtocol struct{}

func (originProtocol) Name() string { return "origin" }
func (originProtocol) ExtractUID(_, _ []byte) (uint32, int, bool) {
	return 0, 0, true
}

// --- auth_chain_a ---
//
// Reconstructed from extractUIDAuthChain: the header begins with a 4-byte
// client nonce, an 8-byte HMAC tag over that nonce, and a 4-byte UID XOR-masked
// by the HMAC keystream:
//
//	nonce   = header[0:4]
//	tag     = header[4:12]
//	encUID  = header[12:16]
//	h       = HMAC-MD5(serverKey, nonce)      // >= 16 bytes
//	accept iff h[0:8] == tag
//	uid     = encUID XOR h[8:12]
type authChainA struct{}

func (authChainA) Name() string { return "auth_chain_a" }

func (authChainA) ExtractUID(header, serverKey []byte) (uint32, int, bool) {
	if len(header) < 0x24 { // 36, matches the binary's length guard
		return 0, 0, false
	}
	h := hmacMD5(serverKey, header[0:4], 16)
	if !hmac.Equal(h[0:8], header[4:12]) {
		return 0, 0, false
	}
	var enc [4]byte
	for i := 0; i < 4; i++ {
		enc[i] = header[12+i] ^ h[8+i]
	}
	return binary.LittleEndian.Uint32(enc[:]), 16, true
}

// clientRandLen reproduces getClientRandLen: packets larger than 1440 get no
// random padding; otherwise a pseudo-random length derived from the last client
// hash (seeded chain). The exact PRNG is the SSR auth_chain xorshift over the
// last-hash words; here it is a faithful, deterministic reduction of that hash.
func clientRandLen(dataLen int, lastHash []byte) int {
	if dataLen > 1440 || len(lastHash) < 16 {
		return 0
	}
	seed := binary.LittleEndian.Uint64(lastHash[0:8]) ^ binary.LittleEndian.Uint64(lastHash[8:16])
	if dataLen > 1300 {
		return int(seed % 31)
	}
	if dataLen > 900 {
		return int(seed % 127)
	}
	if dataLen > 400 {
		return int(seed % 521)
	}
	return int(seed % 1021)
}

// --- auth_aes128_sha1 / auth_aes128_md5 ---
//
// From extractUIDAuthAES128 / validateAuthAES128User: the UID is a 4-byte field
// authenticated by an HMAC (SHA1 or MD5 variant) keyed by the server key.
type authAES128 struct {
	name   string
	hmacFn func(key, data []byte, n int) []byte
}

func newAuthAES128SHA1() authAES128 { return authAES128{"auth_aes128_sha1", hmacSHA1} }
func newAuthAES128MD5() authAES128  { return authAES128{"auth_aes128_md5", hmacMD5} }

func (p authAES128) Name() string { return p.name }

func (p authAES128) ExtractUID(header, serverKey []byte) (uint32, int, bool) {
	// layout: [uid 4][... ][hmac 4] over the preceding bytes
	if len(header) < 12 {
		return 0, 0, false
	}
	tag := p.hmacFn(serverKey, header[0:len(header)-4], 4)
	if !hmac.Equal(tag, header[len(header)-4:]) {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint32(header[0:4]), len(header), true
}

// newProtocol builds a protocol plugin by name.
func newProtocol(name string) Protocol {
	switch name {
	case "auth_chain_a", "auth_chain_b", "auth_chain_c",
		"auth_chain_d", "auth_chain_e", "auth_chain_f":
		return authChainA{} // variants differ only in rand-length PRNG tuning
	case "auth_aes128_sha1":
		return newAuthAES128SHA1()
	case "auth_aes128_md5":
		return newAuthAES128MD5()
	default:
		return originProtocol{}
	}
}

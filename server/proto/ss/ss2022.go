package ss

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Blake3DeriveKey is the SS-2022 key-derivation function. blake3 is not in the
// standard library (the binary uses lukechampine.com/blake3), so it is injected
// here: set it to blake3.DeriveKey to enable the 2022-blake3-* methods. When
// nil, SS-2022 falls back to an HMAC-SHA256 KDF so the package stays buildable
// and testable on stdlib alone (not wire-compatible with real blake3 clients).
var Blake3DeriveKey func(context string, material []byte) []byte

// blake3DeriveKey derives a key for the SS-2022 session (blake3DeriveKey).
func blake3DeriveKey(context string, material []byte, keyLen int) []byte {
	if Blake3DeriveKey != nil {
		out := Blake3DeriveKey(context, material)
		if len(out) >= keyLen {
			return out[:keyLen]
		}
		return out
	}
	// stdlib fallback: HMAC-SHA256(material, context), truncated.
	m := hmac.New(sha256.New, material)
	m.Write([]byte(context))
	return m.Sum(nil)[:min(keyLen, sha256.Size)]
}

// blake3DeriveIdentityKey derives the per-user identity sub-key used by the EIH
// multi-user path (blake3DeriveIdentityKey).
func blake3DeriveIdentityKey(psk []byte, keyLen int) []byte {
	return blake3DeriveKey("shadowsocks 2022 identity subkey", psk, keyLen)
}

// ssIdentityHash computes the identity hash the server compares against each
// user's identity key when demultiplexing an EIH (ssIdentityHash).
func ssIdentityHash(identityKey, salt []byte) []byte {
	m := hmac.New(sha256.New, identityKey)
	m.Write(salt)
	return m.Sum(nil)[:16]
}

// ss2022Spec maps a 2022 method to key length.
var ss2022KeyLen = map[string]int{
	"2022-blake3-aes-128-gcm": 16,
	"2022-blake3-aes-256-gcm": 32,
}

// is2022Method reports whether method is a Shadowsocks-2022 method.
func is2022Method(method string) bool {
	_, ok := ss2022KeyLen[method]
	return ok
}

// decodePSK decodes a base64 pre-shared key.
func decodePSK(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("ss2022: bad psk: %w", err)
	}
	return b, nil
}

// matchUserByIdentity demultiplexes an EIH: it AES-ECB-decrypts the identity
// header with the node iPSK's identity key and matches the recovered uPSK hash
// against the configured users. Mirrors matchUserByIdentity.
func (h *Handler) matchUserByIdentity(salt, eih []byte) *User {
	if len(eih) < 16 {
		return nil
	}
	block, err := aes.NewCipher(blake3DeriveIdentityKey(h.iPSK, 16))
	if err != nil {
		return nil
	}
	var recovered [16]byte
	block.Decrypt(recovered[:], eih[:16])

	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, u := range h.users {
		want := ssIdentityHash(blake3DeriveIdentityKey(u.psk, h.keyLen), salt)
		if hmac.Equal(recovered[:], want) {
			return u
		}
	}
	return nil
}

package license

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// DecodeWrappedSignedLicense decodes a base64-wrapped SignedLicense (the on-wire
// form used by offline license files).
func DecodeWrappedSignedLicense(wrapped string) (*SignedLicense, error) {
	raw, err := decodeBase64String(wrapped)
	if err != nil {
		return nil, fmt.Errorf("decode wrapped license: %w", err)
	}
	var sl SignedLicense
	if err := json.Unmarshal(raw, &sl); err != nil {
		return nil, fmt.Errorf("unmarshal license: %w", err)
	}
	return &sl, nil
}

// EmbeddedPublicKeyBase64 is the author's Ed25519 verification public key,
// hardcoded in the binary (assembled from fragments). Recovered value:
//
//	hex: fd7dc598893044b6b3c87f7578b0f23f99e38a6301b15f3a50f133051cb5eec3
const EmbeddedPublicKeyBase64 = "/X3FmIkwRLazyH91eLDyP5njimMBsV86UPEzBRy17sM="

// cacheKeyPrefix is the domain-separation prefix for the local cache key.
// Recovered from deriveLocalKey.
const cacheKeyPrefix = "heki-cache-v1:"

// getPublicKey decodes the embedded base64 key and requires exactly 32 bytes
// (ed25519.PublicKeySize), erroring otherwise.
func getPublicKey() (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(EmbeddedPublicKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid embedded public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// deriveLocalKey = SHA-256("heki-cache-v1:" || machineID || ":" || licenseKey).
// This binds the cache key to the machine id; copying the cache to another host
// yields a different key.
func deriveLocalKey(machineID, licenseKey string) []byte {
	h := sha256.New()
	h.Write([]byte(cacheKeyPrefix))
	h.Write([]byte(machineID))
	h.Write([]byte(":"))
	h.Write([]byte(licenseKey))
	return h.Sum(nil)
}

// localHMAC = HMAC-SHA256(key, data). Used as the cache integrity tag.
func localHMAC(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// hmacEqual is a constant-time tag comparison.
func hmacEqual(a, b []byte) bool { return hmac.Equal(a, b) }

// xorEncrypt XORs data with a repeating key (symmetric: same call decrypts).
func xorEncrypt(data, key []byte) []byte {
	if len(key) == 0 {
		return append([]byte(nil), data...)
	}
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

// decodeBase64String trims the input and decodes it, trying standard encoding
// first and raw-standard as a fallback. Empty input is an error.
func decodeBase64String(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty base64 input")
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

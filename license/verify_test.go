package license

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

// TestEmbeddedPublicKey checks the embedded key decodes to a 32-byte Ed25519 key.
func TestEmbeddedPublicKey(t *testing.T) {
	pk, err := getPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(pk) != ed25519.PublicKeySize {
		t.Fatalf("pubkey len = %d", len(pk))
	}
}

// TestCacheCryptoRoundTrip proves the local cache XOR+HMAC scheme round-trips
// and that the key is machine-bound (different machineID -> different key).
func TestCacheCryptoRoundTrip(t *testing.T) {
	key := deriveLocalKey("machine-123", "lic-key")
	key2 := deriveLocalKey("machine-123", "lic-key")
	if !bytes.Equal(key, key2) {
		t.Fatal("deriveLocalKey not deterministic")
	}
	if bytes.Equal(key, deriveLocalKey("other-machine", "lic-key")) {
		t.Fatal("deriveLocalKey not machine-bound")
	}

	plain := []byte(`{"max_users":100}`)
	cipher := xorEncrypt(plain, key)
	if bytes.Equal(cipher, plain) {
		t.Fatal("xor produced plaintext")
	}
	back := xorEncrypt(cipher, key) // symmetric
	if !bytes.Equal(back, plain) {
		t.Fatal("xor round-trip failed")
	}

	tag := localHMAC(key, cipher)
	if !hmacEqual(tag, localHMAC(key, cipher)) {
		t.Fatal("hmac mismatch on identical input")
	}
	if hmacEqual(tag, localHMAC(key, append(cipher, 'x'))) {
		t.Fatal("hmac collided on tampered input")
	}
}

// TestSignatureVerifyPath proves verifySignedLicense rejects a forged license
// (no valid signature exists without the author's private key) — i.e. the
// Ed25519 gate actually works.
func TestSignatureVerifyPath(t *testing.T) {
	m := &Manager{}
	pk, _ := getPublicKey()
	m.pubKey = pk
	// a license signed with a DIFFERENT key must be rejected
	_, priv, _ := ed25519.GenerateKey(nil)
	payload := []byte(`{"max_users":999999}`)
	sig := ed25519.Sign(priv, payload)
	sl := &SignedLicense{
		Payload:   b64(payload),
		Signature: b64(sig),
	}
	if _, err := m.verifySignedLicense(sl); err == nil {
		t.Fatal("forged license accepted — signature gate broken")
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

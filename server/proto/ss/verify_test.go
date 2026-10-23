package ss

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

// TestAEADStreamRoundTrip proves the SS-AEAD chunked stream encrypts and
// decrypts back to the original bytes using a real HKDF-SHA1 subkey + AES-GCM.
func TestAEADStreamRoundTrip(t *testing.T) {
	spec := aeadSpecs["aes-256-gcm"]
	master := EVPBytesToKey("correct horse battery staple", spec.keyLen)
	salt := make([]byte, spec.saltLen)
	_, _ = rand.Read(salt)
	subkey, err := hkdfSha1(master, salt, spec.keyLen)
	if err != nil {
		t.Fatal(err)
	}
	wAEAD, _ := spec.newAEAD(subkey)
	rAEAD, _ := spec.newAEAD(subkey)

	var wire bytes.Buffer
	w := newAEADWriter(&wire, wAEAD)
	msg := bytes.Repeat([]byte("heki-ss-"), 5000) // spans multiple chunks
	if _, err := w.Write(msg); err != nil {
		t.Fatal(err)
	}

	r := newAEADReader(&wire, rAEAD)
	got, err := io.ReadAll(io.LimitReader(r, int64(len(msg))))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("round-trip mismatch: got %d bytes", len(got))
	}
}

// TestEVPDeterministic checks EVPBytesToKey is stable and correctly sized.
func TestEVPDeterministic(t *testing.T) {
	a := EVPBytesToKey("pw", 32)
	b := EVPBytesToKey("pw", 32)
	if len(a) != 32 || !bytes.Equal(a, b) {
		t.Fatalf("EVP not deterministic/sized")
	}
}

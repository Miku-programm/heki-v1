package vmess

import (
	"testing"
)

// TestFNVKnown checks fnv-1a against a known vector ("" -> offset basis).
func TestFNVKnown(t *testing.T) {
	if got := fnvHash32(nil); got != fnvOffset32 {
		t.Fatalf("fnv(empty) = %x, want %x", got, fnvOffset32)
	}
	// "a" -> (offset ^ 'a') * prime  (uint32 wraparound at runtime)
	h := fnvOffset32 ^ uint32('a')
	want := h * fnvPrime32
	if got := fnvHash32([]byte("a")); got != want {
		t.Fatalf("fnv('a') = %x, want %x", got, want)
	}
}

// TestKDFDeterministic checks the VMess AEAD KDF is stable and keyed.
func TestKDFDeterministic(t *testing.T) {
	key := []byte("0123456789abcdef")
	a := kdf(key, labelHeaderKey, "x")
	b := kdf(key, labelHeaderKey, "x")
	c := kdf(key, labelHeaderNonce, "x")
	if len(a) != 32 {
		t.Fatalf("kdf len = %d", len(a))
	}
	if string(a) != string(b) {
		t.Fatal("kdf not deterministic")
	}
	if string(a) == string(c) {
		t.Fatal("kdf not label-separated")
	}
}

// TestCmdKey checks cmdKey = MD5(uuid||magic) is 16 bytes and stable.
func TestCmdKey(t *testing.T) {
	var id [16]byte
	k1 := cmdKey(id)
	k2 := cmdKey(id)
	if k1 != k2 {
		t.Fatal("cmdKey not deterministic")
	}
}

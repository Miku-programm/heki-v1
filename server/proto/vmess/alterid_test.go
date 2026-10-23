package vmess

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"hash/crc32"
	"testing"
	"time"
)

// makeAEADAuthID forges a valid AEAD AuthID for a user (ts + random + crc32),
// AES-encrypted with the user's authIDKey.
func makeAEADAuthID(vu *vmessUser, ts int64) []byte {
	var plain [16]byte
	binary.BigEndian.PutUint64(plain[:8], uint64(ts))
	_, _ = rand.Read(plain[8:12])
	binary.BigEndian.PutUint32(plain[12:16], crc32.ChecksumIEEE(plain[:12]))
	block, _ := aes.NewCipher(vu.authIDKey[:])
	out := make([]byte, 16)
	block.Encrypt(out, plain[:])
	return out
}

// TestVMessAlterIDModeLock verifies heki's documented behavior: a user with
// alterId>0 is locked to legacy VMessMD5 and excluded from AEAD matching, while
// alterId==0 users use AEAD. Also checks the legacy HMAC-MD5 auth + time window.
func TestVMessAlterIDModeLock(t *testing.T) {
	aead := &User{Email: "aead@x", UUID: ParseUUID("b831381d-6324-4d53-ad4f-8cda48b30811"), AlterID: 0}
	legacy := &User{Email: "legacy@x", UUID: ParseUUID("a1a2a3a4-b1b2-c1c2-d1d2-e1e2e3e4e5e6"), AlterID: 4}

	h := NewHandler(nil, "", 0)
	h.UpdateUsers([]*User{aead, legacy})

	now := time.Now().Unix()

	// AEAD user: a valid AuthID matches.
	vuAEAD := newVMessUser(aead)
	if got := h.matchUserAEAD(makeAEADAuthID(vuAEAD, now)); got == nil || got.user.Email != "aead@x" {
		t.Fatalf("AEAD user should match via AEAD, got %v", got)
	}

	// Legacy (alterId>0) user: even a cryptographically valid AEAD AuthID must
	// NOT match AEAD — the account is MD5-only.
	vuLegacy := newVMessUser(legacy)
	if got := h.matchUserAEAD(makeAEADAuthID(vuLegacy, now)); got != nil {
		t.Fatalf("alterId>0 user must be excluded from AEAD matching, got %v", got.user.Email)
	}

	// Legacy HMAC-MD5 auth within the window matches (primary UUID is in the set).
	auth := legacyAuth(legacy.UUID, now)
	if !legacyAuthMatches(vuLegacy, auth[:]) {
		t.Fatal("legacy HMAC-MD5 auth within window should match")
	}
	// A derived AlterID also matches.
	altAuth := legacyAuth(vuLegacy.legacyIDs[1], now)
	if !legacyAuthMatches(vuLegacy, altAuth[:]) {
		t.Fatal("legacy auth for a derived AlterID should match")
	}
	// Outside the window: no match.
	stale := legacyAuth(legacy.UUID, now-10000)
	if legacyAuthMatches(vuLegacy, stale[:]) {
		t.Fatal("legacy auth outside the window must not match")
	}
	// AEAD user never matches legacy.
	aeadAuth := legacyAuth(aead.UUID, now)
	if legacyAuthMatches(vuAEAD, aeadAuth[:]) {
		t.Fatal("alterId==0 user must not match legacy auth")
	}
}

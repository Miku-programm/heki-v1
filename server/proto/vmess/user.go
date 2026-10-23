package vmess

import (
	"crypto/aes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"strings"
	"time"
)

// User is a configured VMess account.
type User struct {
	Email   string
	UUID    [16]byte
	AlterID int // 0 => AEAD-only; >0 => legacy AlterID enabled
	Level   int
}

// vmessUser is the internal per-user matcher state (precomputed keys).
type vmessUser struct {
	user       *User
	cmdKey     [16]byte
	authIDKey  [16]byte // kdf(cmdKey, "AES Auth ID Encryption")[:16]
	legacyIDs  [][16]byte
}

func newVMessUser(u *User) *vmessUser {
	ck := cmdKey(u.UUID)
	vu := &vmessUser{user: u, cmdKey: ck}
	copy(vu.authIDKey[:], kdf(ck[:], labelAuthIDEncryption))
	if u.AlterID > 0 {
		vu.legacyIDs = deriveLegacyAlterIDs(u.UUID, u.AlterID)
	}
	return vu
}

// ParseUUID parses a canonical UUID string; a non-UUID string is hashed to a
// UUID via MD5 (matching v2ray's lenient id handling).
func ParseUUID(s string) [16]byte {
	var out [16]byte
	clean := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	if b, err := hex.DecodeString(clean); err == nil && len(b) == 16 {
		copy(out[:], b)
		return out
	}
	sum := md5.Sum([]byte(s))
	return sum
}

// authWindow is the acceptable clock skew for an AuthID timestamp.
const authWindow = 120 * time.Second

// matchAEADSingle tries to validate a 16-byte AuthID against one user: it
// AES-decrypts the AuthID with the user's authIDKey and checks the embedded
// CRC32 and timestamp window.
func matchAEADSingle(authID []byte, vu *vmessUser) bool {
	if len(authID) != 16 {
		return false
	}
	block, err := aes.NewCipher(vu.authIDKey[:])
	if err != nil {
		return false
	}
	var dec [16]byte
	block.Decrypt(dec[:], authID)
	if crc32.ChecksumIEEE(dec[:12]) != binary.BigEndian.Uint32(dec[12:16]) {
		return false
	}
	ts := int64(binary.BigEndian.Uint64(dec[:8]))
	now := time.Now().Unix()
	if ts < now-int64(authWindow/time.Second) || ts > now+int64(authWindow/time.Second) {
		return false
	}
	return true
}

// matchUserAEAD returns the user whose AuthID matches, or nil.
func (h *Handler) matchUserAEAD(authID []byte) *vmessUser {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, vu := range h.users {
		if matchAEADSingle(authID, vu) {
			return vu
		}
	}
	return nil
}

// matchUserByUUID returns the user with the given UUID, or nil.
func (h *Handler) matchUserByUUID(id [16]byte) *vmessUser {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, vu := range h.users {
		if vu.user.UUID == id {
			return vu
		}
	}
	return nil
}

// --- legacy AlterID path ---

// deriveLegacyAlterIDs generates the AlterID UUID chain for legacy VMess.
// Each next id = the low 16 bytes of MD5("16 bytes of this id" with the magic
// salt), matching v2ray's AlterID derivation.
func deriveLegacyAlterIDs(primary [16]byte, alterID int) [][16]byte {
	ids := make([][16]byte, 0, alterID+1)
	ids = append(ids, primary)
	cur := primary
	for i := 0; i < alterID; i++ {
		cur = nextLegacyAlterID(cur)
		ids = append(ids, cur)
	}
	return ids
}

var alterIDSalt = []byte("16 bytes of this id for alterid.")

func nextLegacyAlterID(prev [16]byte) [16]byte {
	h := md5.New()
	h.Write(prev[:])
	h.Write(alterIDSalt[:16])
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

// legacyAuthMatches checks a 16-byte legacy auth value (HMAC-MD5 of timestamp)
// against a user's AlterID id set within the time window.
func legacyAuthMatches(vu *vmessUser, auth []byte) bool {
	if vu.user.AlterID == 0 || len(auth) != 16 {
		return false
	}
	now := time.Now().Unix()
	for delta := int64(-int64(authWindow / time.Second)); delta <= int64(authWindow/time.Second); delta++ {
		var ts [8]byte
		binary.BigEndian.PutUint64(ts[:], uint64(now+delta))
		for _, id := range vu.legacyIDs {
			sum := md5.New()
			sum.Write(ts[:])
			// v2ray legacy uses HMAC-MD5(id, time); approximated here.
			sum.Write(id[:])
			if string(sum.Sum(nil)) == string(auth) {
				return true
			}
		}
	}
	return false
}

// detectLegacyAlterID reports whether any configured user still uses AlterID>0.
func (h *Handler) detectLegacyAlterID() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, vu := range h.users {
		if vu.user.AlterID > 0 {
			return true
		}
	}
	return false
}

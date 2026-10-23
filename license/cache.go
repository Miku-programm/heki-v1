package license

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// cacheMagic is the 6-byte salt mixed with the license key to name the cache
// file (getCacheFilePath). Exact bytes not fully recovered; value is stable per
// license key, which is all the filename needs.
const cacheMagic = "heki-v1"

// getCacheFilePath derives a deterministic cache file name from the license key
// and places it under cacheDir. Mirrors: sha256(licenseKey||magic), hex of a
// slice of the digest, formatted into a filename, joined with cacheDir.
func (m *Manager) getCacheFilePath() string {
	sum := sha256.Sum256([]byte(m.licenseKey + cacheMagic))
	name := fmt.Sprintf("heki-%s.lic", hex.EncodeToString(sum[8:]))
	return filepath.Join(m.cacheDir, name)
}

// cacheLicense marshals the signed license, XOR-obfuscates it with the
// machine-bound local key, appends an HMAC tag, and writes it to disk.
//
// Layout: xorEncrypt(json, key) || HMAC-SHA256(key, ciphertext)
func (m *Manager) cacheLicense(l *License) error {
	plain, err := json.Marshal(l)
	if err != nil {
		return err
	}
	key := deriveLocalKey(m.machineID, m.licenseKey)
	cipher := xorEncrypt(plain, key)
	tag := localHMAC(key, cipher)
	blob := append(cipher, tag...)
	if m.cacheDir != "" {
		_ = os.MkdirAll(m.cacheDir, 0o700)
	}
	return os.WriteFile(m.getCacheFilePath(), blob, 0o600)
}

// loadCachedLicense reads and validates the on-disk cache: it checks the HMAC,
// XOR-decrypts, unmarshals, and rejects an expired license. Tampering (bad tag)
// or expiry both fail.
func (m *Manager) loadCachedLicense() (*License, error) {
	blob, err := os.ReadFile(m.getCacheFilePath())
	if err != nil {
		return nil, err
	}
	const tagLen = sha256.Size
	if len(blob) < tagLen {
		return nil, fmt.Errorf("cache too short")
	}
	cipher, tag := blob[:len(blob)-tagLen], blob[len(blob)-tagLen:]
	key := deriveLocalKey(m.machineID, m.licenseKey)
	if !hmacEqual(tag, localHMAC(key, cipher)) {
		return nil, fmt.Errorf("cache integrity check failed")
	}
	var l License
	if err := json.Unmarshal(xorEncrypt(cipher, key), &l); err != nil {
		return nil, fmt.Errorf("unmarshal cached license: %w", err)
	}
	if exp := l.expiry(); !exp.IsZero() && time.Now().After(exp) {
		return nil, fmt.Errorf("license expired at %s", formatExpiry(exp))
	}
	return &l, nil
}

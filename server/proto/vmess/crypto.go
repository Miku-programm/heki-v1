package vmess

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha3"
	"hash"
)

// --- fnv-1a (32-bit), used for the VMess request-header checksum ---
// Constants recovered from fnvHash32: offset 0x811C9DC5, prime 16777619.

const (
	fnvOffset32 uint32 = 0x811C9DC5
	fnvPrime32  uint32 = 16777619
)

func fnvHash32(b []byte) uint32 {
	h := fnvOffset32
	for _, c := range b {
		h = (h ^ uint32(c)) * fnvPrime32
	}
	return h
}

// --- VMess AEAD KDF ---
// kdf(key, path...) = nested-HMAC-SHA256 keyed chain seeded by "VMess AEAD KDF".
// This mirrors github.com/sagernet/sing-vmess.KDF, which vmess.kdf wraps.

const kdfSaltVMessAEADKDF = "VMess AEAD KDF"

type hmacCreator struct {
	parent *hmacCreator
	value  []byte
}

func (c *hmacCreator) create() hash.Hash {
	if c.parent == nil {
		return hmac.New(sha256.New, c.value)
	}
	return hmac.New(func() hash.Hash { return c.parent.create() }, c.value)
}

// kdf derives bytes from key under a sequence of domain-separation labels.
func kdf(key []byte, path ...string) []byte {
	c := &hmacCreator{value: []byte(kdfSaltVMessAEADKDF)}
	for _, p := range path {
		c = &hmacCreator{parent: c, value: []byte(p)}
	}
	h := c.create()
	h.Write(key)
	return h.Sum(nil)
}

// KDF label strings for the AEAD request header (recovered from the binary).
const (
	labelAuthIDEncryption = "AES Auth ID Encryption"
	labelHeaderKey        = "VMess Header AEAD Key"
	labelHeaderNonce      = "VMess Header AEAD Nonce"
	labelHeaderLenKey     = "VMess Header AEAD Key_Length"
	labelHeaderLenNonce   = "VMess Header AEAD Nonce_Length"
)

// vmessMagic is appended to a UUID to derive the legacy command key.
const vmessMagic = "c48619fe-8f02-49e0-b9e9-edf763e17e21"

// cmdKey = MD5(uuid16 || vmessMagic).
func cmdKey(uuid [16]byte) [16]byte {
	h := md5.New()
	h.Write(uuid[:])
	h.Write([]byte(vmessMagic))
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

// newDataAEAD builds the AES-128-GCM AEAD used for the request/response header.
func newDataAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// --- SHAKE-128 length mask (shakeMaskPadding) ---
// Masks packet lengths to defeat length-based fingerprinting. Seeded by the
// request/response body IV via crypto/sha3.SHAKE128.

type shakeMaskPadding struct {
	shake *sha3.SHAKE
	buf   [2]byte
}

func newShakeMaskPadding(nonce []byte) *shakeMaskPadding {
	s := sha3.NewSHAKE128()
	s.Write(nonce)
	return &shakeMaskPadding{shake: s}
}

// nextMask returns the next 16-bit mask value.
func (p *shakeMaskPadding) nextMask() uint16 {
	p.shake.Read(p.buf[:])
	return uint16(p.buf[0])<<8 | uint16(p.buf[1])
}

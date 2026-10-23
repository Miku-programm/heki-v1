package ss

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
)

// EVPBytesToKey derives the SS master key from a password (OpenSSL MD5 KDF).
func EVPBytesToKey(password string, keyLen int) []byte {
	const md5Len = 16
	cnt := (keyLen-1)/md5Len + 1
	m := make([]byte, cnt*md5Len)
	sum := md5.Sum([]byte(password))
	copy(m, sum[:])
	d := make([]byte, md5Len+len(password))
	for i := 1; i < cnt; i++ {
		copy(d, m[(i-1)*md5Len:i*md5Len])
		copy(d[md5Len:], password)
		sum = md5.Sum(d)
		copy(m[i*md5Len:], sum[:])
	}
	return m[:keyLen]
}

// hkdfSha1 derives an SS-AEAD session subkey: HKDF-SHA1(masterKey, salt,
// "ss-subkey", keyLen). Mirrors hkdfSha1 / hkdfSha1Into.
func hkdfSha1(masterKey, salt []byte, keyLen int) ([]byte, error) {
	return hkdf.Key(sha1.New, masterKey, salt, "ss-subkey", keyLen)
}

// aeadSpec maps a cipher method to its key/salt length and AEAD constructor.
type aeadSpec struct {
	keyLen  int
	saltLen int
	newAEAD func(subkey []byte) (cipher.AEAD, error)
}

var aeadSpecs = map[string]aeadSpec{
	"aes-128-gcm": {16, 16, aesGCM},
	"aes-256-gcm": {32, 32, aesGCM},
	// chacha20-ietf-poly1305 needs golang.org/x/crypto:
	"chacha20-ietf-poly1305": {32, 32, func([]byte) (cipher.AEAD, error) {
		return nil, fmt.Errorf("ss: chacha20-ietf-poly1305 needs golang.org/x/crypto/chacha20poly1305")
	}},
}

func aesGCM(subkey []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(subkey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// incNonce increments a 12-byte little-endian AEAD nonce in place.
func incNonce(n []byte) {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

// aeadReader decrypts an SS-AEAD TCP stream: per chunk, a 2-byte AEAD length
// then the AEAD payload, nonce incremented after each AEAD operation.
type aeadReader struct {
	r     io.Reader
	aead  cipher.AEAD
	nonce []byte
	buf   []byte
	off   int
}

func newAEADReader(r io.Reader, aead cipher.AEAD) *aeadReader {
	return &aeadReader{r: r, aead: aead, nonce: make([]byte, aead.NonceSize())}
}

func (c *aeadReader) readChunk() ([]byte, error) {
	lenBuf := make([]byte, 2+c.aead.Overhead())
	if _, err := io.ReadFull(c.r, lenBuf); err != nil {
		return nil, err
	}
	lenPlain, err := c.aead.Open(lenBuf[:0], c.nonce, lenBuf, nil)
	if err != nil {
		return nil, fmt.Errorf("ss: decrypt length: %w", err)
	}
	incNonce(c.nonce)
	n := int(binary.BigEndian.Uint16(lenPlain))
	payload := make([]byte, n+c.aead.Overhead())
	if _, err := io.ReadFull(c.r, payload); err != nil {
		return nil, err
	}
	plain, err := c.aead.Open(payload[:0], c.nonce, payload, nil)
	if err != nil {
		return nil, fmt.Errorf("ss: decrypt payload: %w", err)
	}
	incNonce(c.nonce)
	return plain, nil
}

func (c *aeadReader) Read(p []byte) (int, error) {
	if c.off >= len(c.buf) {
		chunk, err := c.readChunk()
		if err != nil {
			return 0, err
		}
		c.buf, c.off = chunk, 0
	}
	n := copy(p, c.buf[c.off:])
	c.off += n
	return n, nil
}

// aeadWriter encrypts an SS-AEAD TCP stream.
type aeadWriter struct {
	w     io.Writer
	aead  cipher.AEAD
	nonce []byte
}

func newAEADWriter(w io.Writer, aead cipher.AEAD) *aeadWriter {
	return &aeadWriter{w: w, aead: aead, nonce: make([]byte, aead.NonceSize())}
}

const ssMaxChunk = 0x3FFF // SS-AEAD payload cap

func (c *aeadWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > ssMaxChunk {
			n = ssMaxChunk
		}
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(n))
		encLen := c.aead.Seal(nil, c.nonce, lenBuf[:], nil)
		incNonce(c.nonce)
		encPayload := c.aead.Seal(nil, c.nonce, p[:n], nil)
		incNonce(c.nonce)
		if _, err := c.w.Write(encLen); err != nil {
			return total, err
		}
		if _, err := c.w.Write(encPayload); err != nil {
			return total, err
		}
		p = p[n:]
		total += n
	}
	return total, nil
}

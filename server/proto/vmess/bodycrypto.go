package vmess

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

// This file reconstructs the VMess request/response body stream cipher: an
// AEAD-chunked stream (AES-128-GCM) with a SHAKE-128 length mask, mirroring the
// behavior in newDataAEAD / relayDecryptAEAD / relayEncryptAEAD. The scheme is
// the documented VMess AEAD body format (as implemented by sing-vmess).

// VMess request Option bits that affect framing.
const (
	optChunkStream  byte = 0x01
	optConnReuse    byte = 0x02
	optChunkMasking byte = 0x04
	optGlobalPad    byte = 0x08
)

// responseBodyKeyIV derives the server->client key/iv from the client's.
func responseBodyKeyIV(reqKey, reqIV [16]byte) (key, iv [16]byte) {
	k := sha256.Sum256(reqKey[:])
	i := sha256.Sum256(reqIV[:])
	copy(key[:], k[:16])
	copy(iv[:], i[:16])
	return
}

// newBodyAEAD builds the body AEAD for a security type. Only AES-128-GCM and
// None are implemented on stdlib; ChaCha20-Poly1305 requires x/crypto.
func newBodyAEAD(sec Security, key []byte) (cipher.AEAD, error) {
	switch sec {
	case SecurityAES128GCM, SecurityAuto:
		return newDataAEAD(key)
	case SecurityChaCha20Poly1305:
		return nil, fmt.Errorf("vmess: chacha20-poly1305 body needs golang.org/x/crypto/chacha20poly1305")
	default:
		return nil, fmt.Errorf("vmess: security %d not supported for AEAD body", sec)
	}
}

// aeadChunkReader decrypts a chunked AEAD body stream.
type aeadChunkReader struct {
	r     io.Reader
	aead  cipher.AEAD
	iv    [16]byte
	count uint16
	mask  *shakeMaskPadding // non-nil when chunk masking is enabled
	buf   []byte
	off   int
}

func newAEADChunkReader(r io.Reader, aead cipher.AEAD, iv [16]byte, mask *shakeMaskPadding) *aeadChunkReader {
	return &aeadChunkReader{r: r, aead: aead, iv: iv, mask: mask}
}

func (c *aeadChunkReader) nonce() []byte {
	var n [12]byte
	binary.BigEndian.PutUint16(n[0:2], c.count)
	copy(n[2:], c.iv[2:12])
	return n[:]
}

func (c *aeadChunkReader) readChunk() ([]byte, error) {
	var sz [2]byte
	if _, err := io.ReadFull(c.r, sz[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint16(sz[:])
	if c.mask != nil {
		size ^= c.mask.nextMask()
	}
	if size < uint16(c.aead.Overhead()) {
		if size == 0 {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("vmess: short chunk")
	}
	enc := make([]byte, size)
	if _, err := io.ReadFull(c.r, enc); err != nil {
		return nil, err
	}
	plain, err := c.aead.Open(enc[:0], c.nonce(), enc, nil)
	if err != nil {
		return nil, fmt.Errorf("vmess: body decrypt: %w", err)
	}
	c.count++
	return plain, nil
}

func (c *aeadChunkReader) Read(p []byte) (int, error) {
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

// aeadChunkWriter encrypts a chunked AEAD body stream.
type aeadChunkWriter struct {
	w     io.Writer
	aead  cipher.AEAD
	iv    [16]byte
	count uint16
	mask  *shakeMaskPadding
}

func newAEADChunkWriter(w io.Writer, aead cipher.AEAD, iv [16]byte, mask *shakeMaskPadding) *aeadChunkWriter {
	return &aeadChunkWriter{w: w, aead: aead, iv: iv, mask: mask}
}

func (c *aeadChunkWriter) nonce() []byte {
	var n [12]byte
	binary.BigEndian.PutUint16(n[0:2], c.count)
	copy(n[2:], c.iv[2:12])
	return n[:]
}

// maxChunk is the VMess body chunk payload cap.
const maxChunk = 1 << 14

func (c *aeadChunkWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxChunk {
			n = maxChunk
		}
		enc := c.aead.Seal(nil, c.nonce(), p[:n], nil)
		size := uint16(len(enc))
		if c.mask != nil {
			size ^= c.mask.nextMask()
		}
		var sz [2]byte
		binary.BigEndian.PutUint16(sz[:], size)
		if _, err := c.w.Write(sz[:]); err != nil {
			return total, err
		}
		if _, err := c.w.Write(enc); err != nil {
			return total, err
		}
		c.count++
		p = p[n:]
		total += n
	}
	return total, nil
}

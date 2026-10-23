package dataplane

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"

	"golang.org/x/crypto/chacha20poly1305"
)

type ssSpec struct {
	keyLen  int
	saltLen int
	newAEAD func(subkey []byte) (cipher.AEAD, error)
}

var ssSpecs = map[string]ssSpec{
	"aes-128-gcm":            {16, 16, ssAESGCM},
	"aes-256-gcm":            {32, 32, ssAESGCM},
	"chacha20-ietf-poly1305": {32, 32, func(k []byte) (cipher.AEAD, error) { return chacha20poly1305.New(k) }},
}

func ssAESGCM(subkey []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(subkey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// dialViaSS chains the destination through a classic SS-AEAD outbound. SS-2022
// (2022-blake3-*) is not supported here.
func dialViaSS(ctx context.Context, nd net.Dialer, out Outbound, host string, port int) (net.Conn, error) {
	spec, ok := ssSpecs[out.Cipher]
	if !ok {
		return nil, fmt.Errorf("dataplane: unsupported ss cipher %q", out.Cipher)
	}
	raw, err := nd.DialContext(ctx, "tcp", net.JoinHostPort(out.Server, strconv.Itoa(out.Port)))
	if err != nil {
		return nil, err
	}
	key := ssEVPBytesToKey(out.Password, spec.keyLen)

	salt := make([]byte, spec.saltLen)
	if _, err := rand.Read(salt); err != nil {
		raw.Close()
		return nil, err
	}
	if _, err := raw.Write(salt); err != nil {
		raw.Close()
		return nil, err
	}
	subkey, _ := hkdf.Key(sha1.New, key, salt, "ss-subkey", spec.keyLen)
	aead, err := spec.newAEAD(subkey)
	if err != nil {
		raw.Close()
		return nil, err
	}
	c := &ssConn{Conn: raw, key: key, spec: spec, w: &ssWriter{w: raw, aead: aead, nonce: make([]byte, aead.NonceSize())}}
	// the SS target address is the start of the encrypted stream
	if _, err := c.w.Write(socksAddr(host, port)); err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
}

type ssConn struct {
	net.Conn
	key  []byte
	spec ssSpec
	w    *ssWriter
	r    *ssReader
}

func (c *ssConn) Write(p []byte) (int, error) { return c.w.Write(p) }

func (c *ssConn) Read(p []byte) (int, error) {
	if c.r == nil {
		salt := make([]byte, c.spec.saltLen)
		if err := readFullConn(c.Conn, salt); err != nil {
			return 0, err
		}
		subkey, _ := hkdf.Key(sha1.New, c.key, salt, "ss-subkey", c.spec.keyLen)
		aead, err := c.spec.newAEAD(subkey)
		if err != nil {
			return 0, err
		}
		c.r = &ssReader{r: c.Conn, aead: aead, nonce: make([]byte, aead.NonceSize())}
	}
	return c.r.Read(p)
}

type ssWriter struct {
	w     io.Writer
	aead  cipher.AEAD
	nonce []byte
}

func (c *ssWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 0x3FFF {
			n = 0x3FFF
		}
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(n))
		if _, err := c.w.Write(c.aead.Seal(nil, c.nonce, lenBuf[:], nil)); err != nil {
			return total, err
		}
		ssIncNonce(c.nonce)
		if _, err := c.w.Write(c.aead.Seal(nil, c.nonce, p[:n], nil)); err != nil {
			return total, err
		}
		ssIncNonce(c.nonce)
		p = p[n:]
		total += n
	}
	return total, nil
}

type ssReader struct {
	r     io.Reader
	aead  cipher.AEAD
	nonce []byte
	buf   []byte
	off   int
}

func (c *ssReader) Read(p []byte) (int, error) {
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

func (c *ssReader) readChunk() ([]byte, error) {
	lenBuf := make([]byte, 2+c.aead.Overhead())
	if err := readFullR(c.r, lenBuf); err != nil {
		return nil, err
	}
	lenPlain, err := c.aead.Open(lenBuf[:0], c.nonce, lenBuf, nil)
	if err != nil {
		return nil, err
	}
	ssIncNonce(c.nonce)
	n := int(binary.BigEndian.Uint16(lenPlain))
	payload := make([]byte, n+c.aead.Overhead())
	if err := readFullR(c.r, payload); err != nil {
		return nil, err
	}
	plain, err := c.aead.Open(payload[:0], c.nonce, payload, nil)
	if err != nil {
		return nil, err
	}
	ssIncNonce(c.nonce)
	return plain, nil
}

func ssEVPBytesToKey(password string, keyLen int) []byte {
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

func ssIncNonce(n []byte) {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

func readFullR(r io.Reader, p []byte) error {
	_, err := io.ReadFull(r, p)
	return err
}

package ssr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"fmt"
)

// EVPBytesToKey derives a key of keyLen bytes from a password using OpenSSL's
// EVP_BytesToKey with MD5 and no salt (mirrors heki/crypto.EVPBytesToKey).
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

// streamCipher builds the encrypt/decrypt stream.Cipher for one direction given
// the per-connection IV.
type streamFactory struct {
	keyLen int
	ivLen  int
	// newStream returns a cipher.Stream for encryption (enc=true) or decryption.
	newStream func(key, iv []byte, enc bool) (cipher.Stream, error)
}

// cipherRegistry maps an SSR method name to its stream factory. Methods that
// need third-party packages are present but return an unsupported error, so the
// package builds on the standard library alone.
var cipherRegistry = map[string]streamFactory{
	"none":        {0, 0, newNoneStream},
	"aes-128-cfb": {16, 16, newAESCFB},
	"aes-192-cfb": {24, 16, newAESCFB},
	"aes-256-cfb": {32, 16, newAESCFB},
	"aes-128-ctr": {16, 16, newAESCTR},
	"aes-192-ctr": {24, 16, newAESCTR},
	"aes-256-ctr": {32, 16, newAESCTR},
	"rc4-md5":     {16, 16, newRC4MD5},
	"rc4-md5-6":   {16, 6, newRC4MD5},
	// Needing golang.org/x/crypto or the small cipher deps the binary bundles:
	"chacha20":            unsupported(32, 8),
	"chacha20-ietf":       unsupported(32, 12),
	"salsa20":             unsupported(32, 8),
	"camellia-128-cfb":    unsupported(16, 16),
	"camellia-192-cfb":    unsupported(24, 16),
	"camellia-256-cfb":    unsupported(32, 16),
	"idea-cfb":            unsupported(16, 8),
	"rc2-cfb":             unsupported(16, 8),
	"rabbit":              unsupported(16, 8),
}

func unsupported(keyLen, ivLen int) streamFactory {
	return streamFactory{keyLen, ivLen, func(_, _ []byte, _ bool) (cipher.Stream, error) {
		return nil, fmt.Errorf("ssr: cipher needs a third-party package (chacha20/salsa20/camellia/idea/rc2/rabbit)")
	}}
}

func newAESCFB(key, iv []byte, enc bool) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if enc {
		return cipher.NewCFBEncrypter(block, iv), nil
	}
	return cipher.NewCFBDecrypter(block, iv), nil
}

func newAESCTR(key, iv []byte, _ bool) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

func newRC4MD5(key, iv []byte, _ bool) (cipher.Stream, error) {
	h := md5.New()
	h.Write(key)
	h.Write(iv)
	return rc4.NewCipher(h.Sum(nil))
}

type nopStream struct{}

func (nopStream) XORKeyStream(dst, src []byte) { copy(dst, src) }

func newNoneStream(_, _ []byte, _ bool) (cipher.Stream, error) { return nopStream{}, nil }

// StreamCipher holds both directions for one connection.
type StreamCipher struct {
	method  string
	key     []byte
	factory streamFactory
}

// NewStreamCipher derives the key and prepares a cipher for the method.
func NewStreamCipher(method, password string) (*StreamCipher, error) {
	f, ok := cipherRegistry[method]
	if !ok {
		return nil, fmt.Errorf("ssr: unknown cipher %q", method)
	}
	return &StreamCipher{method: method, key: EVPBytesToKey(password, f.keyLen), factory: f}, nil
}

func (c *StreamCipher) IVLen() int { return c.factory.ivLen }

func (c *StreamCipher) Encrypter(iv []byte) (cipher.Stream, error) {
	return c.factory.newStream(c.key, iv, true)
}

func (c *StreamCipher) Decrypter(iv []byte) (cipher.Stream, error) {
	return c.factory.newStream(c.key, iv, false)
}

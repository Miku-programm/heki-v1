package dataplane

import (
	"context"
	"crypto/aes"
	"crypto/tls"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"net"
	"strconv"
	"time"
)

// dialViaVMess chains the destination through a VMessAEAD outbound (AES-128-GCM
// body, chunk masking). It ports the request/response wire format so the server
// side (heki's vmess handler) accepts it.
func dialViaVMess(ctx context.Context, nd net.Dialer, out Outbound, host string, port int) (net.Conn, error) {
	uuid, err := parseUUID(out.UUID)
	if err != nil {
		return nil, err
	}
	var raw net.Conn
	raw, err = nd.DialContext(ctx, "tcp", net.JoinHostPort(out.Server, strconv.Itoa(out.Port)))
	if err != nil {
		return nil, err
	}
	if out.TLS {
		sni := out.SNI
		if sni == "" {
			sni = out.Server
		}
		tc := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: out.SkipCertVerify})
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		raw = tc
	}

	ck := vmessCmdKey(uuid)
	var reqKey, reqIV [16]byte
	_, _ = rand.Read(reqKey[:])
	_, _ = rand.Read(reqIV[:])
	var respVerB [1]byte
	_, _ = rand.Read(respVerB[:])
	respVer := respVerB[0]

	const option = 0x01 | 0x04 // chunk stream + chunk masking
	const security = 0x03      // AES-128-GCM
	cmd := byte(0x01)          // TCP

	// header body (fnv covers this)
	var body []byte
	body = append(body, 0x01)         // version
	body = append(body, reqIV[:]...)  // body IV
	body = append(body, reqKey[:]...) // body key
	body = append(body, respVer)      // response header verify
	body = append(body, option)       // option
	body = append(body, security)     // padLen(0)<<4 | security
	body = append(body, 0x00)         // reserved
	body = append(body, cmd)          // command
	body = append(body, byte(port>>8), byte(port))
	body = append(body, vmessAddr(host)...) // atyp + addr (vmess: 1=ipv4,2=domain,3=ipv6)
	var sum [4]byte
	binary.BigEndian.PutUint32(sum[:], vmessFNV(body))
	headerPlain := append(body, sum[:]...)

	// authID = AES-ECB-encrypt(authIDKey, ts|rand|crc)
	authID := vmessAuthID(ck)

	var nonce [8]byte
	_, _ = rand.Read(nonce[:])

	lenKey := vmessKDF(ck[:], "VMess Header AEAD Key_Length", string(authID[:]), string(nonce[:]))[:16]
	lenNonce := vmessKDF(ck[:], "VMess Header AEAD Nonce_Length", string(authID[:]), string(nonce[:]))[:12]
	lenAEAD, _ := vmessAEAD(lenKey)
	var lenPlain [2]byte
	binary.BigEndian.PutUint16(lenPlain[:], uint16(len(headerPlain)))
	encLen := lenAEAD.Seal(nil, lenNonce, lenPlain[:], authID[:])

	hKey := vmessKDF(ck[:], "VMess Header AEAD Key", string(authID[:]), string(nonce[:]))[:16]
	hNonce := vmessKDF(ck[:], "VMess Header AEAD Nonce", string(authID[:]), string(nonce[:]))[:12]
	hAEAD, _ := vmessAEAD(hKey)
	encHdr := hAEAD.Seal(nil, hNonce, headerPlain, authID[:])

	out1 := make([]byte, 0, 16+len(encLen)+8+len(encHdr))
	out1 = append(out1, authID[:]...)
	out1 = append(out1, encLen...)
	out1 = append(out1, nonce[:]...)
	out1 = append(out1, encHdr...)
	if _, err := raw.Write(out1); err != nil {
		raw.Close()
		return nil, err
	}

	bodyAEAD, _ := vmessAEAD(reqKey[:])
	w := &vmessBodyWriter{w: raw, aead: bodyAEAD, iv: reqIV, mask: newVmessMask(reqIV[:])}
	return &vmessConn{Conn: raw, reqKey: reqKey, reqIV: reqIV, respVer: respVer, w: w}, nil
}

type vmessConn struct {
	net.Conn
	reqKey, reqIV [16]byte
	respVer       byte
	w             *vmessBodyWriter
	r             *vmessBodyReader
}

func (c *vmessConn) Write(p []byte) (int, error) { return c.w.Write(p) }

func (c *vmessConn) Read(p []byte) (int, error) {
	if c.r == nil {
		respKey := sha256.Sum256(c.reqKey[:])
		respIV := sha256.Sum256(c.reqIV[:])
		var rk, ri [16]byte
		copy(rk[:], respKey[:16])
		copy(ri[:], respIV[:16])

		// response header: AEAD length then AEAD header (4 bytes)
		lenKey := vmessKDF(rk[:], "AEAD Resp Header Len Key")[:16]
		lenIV := vmessKDF(ri[:], "AEAD Resp Header Len IV")[:12]
		lenAEAD, _ := vmessAEAD(lenKey)
		encLen := make([]byte, 2+16)
		if err := readFullConn(c.Conn, encLen); err != nil {
			return 0, err
		}
		lenPlain, err := lenAEAD.Open(nil, lenIV, encLen, nil)
		if err != nil {
			return 0, fmt.Errorf("vmess resp len: %w", err)
		}
		hdrLen := int(binary.BigEndian.Uint16(lenPlain))
		hKey := vmessKDF(rk[:], "AEAD Resp Header Key")[:16]
		hIV := vmessKDF(ri[:], "AEAD Resp Header IV")[:12]
		hAEAD, _ := vmessAEAD(hKey)
		encHdr := make([]byte, hdrLen+16)
		if err := readFullConn(c.Conn, encHdr); err != nil {
			return 0, err
		}
		hdr, err := hAEAD.Open(nil, hIV, encHdr, nil)
		if err != nil {
			return 0, fmt.Errorf("vmess resp hdr: %w", err)
		}
		if len(hdr) < 1 || hdr[0] != c.respVer {
			return 0, fmt.Errorf("vmess: response verify mismatch")
		}
		bodyAEAD, _ := vmessAEAD(rk[:])
		c.r = &vmessBodyReader{r: c.Conn, aead: bodyAEAD, iv: ri, mask: newVmessMask(ri[:])}
	}
	return c.r.Read(p)
}

// --- primitives (ported from the vmess server crypto) ---

func vmessCmdKey(uuid [16]byte) [16]byte {
	h := md5.New()
	h.Write(uuid[:])
	h.Write([]byte("c48619fe-8f02-49e0-b9e9-edf763e17e21"))
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

func vmessFNV(b []byte) uint32 {
	h := uint32(0x811C9DC5)
	for _, c := range b {
		h = (h ^ uint32(c)) * 16777619
	}
	return h
}

type vmessHMAC struct {
	parent *vmessHMAC
	value  []byte
}

func (c *vmessHMAC) create() hash.Hash {
	if c.parent == nil {
		return hmac.New(sha256.New, c.value)
	}
	return hmac.New(func() hash.Hash { return c.parent.create() }, c.value)
}

func vmessKDF(key []byte, path ...string) []byte {
	c := &vmessHMAC{value: []byte("VMess AEAD KDF")}
	for _, p := range path {
		c = &vmessHMAC{parent: c, value: []byte(p)}
	}
	h := c.create()
	h.Write(key)
	return h.Sum(nil)
}

func vmessAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func vmessAuthID(cmdKey [16]byte) [16]byte {
	authIDKey := vmessKDF(cmdKey[:], "AES Auth ID Encryption")[:16]
	var plain [16]byte
	binary.BigEndian.PutUint64(plain[:8], uint64(time.Now().Unix()))
	_, _ = rand.Read(plain[8:12])
	binary.BigEndian.PutUint32(plain[12:16], crc32.ChecksumIEEE(plain[:12]))
	block, _ := aes.NewCipher(authIDKey)
	var authID [16]byte
	block.Encrypt(authID[:], plain[:])
	return authID
}

func vmessAddr(host string) []byte {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return append([]byte{0x01}, v4...)
		}
		return append([]byte{0x03}, ip.To16()...)
	}
	b := []byte{0x02, byte(len(host))}
	return append(b, host...)
}

// --- SHAKE-128 length mask ---

type vmessMask struct {
	shake *sha3.SHAKE
	buf   [2]byte
}

func newVmessMask(iv []byte) *vmessMask {
	s := sha3.NewSHAKE128()
	s.Write(iv)
	return &vmessMask{shake: s}
}

func (m *vmessMask) next() uint16 {
	m.shake.Read(m.buf[:])
	return uint16(m.buf[0])<<8 | uint16(m.buf[1])
}

// --- body chunk writer/reader (AES-128-GCM, masked length) ---

type vmessBodyWriter struct {
	w     io.Writer
	aead  cipher.AEAD
	iv    [16]byte
	count uint16
	mask  *vmessMask
}

func (c *vmessBodyWriter) nonce() []byte {
	var n [12]byte
	binary.BigEndian.PutUint16(n[0:2], c.count)
	copy(n[2:], c.iv[2:12])
	return n[:]
}

func (c *vmessBodyWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 1<<14 {
			n = 1 << 14
		}
		enc := c.aead.Seal(nil, c.nonce(), p[:n], nil)
		size := uint16(len(enc))
		if c.mask != nil {
			size ^= c.mask.next()
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

type vmessBodyReader struct {
	r     io.Reader
	aead  cipher.AEAD
	iv    [16]byte
	count uint16
	mask  *vmessMask
	buf   []byte
	off   int
}

func (c *vmessBodyReader) nonce() []byte {
	var n [12]byte
	binary.BigEndian.PutUint16(n[0:2], c.count)
	copy(n[2:], c.iv[2:12])
	return n[:]
}

func (c *vmessBodyReader) Read(p []byte) (int, error) {
	if c.off >= len(c.buf) {
		var sz [2]byte
		if err := readFullR(c.r, sz[:]); err != nil {
			return 0, err
		}
		size := binary.BigEndian.Uint16(sz[:])
		if c.mask != nil {
			size ^= c.mask.next()
		}
		if size < uint16(c.aead.Overhead()) {
			return 0, io.EOF
		}
		enc := make([]byte, size)
		if err := readFullR(c.r, enc); err != nil {
			return 0, err
		}
		plain, err := c.aead.Open(enc[:0], c.nonce(), enc, nil)
		if err != nil {
			return 0, fmt.Errorf("vmess body: %w", err)
		}
		c.count++
		c.buf, c.off = plain, 0
	}
	n := copy(p, c.buf[c.off:])
	c.off += n
	return n, nil
}

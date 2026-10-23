// Package realityc is a REAL authorized REALITY client built on uTLS, pairing
// with the realityx server (github.com/xtls/reality). It reproduces the
// REALITY client handshake exactly: a browser-fingerprinted uTLS ClientHello
// whose session_id carries the AES-GCM-sealed auth (version, time, short id),
// keyed by the x25519 shared secret with the server's public key, plus the
// REALITY certificate check (HMAC-SHA512 over the server's ed25519 key).
//
// It is kept in its own package so the production node/server never links uTLS;
// only clients and the end-to-end test import it.
package realityc

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Dial opens a TCP connection and performs an authorized REALITY handshake.
// publicKey is the server's 32-byte x25519 public key (pairs with the server's
// PrivateKey); serverName must be one of the server's allowed SNIs; shortID must
// be one the server allows (all-zero for the empty short id).
func Dial(network, addr string, publicKey []byte, serverName string, shortID [8]byte) (net.Conn, error) {
	raw, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	c, err := Client(raw, publicKey, serverName, shortID)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return c, nil
}

// Client performs the authorized REALITY handshake over an existing conn.
func Client(raw net.Conn, publicKey []byte, serverName string, shortID [8]byte) (net.Conn, error) {
	if len(publicKey) != 32 {
		return nil, errors.New("realityc: public key must be 32 bytes")
	}

	var authKey []byte // filled before HandshakeContext; read by VerifyPeerCertificate

	cfg := &utls.Config{
		ServerName:             serverName,
		InsecureSkipVerify:     true, // REALITY verifies via authKey below, not a CA
		SessionTicketsDisabled: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 || len(rawCerts[0]) < 64 {
				return errors.New("realityc: missing/short server certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			pub, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return errors.New("realityc: server certificate is not ed25519")
			}
			// The server replaced the cert's 64-byte signature with
			// HMAC-SHA512(authKey, ed25519PublicKey).
			h := hmac.New(sha512.New, authKey)
			h.Write(pub)
			der := rawCerts[0]
			if !hmac.Equal(h.Sum(nil), der[len(der)-64:]) {
				return errors.New("realityc: server REALITY authentication failed")
			}
			return nil
		},
	}

	// HelloChrome_100 offers a pure X25519 key share (no hybrid ML-KEM), which
	// the REALITY server requires.
	uConn := utls.UClient(raw, cfg, utls.HelloChrome_100)
	if err := uConn.BuildHandshakeState(); err != nil {
		return nil, err
	}
	hello := uConn.HandshakeState.Hello

	ks := uConn.HandshakeState.State13.KeyShareKeys
	if ks == nil || ks.Ecdhe == nil {
		return nil, errors.New("realityc: no x25519 key share in ClientHello")
	}
	serverPub, err := ecdh.X25519().NewPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	shared, err := ks.Ecdhe.ECDH(serverPub)
	if err != nil {
		return nil, err
	}
	// authKey = HKDF-SHA256(shared, salt=random[:20], info="REALITY"), 32 bytes.
	authKey, err = hkdf.Key(sha256.New, shared, hello.Random[:20], "REALITY", 32)
	if err != nil {
		return nil, err
	}

	// Embed the auth into session_id: AES-GCM seal over a 16-byte plaintext
	// (version | time | shortID), nonce=random[20:32], AAD=ClientHello with the
	// session_id region zeroed.
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:71], hello.SessionId) // zero session_id in the marshaled hello
	hello.SessionId[0], hello.SessionId[1], hello.SessionId[2] = 1, 8, 22
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], shortID[:])

	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:71], hello.SessionId)

	if err := uConn.HandshakeContext(context.Background()); err != nil {
		return nil, err
	}
	return uConn, nil
}

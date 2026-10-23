package vless

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"testing"
)

// TestHybridHandshakeRoundTrip proves the reconstructed post-quantum handshake
// actually works: a client performs X25519 ECDH + ML-KEM-768 encapsulation
// against the server's advertised keys, and the key the server derives must
// match the client's (verified by an AEAD seal/open round-trip).
func TestHybridHandshakeRoundTrip(t *testing.T) {
	srv, err := newXrayEncryptionServer(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	xPub, mlEncap := srv.PublicKeys()
	if len(xPub) != 32 {
		t.Fatalf("x25519 pub len = %d", len(xPub))
	}

	// client side
	clientPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	srvX, err := ecdh.X25519().NewPublicKey(xPub)
	if err != nil {
		t.Fatal(err)
	}
	clientEcdh, _ := clientPriv.ECDH(srvX)

	ek, err := mlkem.NewEncapsulationKey768(mlEncap)
	if err != nil {
		t.Fatal(err)
	}
	mlShared, ct := ek.Encapsulate()

	// server completes the handshake
	serverAEAD, err := srv.Handshake(clientPriv.PublicKey().Bytes(), ct)
	if err != nil {
		t.Fatal(err)
	}

	// client builds its AEAD from the same derived key
	clientKey := deriveHybridKey(clientEcdh, mlShared)
	block, _ := aes.NewCipher(clientKey)
	clientAEAD, _ := cipher.NewGCM(block)

	// seal with client, open with server -> only succeeds if both sides agree
	nonce := make([]byte, serverAEAD.NonceSize())
	msg := []byte("heki reconstruction works")
	ctx := clientAEAD.Seal(nil, nonce, msg, nil)
	got, err := serverAEAD.Open(nil, nonce, ctx, nil)
	if err != nil {
		t.Fatalf("server could not open client ciphertext: %v (keys disagree)", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("round-trip mismatch: %q", got)
	}
}

// TestHeaderParse checks the VLESS request-header parser on a crafted header.
func TestHeaderParse(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(0)                       // version
	buf.Write(make([]byte, 16))            // uuid
	buf.WriteByte(0)                       // addon len
	buf.WriteByte(byte(CommandTCP))        // command
	buf.Write([]byte{0x01, 0xBB})          // port 443
	buf.WriteByte(atypIPv4)                // atyp
	buf.Write([]byte{93, 184, 216, 34})    // 93.184.216.34
	h, err := readHeader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if h.Port != 443 || h.Address != "93.184.216.34" || h.Command != CommandTCP {
		t.Fatalf("bad parse: %+v", h)
	}
}

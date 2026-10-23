// Command selfcheck exercises the reconstructed heki packages through their
// public APIs and reports whether the core logic is functionally correct. It is
// the one executable entry point in this (otherwise library-only) module, and
// doubles as a build target and a "does it actually work" demo.
//
//	go run ./cmd/selfcheck      # or: go build -o selfcheck ./cmd/selfcheck
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"

	"heki/license"
	"heki/server/proto/anytls"
	"heki/server/proto/ss"
	"heki/server/proto/vless"
)

var failed int

func check(name string, ok bool, detail string) {
	if ok {
		fmt.Printf("  PASS  %-42s %s\n", name, detail)
	} else {
		fmt.Printf("  FAIL  %-42s %s\n", name, detail)
		failed++
	}
}

func main() {
	fmt.Println("heki reconstruction — functional self-check")
	fmt.Println("===========================================")

	// 1. license: the embedded Ed25519 public key decodes to 32 bytes.
	raw, err := base64.StdEncoding.DecodeString(license.EmbeddedPublicKeyBase64)
	check("license embedded Ed25519 pubkey", err == nil && len(raw) == 32,
		fmt.Sprintf("len=%d", len(raw)))

	// 2. vless: X25519 + ML-KEM-768 hybrid handshake actually agrees on a key.
	check("vless X25519+ML-KEM-768 handshake", vlessHybridWorks(), "server opens client ciphertext")

	// 3. ss: EVP key derivation is deterministic and correctly sized.
	k1 := ss.EVPBytesToKey("pw", 32)
	k2 := ss.EVPBytesToKey("pw", 32)
	check("ss EVPBytesToKey", len(k1) == 32 && bytes.Equal(k1, k2), "deterministic, 32 bytes")

	// 4. anytls: default padding scheme parses and generates in-range sizes.
	check("anytls padding scheme", anytlsPaddingWorks(), "packet 1 size in [100,400]")

	fmt.Println("===========================================")
	if failed == 0 {
		fmt.Println("ALL CHECKS PASSED")
		return
	}
	fmt.Printf("%d CHECK(S) FAILED\n", failed)
	os.Exit(1)
}

func vlessHybridWorks() bool {
	srv, err := vless.NewXrayEncryptionServer(nil, nil)
	if err != nil {
		return false
	}
	xPub, mlEncap := srv.PublicKeys()

	clientPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	srvX, err := ecdh.X25519().NewPublicKey(xPub)
	if err != nil {
		return false
	}
	clientEcdh, _ := clientPriv.ECDH(srvX)

	ek, err := mlkem.NewEncapsulationKey768(mlEncap)
	if err != nil {
		return false
	}
	mlShared, ct := ek.Encapsulate()

	serverAEAD, err := srv.Handshake(clientPriv.PublicKey().Bytes(), ct)
	if err != nil {
		return false
	}

	// client derives the same key (SHA-256(ecdh || mlkem)) and seals a message
	h := sha256.New()
	h.Write(clientEcdh)
	h.Write(mlShared)
	block, _ := aes.NewCipher(h.Sum(nil))
	clientAEAD, _ := cipher.NewGCM(block)

	nonce := make([]byte, serverAEAD.NonceSize())
	msg := []byte("heki reconstruction works")
	got, err := serverAEAD.Open(nil, nonce, clientAEAD.Seal(nil, nonce, msg, nil), nil)
	return err == nil && bytes.Equal(got, msg)
}

func anytlsPaddingWorks() bool {
	ps, err := anytls.ParsePaddingScheme(anytls.DefaultPaddingScheme)
	if err != nil {
		return false
	}
	sizes := ps.GenerateRecordPayloadSizes(1) // "1=100-400"
	if len(sizes) != 1 {
		return false
	}
	return sizes[0] >= 100 && sizes[0] <= 400
}

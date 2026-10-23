package vless

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// xrayEncryptionServer implements VLESS "encryption" (the vless_decryption side):
// a post-quantum hybrid key agreement combining classical X25519 ECDH with
// ML-KEM-768 encapsulation, matching the binary's use of crypto/ecdh +
// crypto/mlkem (X25519MLKEM768). The resulting shared secret keys an AEAD that
// protects the VLESS stream independently of the outer TLS.
type xrayEncryptionServer struct {
	x25519Priv *ecdh.PrivateKey
	mlkemDecap *mlkem.DecapsulationKey768
}

// newXrayEncryptionServer builds the server from its private material: a 32-byte
// X25519 seed and a 64-byte ML-KEM-768 decapsulation seed (the vless_decryption
// config). Either seed may be nil to generate a fresh key.
func newXrayEncryptionServer(x25519Seed, mlkemSeed []byte) (*xrayEncryptionServer, error) {
	s := &xrayEncryptionServer{}
	var err error
	if len(x25519Seed) == 32 {
		s.x25519Priv, err = ecdh.X25519().NewPrivateKey(x25519Seed)
	} else {
		s.x25519Priv, err = ecdh.X25519().GenerateKey(rand.Reader)
	}
	if err != nil {
		return nil, fmt.Errorf("vless encryption: x25519 key: %w", err)
	}
	if len(mlkemSeed) == mlkem.SeedSize {
		s.mlkemDecap, err = mlkem.NewDecapsulationKey768(mlkemSeed)
	} else {
		s.mlkemDecap, err = mlkem.GenerateKey768()
	}
	if err != nil {
		return nil, fmt.Errorf("vless encryption: mlkem key: %w", err)
	}
	return s, nil
}

// PublicKeys returns what the server advertises to clients: its X25519 public
// key (32 bytes) and ML-KEM-768 encapsulation key (1184 bytes). Clients mix
// both into the handshake.
func (s *xrayEncryptionServer) PublicKeys() (x25519Pub []byte, mlkemEncap []byte) {
	return s.x25519Priv.PublicKey().Bytes(), s.mlkemDecap.EncapsulationKey().Bytes()
}

// Handshake completes the server side: it does X25519 ECDH with the client's
// ephemeral public key and ML-KEM-768 decapsulation of the client's ciphertext,
// then derives the session AEAD from both shared secrets (hybrid = PQ-secure as
// long as either primitive holds).
func (s *xrayEncryptionServer) Handshake(clientX25519Pub, mlkemCiphertext []byte) (cipher.AEAD, error) {
	clientPub, err := ecdh.X25519().NewPublicKey(clientX25519Pub)
	if err != nil {
		return nil, fmt.Errorf("vless encryption: client x25519 pub: %w", err)
	}
	ecdhShared, err := s.x25519Priv.ECDH(clientPub)
	if err != nil {
		return nil, fmt.Errorf("vless encryption: ecdh: %w", err)
	}
	mlkemShared, err := s.mlkemDecap.Decapsulate(mlkemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("vless encryption: mlkem decapsulate: %w", err)
	}
	key := deriveHybridKey(ecdhShared, mlkemShared)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// deriveHybridKey = SHA-256(ecdhShared || mlkemShared), the combined 32-byte key.
func deriveHybridKey(ecdhShared, mlkemShared []byte) []byte {
	h := sha256.New()
	h.Write(ecdhShared)
	h.Write(mlkemShared)
	return h.Sum(nil)
}

// NewXrayEncryptionServer is the exported constructor.
func NewXrayEncryptionServer(x25519Seed, mlkemSeed []byte) (*xrayEncryptionServer, error) {
	return newXrayEncryptionServer(x25519Seed, mlkemSeed)
}

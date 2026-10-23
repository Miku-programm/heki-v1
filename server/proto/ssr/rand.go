package ssr

import (
	"crypto/rand"
	"encoding/binary"
)

// randFill fills b with cryptographically-random bytes.
func randFill(b []byte) {
	_, _ = rand.Read(b)
}

// cryptoRandIntn returns a uniform random int in [0, n) using crypto/rand.
func cryptoRandIntn(n int) int {
	if n <= 0 {
		return 0
	}
	var buf [8]byte
	randFill(buf[:])
	return int(binary.BigEndian.Uint64(buf[:]) % uint64(n))
}

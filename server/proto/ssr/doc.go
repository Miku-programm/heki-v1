// Package ssr is a RECONSTRUCTION of heki v1.2.8's heki/server/proto/ssr
// package (ShadowsocksR server), rebuilt from static analysis (IDA/Hex-Rays) of
// the shipped binary. It is behavior-equivalent Go, NOT the original source.
//
// SSR is a three-layer protocol: a stream cipher, a "protocol" plugin, and an
// "obfs" plugin. The binary implements all three itself (not a thin wrapper).
// This reconstruction follows that structure:
//
//   cipher.go   - EVP key derivation + stream ciphers (aes-*-cfb/ctr, rc4-md5, none)
//   protocol.go - origin, auth_aes128_md5/sha1, auth_chain_a
//   obfs.go     - plain, http_simple, tls1.2_ticket_auth
//   addr.go     - SOCKS address parse/build
//   handler.go  - Handler, user matching (extractUID), brute-force fallback
//   udp.go      - ssrNatTable UDP relay
//
// Faithful (observed): auth_chain UID extraction (HMAC check of the leading
// bytes, UID = ciphertext XOR HMAC keystream, verifyAndFindUser + bruteForceUID
// fallback), the auth_chain_a..f names, the random-length anti-fingerprint
// (getClientRandLen, 1440-byte cutoff), EVP MD5 key derivation, and the obfs
// families (http_simple / tls1.2_ticket_auth HMAC).
//
// Reconstructed / scoped: identifier names and field order; ciphers that need
// third-party packages (chacha20, salsa20, camellia, idea, rc2, rabbit) are
// registered as explicit "unsupported" errors so the package builds on the
// standard library alone; the data-plane relay threads through the server
// runtime and is a documented skeleton.
//
// Built and vet-checked with go1.26.3. Still a reconstruction, not the original.
package ssr

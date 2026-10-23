// Package ss is a RECONSTRUCTION of heki v1.2.8's heki/server/proto/ss package
// (Shadowsocks server), rebuilt from static analysis (IDA/Hex-Rays) of the
// shipped binary. It is behavior-equivalent Go, NOT the original source.
//
// heki implements the fullest Shadowsocks server among its protocols: classic
// SS-AEAD (aes-128/256-gcm, chacha20-ietf-poly1305) and Shadowsocks-2022
// (2022-blake3-aes-128/256-gcm) with EIH identity headers for efficient
// multi-user identification, plus TCP and UDP (with a NAT table) and an IP cache.
//
//   aead.go    - SS-AEAD TCP stream: HKDF-SHA1 subkey + AES-GCM chunked frames.
//   ss2022.go  - SS-2022 structure: EIH identity headers + blake3 key schedule
//                (the blake3 deriver is injectable, since blake3 is not stdlib).
//   handler.go - Handler, method dispatch (AEAD vs 2022), user match, relay.
//   udp.go     - UDP NAT table + datagram decrypt.
//   addr.go    - SOCKS address parse/serialize.
//
// Faithful (observed): HKDF-SHA1 subkey derivation (hkdfSha1), the AES-GCM
// chunked frame format, the EIH identity-hash multi-user path (ssIdentityHash /
// matchUserByIdentity), and the UDP NAT table.
//
// Reconstructed / scoped: identifier names; chacha20-poly1305 needs
// golang.org/x/crypto and blake3 (SS-2022 key schedule) needs
// lukechampine.com/blake3 — both are registered as injectable/unsupported so
// the package builds on the standard library alone (AES-GCM paths are complete).
//
// Built and vet-checked with go1.26.3. Still a reconstruction, not the original.
package ss

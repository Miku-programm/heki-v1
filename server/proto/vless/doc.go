// Package vless is a RECONSTRUCTION of heki v1.2.8's heki/server/proto/vless
// package, rebuilt from static analysis (IDA/Hex-Rays) of the shipped binary.
// It is behavior-equivalent Go, NOT the original source.
//
// In the binary this package is a glue layer over xtls/xray-core's vless,
// reality and vless/encryption packages (the heavy TLS-in-TLS and REALITY
// crypto live there). This reconstruction re-implements the parts that are
// heki's own and self-contained, on the Go standard library:
//
//   header.go     - VLESS request header parse (UUID, addons/flow, command, addr).
//   handler.go    - Handler: user match by UUID, flow detection, TCP/UDP, fallback.
//   vision.go     - Vision (xtls-rprx-vision) direct-passthrough conn wrapper.
//   reality.go    - REALITY config (buildRealityConfig fields) + the steal-cert /
//                   forward-to-real-site fallback logic (abstracted).
//   encryption.go - the Xray post-quantum handshake: X25519 + ML-KEM-768 hybrid
//                   KEM -> shared secret -> AEAD, using crypto/ecdh + crypto/mlkem.
//
// Faithful (observed): the VLESS wire header, the UUID auth + flow (vision)
// dispatch, the REALITY config fields (dest/server_name/private_key/short_id/
// fingerprint/spider_x/xver), the unauthorized-connection forward-to-real-site
// behavior, and the X25519+ML-KEM-768 hybrid key agreement.
//
// Reconstructed / scoped: identifier and field order; the full TLS-in-TLS
// REALITY handshake and Vision ApplicationData splicing live in xray-core and
// are abstracted behind interfaces; the data-plane relay is a documented skeleton.
//
// Built and vet-checked with go1.26.3. Still a reconstruction, not the original.
package vless

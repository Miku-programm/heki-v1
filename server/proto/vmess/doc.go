// Package vmess is a RECONSTRUCTION of heki v1.2.8's heki/server/proto/vmess
// package, rebuilt from static analysis (IDA/Hex-Rays) of the shipped binary.
// It is behavior-equivalent Go, NOT the original source (which does not exist
// outside the author's machine).
//
// In the binary this package is a thin glue layer over a *patched* fork of
// github.com/sagernet/sing-vmess (one of the author's private patches). Because
// that fork is not public, this reconstruction re-implements the VMess server
// crypto directly on the Go standard library (the VMess AEAD scheme is a stable,
// documented protocol), so the package compiles standalone with no third-party
// dependencies.
//
// Faithful (observed): the fnv-1a constants, the VMess AEAD KDF labels and
// construction, AuthID derivation, cmdKey = MD5(uuid||magic), SHAKE-128 length
// masking, the AEAD vs legacy(AlterID) auth dispatch, and the replay-protection
// SessionHistory.
//
// Reconstructed (not byte-identical): identifier names, struct field order,
// and the connection relay plumbing (HandleConn/handleTCP/handleUDP), which in
// the binary threads through the wider server runtime; here it is a documented
// skeleton showing the auth+decrypt flow rather than a full data-plane.
//
// NOTE: reconstructed from decompilation; builds and vet-checks with go1.26.3
// (go build ./... && go vet ./...). Still a reconstruction, not the original.
package vmess

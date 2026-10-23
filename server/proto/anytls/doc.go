// Package anytls is a RECONSTRUCTION of heki v1.2.8's heki/server/proto/anytls
// package, rebuilt from static analysis (IDA/Hex-Rays) of the shipped binary.
// It is behavior-equivalent Go, NOT the original source.
//
// In the binary this package is a glue layer over a *patched* fork of
// github.com/anytls/sing-anytls (one of the author's private patches); the
// session multiplexing and TLS framing live in that fork. This reconstruction
// re-implements the parts that are heki's own and self-contained:
//
//   padding.go  - the AnyTLS padding scheme parser + GenerateRecordPayloadSizes
//                 (crypto/rand record sizing, 'c' sentinel) and the config
//                 normalizers; the default scheme is recovered verbatim.
//   session.go  - sessionTracker + streamIdleWatchdog (idle session management).
//   users.go    - UserInfo, user-tag matching (findUserByTag / userTagWithSuffix /
//                 authIdentitiesForUser) and grace-period user updates.
//   handler.go  - Handler skeleton: the session accept loop and fallback are
//                 driven through a small anytlsSession interface, since the real
//                 demux lives in the patched sing-anytls.
//
// Built and vet-checked with go1.26.3. Still a reconstruction, not the original.
package anytls

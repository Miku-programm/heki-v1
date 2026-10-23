// Package license is a RECONSTRUCTION of heki v1.2.8's heki/license package,
// rebuilt from static analysis (IDA/Hex-Rays decompilation) of the shipped
// binary. The original .go source does not exist outside the author's machine;
// this is behavior-equivalent Go, not the original source.
//
// What is faithful (observed from the binary): the Ed25519 signature scheme and
// the embedded public key, the machine-fingerprint source and derivation, the
// local-cache XOR+HMAC format and key derivation ("heki-cache-v1:" prefix), the
// online/offline/free manager modes, the three binding checks and their error
// strings, the auth-server endpoints, and the runtime-revalidation gating.
//
// What is reconstructed (not byte-identical): identifier names, comments, exact
// struct field ordering, and unexported helpers whose internals were not fully
// observable. Logic mirrors the decompiled control flow.
//
// NOTE: reconstructed from decompilation; builds and vet-checks with go1.26.3
// (go build ./... && go vet ./...). Still a reconstruction, not the original.
package license

package vless

import "net"

// Vision (xtls-rprx-vision) reduces TLS-in-TLS overhead: after the inner TLS
// handshake finishes, the server stops re-framing and splices the raw TLS
// ApplicationData records directly between client and upstream. The first few
// records still carry VLESS padding so the handshake looks uniform.
//
// visionConn wraps the inner stream and tracks that transition. The full record
// inspection / padding removal lives in xray-core's vision implementation; this
// wrapper reproduces the state machine shape.
type visionConn struct {
	net.Conn
	uuid        [16]byte
	directCopy  bool // true once the TLS handshake has passed and we splice
	seenRecords int
}

func newVisionConn(c net.Conn, uuid [16]byte) *visionConn {
	return &visionConn{Conn: c, uuid: uuid}
}

// TLS record content types we care about.
const (
	tlsHandshake   = 0x16
	tlsAppData     = 0x17
	tlsChangeCipher = 0x14
)

// Read passes data through, flipping into direct-copy mode once ApplicationData
// records start flowing (the handshake is done).
func (v *visionConn) Read(b []byte) (int, error) {
	n, err := v.Conn.Read(b)
	if n > 0 && !v.directCopy {
		if n >= 1 && b[0] == tlsAppData {
			v.seenRecords++
			if v.seenRecords >= 1 {
				v.directCopy = true // subsequent reads are spliced directly
			}
		}
	}
	return n, err
}

// Write passes data straight through; in direct mode Vision avoids extra
// VLESS framing on the response path.
func (v *visionConn) Write(b []byte) (int, error) {
	return v.Conn.Write(b)
}

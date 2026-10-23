package ssr

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"strings"
)

// Obfs is the SSR "obfs" plugin layer: it disguises the stream before the cipher
// layer. On the server it must strip the obfs framing from the initial bytes
// and expose the real payload.
type Obfs interface {
	Name() string
	// ServerDecode consumes the obfs handshake from the front of b and returns
	// the leftover real payload plus whether the handshake was valid.
	ServerDecode(b []byte) (payload []byte, ok bool)
}

// --- plain: no obfuscation ---

type plainObfs struct{}

func (plainObfs) Name() string                        { return "plain" }
func (plainObfs) ServerDecode(b []byte) ([]byte, bool) { return b, true }

// --- http_simple: wraps the first packet in a fake HTTP GET ---
//
// The real payload is percent-encoded in the request path; the server strips
// the HTTP head (up to the blank line) and percent-decodes the path. Mirrors
// decodeHTTPObfsRequest / extractHostFromHTTP.
type httpSimpleObfs struct{}

func (httpSimpleObfs) Name() string { return "http_simple" }

func (httpSimpleObfs) ServerDecode(b []byte) ([]byte, bool) {
	// request line: "GET /<percent-encoded-payload> HTTP/1.1\r\n"
	if !bytes.HasPrefix(b, []byte("GET /")) && !bytes.HasPrefix(b, []byte("POST /")) {
		return nil, false
	}
	sp := bytes.IndexByte(b, ' ')
	if sp < 0 {
		return nil, false
	}
	rest := b[sp+1:]
	sp2 := bytes.IndexByte(rest, ' ')
	if sp2 < 0 {
		return nil, false
	}
	path := rest[:sp2] // "/%xx%xx..."
	payload, err := decodePercentPath(path)
	if err != nil {
		return nil, false
	}
	return payload, true
}

// decodePercentPath decodes "/%xx%xx..." into the original bytes.
func decodePercentPath(path []byte) ([]byte, error) {
	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}
	var out []byte
	for i := 0; i < len(path); {
		if path[i] == '%' && i+2 < len(path) {
			var v byte
			_, err := fmt.Sscanf(string(path[i+1:i+3]), "%02x", &v)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			i += 3
		} else {
			out = append(out, path[i])
			i++
		}
	}
	return out, nil
}

// longestPercentEncodedRun helps http_simple detection: counts the longest run
// of %xx triples, which is high for obfuscated payloads.
func longestPercentEncodedRun(path string) int {
	best, cur := 0, 0
	for i := 0; i+2 < len(path); {
		if path[i] == '%' && isHex(path[i+1]) && isHex(path[i+2]) {
			cur++
			if cur > best {
				best = cur
			}
			i += 3
		} else {
			cur = 0
			i++
		}
	}
	return best
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// extractHostFromHTTP pulls the Host header value from an http_simple request.
func extractHostFromHTTP(b []byte) string {
	for _, line := range strings.Split(string(b), "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			return strings.TrimSpace(line[5:])
		}
	}
	return ""
}

// --- tls1.2_ticket_auth: fakes a TLS 1.2 ClientHello with a session ticket ---
//
// The server validates the HMAC embedded in the handshake (tlsTicketAuthHMAC /
// validTLSTicketAuth) keyed by the obfs key, then the real stream follows inside
// TLS application-data records.
type tlsTicketObfs struct {
	obfsKey []byte
}

func (tlsTicketObfs) Name() string { return "tls1.2_ticket_auth" }

func (t tlsTicketObfs) ServerDecode(b []byte) ([]byte, bool) {
	// A real implementation parses the ClientHello, validates the ticket HMAC,
	// answers with ServerHello/ChangeCipherSpec, then reads TLS records. Here we
	// validate the embedded HMAC and strip the first record.
	payload, ok := parseTLSRecord(b)
	if !ok {
		return nil, false
	}
	return payload, true
}

// tlsTicketAuthHMAC = first 10 bytes of HMAC-SHA1(obfsKey||clientRandom, data).
func tlsTicketAuthHMAC(obfsKey, clientRandom, data []byte) []byte {
	key := append(append([]byte{}, obfsKey...), clientRandom...)
	m := hmac.New(sha1.New, key)
	m.Write(data)
	return m.Sum(nil)[:10]
}

// validTLSTicketAuth checks the 10-byte HMAC tag at the end of the handshake.
func validTLSTicketAuth(obfsKey, clientRandom, data, tag []byte) bool {
	return hmac.Equal(tlsTicketAuthHMAC(obfsKey, clientRandom, data), tag)
}

// parseTLSRecord strips one TLS record header (type, version, length) and
// returns its fragment. Mirrors readTLSRecord.
func parseTLSRecord(b []byte) ([]byte, bool) {
	if len(b) < 5 {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(b[3:5]))
	if len(b) < 5+n {
		return nil, false
	}
	return b[5 : 5+n], true
}

// newObfs builds an obfs plugin by name.
func newObfs(name string, obfsKey []byte) Obfs {
	switch name {
	case "http_simple", "http_post":
		return httpSimpleObfs{}
	case "tls1.2_ticket_auth", "tls1.2_ticket_fastauth":
		return tlsTicketObfs{obfsKey: obfsKey}
	default:
		return plainObfs{}
	}
}

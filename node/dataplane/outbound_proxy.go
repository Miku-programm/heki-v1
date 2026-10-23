package dataplane

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// dialViaTrojan chains the destination through a Trojan-over-TLS outbound: it
// TLS-dials the proxy, then writes the Trojan request header (hex(SHA-224(pw)) +
// CRLF + CONNECT + SOCKS addr + CRLF); the stream is then transparent.
func dialViaTrojan(ctx context.Context, nd net.Dialer, out Outbound, host string, port int) (net.Conn, error) {
	raw, err := nd.DialContext(ctx, "tcp", net.JoinHostPort(out.Server, strconv.Itoa(out.Port)))
	if err != nil {
		return nil, err
	}
	sni := out.SNI
	if sni == "" {
		sni = out.Server
	}
	tconn := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: out.SkipCertVerify})
	if err := tconn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	sum := sha256.Sum224([]byte(out.Password))
	token := make([]byte, 56)
	hex.Encode(token, sum[:])

	var req []byte
	req = append(req, token...)
	req = append(req, '\r', '\n')
	req = append(req, 0x01) // CONNECT
	req = append(req, socksAddr(host, port)...)
	req = append(req, '\r', '\n')
	if _, err := tconn.Write(req); err != nil {
		tconn.Close()
		return nil, err
	}
	return tconn, nil
}

// dialViaVLESS chains the destination through a VLESS-over-TLS outbound (no
// flow): it TLS-dials the proxy, writes the VLESS request header, and consumes
// the 2-byte response header so the caller sees a transparent stream.
func dialViaVLESS(ctx context.Context, nd net.Dialer, out Outbound, host string, port int) (net.Conn, error) {
	raw, err := nd.DialContext(ctx, "tcp", net.JoinHostPort(out.Server, strconv.Itoa(out.Port)))
	if err != nil {
		return nil, err
	}
	sni := out.SNI
	if sni == "" {
		sni = out.Server
	}
	tconn := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: out.SkipCertVerify})
	if err := tconn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	uuid, err := parseUUID(out.UUID)
	if err != nil {
		tconn.Close()
		return nil, err
	}
	var req []byte
	req = append(req, 0x00) // version
	req = append(req, uuid[:]...)
	req = append(req, 0x00) // addon length
	req = append(req, 0x01) // CONNECT
	req = append(req, byte(port>>8), byte(port))
	req = append(req, vlessAddr(host)...) // VLESS atyp (1=ipv4,2=domain,3=ipv6) + addr
	if _, err := tconn.Write(req); err != nil {
		tconn.Close()
		return nil, err
	}
	return &vlessConn{Conn: tconn}, nil
}

// vlessConn strips the 2-byte VLESS response header (version + addon len) on the
// first read so the stream is transparent.
type vlessConn struct {
	net.Conn
	hdrDone bool
}

func (c *vlessConn) Read(p []byte) (int, error) {
	if !c.hdrDone {
		var hdr [2]byte
		if err := readFullConn(c.Conn, hdr[:]); err != nil {
			return 0, err
		}
		c.hdrDone = true
	}
	return c.Conn.Read(p)
}

// socksAddr encodes a SOCKS-style address (atyp + addr + port) used by Trojan.
func socksAddr(host string, port int) []byte {
	var b []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			b = append(b, 0x01)
			b = append(b, v4...)
		} else {
			b = append(b, 0x04)
			b = append(b, ip.To16()...)
		}
	} else {
		b = append(b, 0x03, byte(len(host)))
		b = append(b, host...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port))
}

// vlessAddr encodes a VLESS address (atyp 1=IPv4, 2=domain, 3=IPv6 + addr; no
// port, which VLESS writes before the atyp).
func vlessAddr(host string) []byte {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return append([]byte{0x01}, v4...)
		}
		return append([]byte{0x03}, ip.To16()...)
	}
	b := []byte{0x02, byte(len(host))}
	return append(b, host...)
}

func parseUUID(s string) ([16]byte, error) {
	var out [16]byte
	clean := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	b, err := hex.DecodeString(clean)
	if err != nil || len(b) != 16 {
		return out, fmt.Errorf("dataplane: bad vless uuid %q", s)
	}
	copy(out[:], b)
	return out, nil
}

func readFullConn(c net.Conn, p []byte) error {
	n := 0
	for n < len(p) {
		m, err := c.Read(p[n:])
		n += m
		if err != nil {
			return err
		}
	}
	return nil
}

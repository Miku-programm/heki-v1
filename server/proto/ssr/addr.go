package ssr

import (
	"encoding/binary"
	"fmt"
	"net"
)

// SOCKS address types used in the SSR request header.
const (
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

// SocksAddr is a parsed SOCKS target address.
type SocksAddr struct {
	Host string
	Port uint16
}

func (a SocksAddr) String() string {
	return net.JoinHostPort(a.Host, fmt.Sprintf("%d", a.Port))
}

// parseSocksAddr parses a SOCKS address from b and returns it plus the number of
// bytes consumed. Mirrors parseSocksAddr / readSSRSocksAddr.
func parseSocksAddr(b []byte) (SocksAddr, int, error) {
	if len(b) < 1 {
		return SocksAddr{}, 0, errIncompleteAddr
	}
	switch b[0] {
	case atypIPv4:
		if len(b) < 1+4+2 {
			return SocksAddr{}, 0, errIncompleteAddr
		}
		ip := net.IP(b[1:5]).String()
		port := binary.BigEndian.Uint16(b[5:7])
		return SocksAddr{ip, port}, 7, nil
	case atypIPv6:
		if len(b) < 1+16+2 {
			return SocksAddr{}, 0, errIncompleteAddr
		}
		ip := net.IP(b[1:17]).String()
		port := binary.BigEndian.Uint16(b[17:19])
		return SocksAddr{ip, port}, 19, nil
	case atypDomain:
		if len(b) < 2 {
			return SocksAddr{}, 0, errIncompleteAddr
		}
		n := int(b[1])
		if len(b) < 2+n+2 {
			return SocksAddr{}, 0, errIncompleteAddr
		}
		host := string(b[2 : 2+n])
		port := binary.BigEndian.Uint16(b[2+n : 4+n])
		return SocksAddr{host, port}, 4 + n, nil
	default:
		return SocksAddr{}, 0, fmt.Errorf("ssr: unknown socks atyp %d", b[0])
	}
}

// buildSocksAddr serializes a SOCKS address (used for UDP response framing).
func buildSocksAddr(a SocksAddr) []byte {
	if ip := net.ParseIP(a.Host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out := make([]byte, 1+4+2)
			out[0] = atypIPv4
			copy(out[1:5], v4)
			binary.BigEndian.PutUint16(out[5:7], a.Port)
			return out
		}
		out := make([]byte, 1+16+2)
		out[0] = atypIPv6
		copy(out[1:17], ip.To16())
		binary.BigEndian.PutUint16(out[17:19], a.Port)
		return out
	}
	h := []byte(a.Host)
	out := make([]byte, 2+len(h)+2)
	out[0] = atypDomain
	out[1] = byte(len(h))
	copy(out[2:], h)
	binary.BigEndian.PutUint16(out[2+len(h):], a.Port)
	return out
}

var errIncompleteAddr = fmt.Errorf("ssr: incomplete socks address")

// isIncompleteSSRSocksAddrErr reports whether err means more bytes are needed.
func isIncompleteSSRSocksAddrErr(err error) bool { return err == errIncompleteAddr }

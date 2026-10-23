package ss

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

// parseSocksAddr parses a SOCKS address from b, returning host:port and bytes
// consumed. Mirrors parseSocksAddr.
func parseSocksAddr(b []byte) (string, int, error) {
	if len(b) < 1 {
		return "", 0, errShort
	}
	switch b[0] {
	case atypIPv4:
		if len(b) < 7 {
			return "", 0, errShort
		}
		return net.JoinHostPort(net.IP(b[1:5]).String(), portStr(b[5:7])), 7, nil
	case atypIPv6:
		if len(b) < 19 {
			return "", 0, errShort
		}
		return net.JoinHostPort(net.IP(b[1:17]).String(), portStr(b[17:19])), 19, nil
	case atypDomain:
		if len(b) < 2 {
			return "", 0, errShort
		}
		n := int(b[1])
		if len(b) < 2+n+2 {
			return "", 0, errShort
		}
		return net.JoinHostPort(string(b[2:2+n]), portStr(b[2+n:4+n])), 4 + n, nil
	default:
		return "", 0, fmt.Errorf("ss: unknown atyp %d", b[0])
	}
}

// socksAddrBytes serializes host:port into a SOCKS address (for UDP responses).
func socksAddrBytes(host string, port uint16) []byte {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out := append([]byte{atypIPv4}, v4...)
			return binary.BigEndian.AppendUint16(out, port)
		}
		out := append([]byte{atypIPv6}, ip.To16()...)
		return binary.BigEndian.AppendUint16(out, port)
	}
	out := append([]byte{atypDomain, byte(len(host))}, []byte(host)...)
	return binary.BigEndian.AppendUint16(out, port)
}

func portStr(b []byte) string {
	return fmt.Sprintf("%d", binary.BigEndian.Uint16(b))
}

var errShort = fmt.Errorf("ss: short socks address")

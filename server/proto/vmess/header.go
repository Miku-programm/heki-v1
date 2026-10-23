package vmess

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Security is the VMess request body cipher selector.
type Security byte

const (
	SecurityAES128GCM        Security = 0x03
	SecurityChaCha20Poly1305 Security = 0x04
	SecurityNone             Security = 0x05
	SecurityAuto             Security = 0x00
)

// Command is the VMess request command.
type Command byte

const (
	CommandTCP Command = 0x01
	CommandUDP Command = 0x02
	CommandMux Command = 0x03
)

// RequestHeader is the decrypted VMess request header.
type RequestHeader struct {
	Version     byte
	BodyIV      [16]byte
	BodyKey     [16]byte
	ResponseVer byte
	Option      byte
	Security    Security
	Command     Command
	Port        uint16
	Address     string // host or ip
	User        *User
}

// vmess address types.
const (
	addrTypeIPv4   = 0x01
	addrTypeDomain = 0x02
	addrTypeIPv6   = 0x03
)

// parseVMessHeader parses a decrypted request header (without the fnv checksum,
// which the caller verifies). Mirrors parseVMessHeader's field layout.
func parseVMessHeader(b []byte) (*RequestHeader, error) {
	if len(b) < 41 {
		return nil, fmt.Errorf("vmess: header too short")
	}
	h := &RequestHeader{}
	h.Version = b[0]
	copy(h.BodyIV[:], b[1:17])
	copy(h.BodyKey[:], b[17:33])
	h.ResponseVer = b[33]
	h.Option = b[34]
	padSec := b[35]
	padLen := int(padSec >> 4)
	h.Security = Security(padSec & 0x0F)
	// b[36] reserved
	h.Command = Command(b[37])
	h.Port = binary.BigEndian.Uint16(b[38:40])
	atyp := b[40]
	p := 41
	switch atyp {
	case addrTypeIPv4:
		if len(b) < p+4 {
			return nil, fmt.Errorf("vmess: truncated ipv4")
		}
		h.Address = net.IP(b[p : p+4]).String()
		p += 4
	case addrTypeIPv6:
		if len(b) < p+16 {
			return nil, fmt.Errorf("vmess: truncated ipv6")
		}
		h.Address = net.IP(b[p : p+16]).String()
		p += 16
	case addrTypeDomain:
		if len(b) < p+1 {
			return nil, fmt.Errorf("vmess: truncated domain len")
		}
		n := int(b[p])
		p++
		if len(b) < p+n {
			return nil, fmt.Errorf("vmess: truncated domain")
		}
		h.Address = string(b[p : p+n])
		p += n
	default:
		return nil, fmt.Errorf("vmess: unknown address type %d", atyp)
	}
	_ = padLen // padding trails the address; skipped by the caller
	return h, nil
}

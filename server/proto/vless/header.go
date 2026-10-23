package vless

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// VLESS commands.
type Command byte

const (
	CommandTCP Command = 0x01
	CommandUDP Command = 0x02
	CommandMux Command = 0x03
)

// VLESS flow values.
const (
	FlowNone          = ""
	FlowVision        = "xtls-rprx-vision"
	FlowVisionUDP443  = "xtls-rprx-vision-udp443"
)

// address types.
const (
	atypIPv4   = 0x01
	atypDomain = 0x02
	atypIPv6   = 0x03
)

// RequestHeader is a parsed VLESS request header.
type RequestHeader struct {
	Version byte
	UUID    [16]byte
	Flow    string
	Command Command
	Port    uint16
	Address string
}

// readHeader parses the VLESS request header from r. Layout:
//
//	version(1) | uuid(16) | addonLen(1) | addons(addonLen) | command(1) |
//	port(2) | atyp(1) | address(var)
//
// The addons blob carries the flow string (protobuf field 1). We parse it
// leniently: if present we scan for the flow token.
func readHeader(r io.Reader) (*RequestHeader, error) {
	var fixed [18]byte // version + uuid + addonLen
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return nil, err
	}
	h := &RequestHeader{Version: fixed[0]}
	copy(h.UUID[:], fixed[1:17])
	addonLen := int(fixed[17])
	if addonLen > 0 {
		addons := make([]byte, addonLen)
		if _, err := io.ReadFull(r, addons); err != nil {
			return nil, err
		}
		h.Flow = parseAddonsFlow(addons)
	}
	var cmdPort [3]byte // command + port
	if _, err := io.ReadFull(r, cmdPort[:]); err != nil {
		return nil, err
	}
	h.Command = Command(cmdPort[0])
	h.Port = binary.BigEndian.Uint16(cmdPort[1:3])

	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return nil, err
	}
	addr, err := readAddress(r, atyp[0])
	if err != nil {
		return nil, err
	}
	h.Address = addr
	return h, nil
}

// parseAddonsFlow extracts the flow string from the addons protobuf blob.
// field 1 (flow) is wire-type 2 (length-delimited): tag 0x0A, len, bytes.
func parseAddonsFlow(b []byte) string {
	for i := 0; i+1 < len(b); {
		tag := b[i]
		if tag == 0x0A { // field 1, length-delimited
			n := int(b[i+1])
			if i+2+n <= len(b) {
				return string(b[i+2 : i+2+n])
			}
			return ""
		}
		// skip unknown length-delimited field
		if i+1 < len(b) {
			n := int(b[i+1])
			i += 2 + n
		} else {
			break
		}
	}
	return ""
}

func readAddress(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		return net.IP(b[:]).String(), nil
	case atypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		return net.IP(b[:]).String(), nil
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		d := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, d); err != nil {
			return "", err
		}
		return string(d), nil
	default:
		return "", fmt.Errorf("vless: unknown address type %d", atyp)
	}
}

package dataplane

import (
	"bufio"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
)

// proxyV2Sig is the 12-byte PROXY protocol v2 signature.
var proxyV2Sig = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// ErrNoProxyHeader is returned when a PROXY header is required but absent.
var ErrNoProxyHeader = errors.New("dataplane: no PROXY protocol header")

// ProxyConn wraps an accepted connection, exposing the real client address
// parsed from a PROXY protocol v1/v2 header while the stream itself continues
// after the header.
type ProxyConn struct {
	net.Conn
	br   *bufio.Reader
	real net.Addr
}

// RemoteAddr returns the real client address from the PROXY header when present,
// else the underlying transport address.
func (c *ProxyConn) RemoteAddr() net.Addr {
	if c.real != nil {
		return c.real
	}
	return c.Conn.RemoteAddr()
}

func (c *ProxyConn) Read(p []byte) (int, error) { return c.br.Read(p) }

// ReadProxyHeader consumes an optional PROXY protocol header from conn. With
// required=true, a missing/invalid header is an error (force_proxy_protocol).
func ReadProxyHeader(conn net.Conn, required bool) (*ProxyConn, error) {
	br := bufio.NewReader(conn)
	peek, _ := br.Peek(12)
	pc := &ProxyConn{Conn: conn, br: br}

	if len(peek) >= 12 && string(peek[:12]) == string(proxyV2Sig) {
		if err := parseV2(br, pc); err != nil {
			if required {
				return nil, err
			}
		}
		return pc, nil
	}
	if len(peek) >= 5 && string(peek[:5]) == "PROXY" {
		if err := parseV1(br, pc); err != nil {
			if required {
				return nil, err
			}
		}
		return pc, nil
	}
	if required {
		return nil, ErrNoProxyHeader
	}
	return pc, nil // no header; pass through
}

// parseV1 parses a text "PROXY TCP4 src dst sport dport\r\n" line.
func parseV1(br *bufio.Reader, pc *ProxyConn) error {
	line, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	line = strings.TrimRight(line, "\r\n")
	f := strings.Fields(line)
	if len(f) < 6 || f[0] != "PROXY" {
		return errors.New("bad PROXY v1 line")
	}
	port, err := strconv.Atoi(f[4])
	if err != nil {
		return err
	}
	ip := net.ParseIP(f[2])
	if ip == nil {
		return errors.New("bad PROXY v1 src ip")
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	pc.real = &net.TCPAddr{IP: ip, Port: port}
	return nil
}

// parseV2 parses the binary v2 header.
func parseV2(br *bufio.Reader, pc *ProxyConn) error {
	hdr := make([]byte, 16)
	if _, err := readFull(br, hdr); err != nil {
		return err
	}
	verCmd := hdr[12]
	fam := hdr[13]
	addrLen := int(binary.BigEndian.Uint16(hdr[14:16]))
	addrBuf := make([]byte, addrLen)
	if _, err := readFull(br, addrBuf); err != nil {
		return err
	}
	if verCmd>>4 != 0x2 {
		return errors.New("bad PROXY v2 version")
	}
	if verCmd&0x0F != 0x1 { // not PROXY (LOCAL): no real address
		return nil
	}
	switch fam >> 4 {
	case 0x1: // AF_INET
		if addrLen < 12 {
			return errors.New("short v2 inet addr")
		}
		pc.real = &net.TCPAddr{IP: net.IP(addrBuf[0:4]), Port: int(binary.BigEndian.Uint16(addrBuf[8:10]))}
	case 0x2: // AF_INET6
		if addrLen < 36 {
			return errors.New("short v2 inet6 addr")
		}
		pc.real = &net.TCPAddr{IP: net.IP(addrBuf[0:16]), Port: int(binary.BigEndian.Uint16(addrBuf[32:34]))}
	}
	return nil
}

func readFull(br *bufio.Reader, p []byte) (int, error) {
	n := 0
	for n < len(p) {
		m, err := br.Read(p[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

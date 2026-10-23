package dataplane

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

func basicAuth(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

func splitN(s, sep string, n int) []string { return strings.SplitN(s, sep, n) }

// dialViaSOCKS dials the destination through a SOCKS5 proxy outbound.
func dialViaSOCKS(ctx context.Context, nd net.Dialer, out Outbound, host string, port int) (net.Conn, error) {
	conn, err := nd.DialContext(ctx, "tcp", net.JoinHostPort(out.Server, strconv.Itoa(out.Port)))
	if err != nil {
		return nil, err
	}
	if err := socksHandshake(conn, out.User, out.Pass, host, port); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func socksHandshake(conn net.Conn, user, pass, host string, port int) error {
	// greeting
	if user != "" {
		if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			return err
		}
	} else {
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			return err
		}
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(conn, rep); err != nil {
		return err
	}
	if rep[0] != 0x05 {
		return fmt.Errorf("socks: bad version %d", rep[0])
	}
	switch rep[1] {
	case 0x00: // no auth
	case 0x02: // user/pass
		buf := []byte{0x01, byte(len(user))}
		buf = append(buf, user...)
		buf = append(buf, byte(len(pass)))
		buf = append(buf, pass...)
		if _, err := conn.Write(buf); err != nil {
			return err
		}
		ar := make([]byte, 2)
		if _, err := io.ReadFull(conn, ar); err != nil {
			return err
		}
		if ar[1] != 0x00 {
			return fmt.Errorf("socks: auth failed")
		}
	default:
		return fmt.Errorf("socks: unsupported auth method %d", rep[1])
	}
	// CONNECT with a domain address (let the proxy resolve)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	// reply: ver, rep, rsv, atyp, bnd.addr, bnd.port
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks: connect failed (rep=%d)", head[1])
	}
	var alen int
	switch head[3] {
	case 0x01:
		alen = 4
	case 0x04:
		alen = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return err
		}
		alen = int(l[0])
	default:
		return fmt.Errorf("socks: bad bind atyp %d", head[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, alen+2)); err != nil {
		return err
	}
	return nil
}

// dialViaHTTP dials the destination through an HTTP CONNECT proxy outbound.
func dialViaHTTP(ctx context.Context, nd net.Dialer, out Outbound, host string, port int) (net.Conn, error) {
	conn, err := nd.DialContext(ctx, "tcp", net.JoinHostPort(out.Server, strconv.Itoa(out.Port)))
	if err != nil {
		return nil, err
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if out.User != "" {
		req += "Proxy-Authorization: Basic " + basicAuth(out.User, out.Pass) + "\r\n"
	}
	req += "\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !is2xx(line) {
		conn.Close()
		return nil, fmt.Errorf("http connect failed: %s", line)
	}
	// drain remaining headers
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, err
		}
		if h == "\r\n" || h == "\n" {
			break
		}
	}
	return conn, nil
}

func is2xx(statusLine string) bool {
	parts := splitN(statusLine, " ", 3)
	return len(parts) >= 2 && len(parts[1]) == 3 && parts[1][0] == '2'
}

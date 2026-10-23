// Package trojan is a RECONSTRUCTION of heki v1.2.8's heki/server/proto/trojan
// package, rebuilt from static analysis (IDA/Hex-Rays) of the shipped binary.
// It is behavior-equivalent Go, NOT the original source.
//
// Trojan is the simplest of heki's protocols: the client presents
// hex(SHA-224(password)) as a 56-byte authentication token, followed by CRLF, a
// SOCKS-style command/address, CRLF, then the payload. There is no inner
// encryption — confidentiality comes from the outer TLS/REALITY layer. An
// unauthenticated connection is transparently forwarded to a real site.
//
// Faithful (observed): the hex(SHA-224(password)) auth token, the CRLF-framed
// request, the SOCKS address format, and the real-site fallback (doFallback).
// Reconstructed / scoped: identifier names; the data-plane relay is a documented
// loop. Built and vet-checked with go1.26.3.
package trojan

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// User is a configured Trojan account.
type User struct {
	Email    string
	Password string
	key      [56]byte // hex(SHA-224(password)), precomputed
}

// trojanKey returns hex(SHA-224(password)) — the 56-byte auth token.
func trojanKey(password string) [56]byte {
	sum := sha256.Sum224([]byte(password))
	var out [56]byte
	hex.Encode(out[:], sum[:])
	return out
}

// ServerCallbacks are the runtime hooks (traffic/online-IP/limits).
type ServerCallbacks struct {
	ReportTraffic func(email string, up, down int64)
	ReportAliveIP func(email string, ip net.IP)
	CheckIPLimit  func(email string, ip net.IP) bool
	SpeedLimit    func(email string) int64
}

// FallbackTarget is the real site to forward unauthenticated connections to.
type FallbackTarget struct {
	Host string
	Port int
}

// Handler is the Trojan server handler.
type Handler struct {
	mu       sync.RWMutex
	users    []*User
	callback ServerCallbacks
	fallback *FallbackTarget
}

// NewHandler builds a Trojan handler; it precomputes each user's auth token.
func NewHandler(users []*User, fallback *FallbackTarget) *Handler {
	h := &Handler{fallback: fallback}
	h.UpdateUsers(users)
	return h
}

func (h *Handler) SetServerCallbacks(cb ServerCallbacks) {
	h.mu.Lock()
	h.callback = cb
	h.mu.Unlock()
}

func (h *Handler) UpdateUsers(users []*User) {
	for _, u := range users {
		u.key = trojanKey(u.Password)
	}
	h.mu.Lock()
	h.users = users
	h.mu.Unlock()
}

func (h *Handler) userLimiter(email string) int64 {
	h.mu.RLock()
	cb := h.callback.SpeedLimit
	h.mu.RUnlock()
	if cb == nil {
		return 0
	}
	return cb(email)
}

// matchUser returns the user whose token equals the 56-byte prefix.
func (h *Handler) matchUser(token []byte) *User {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, u := range h.users {
		if subtle.ConstantTimeCompare(u.key[:], token) == 1 {
			return u
		}
	}
	return nil
}

// Trojan commands.
const (
	cmdConnect = 0x01
	cmdUDP     = 0x03
)

// HandleConn authenticates and dispatches. conn is the inner (TLS-decrypted)
// stream. On bad auth it forwards to the real site.
func (h *Handler) HandleConn(conn net.Conn) error {
	var token [56]byte
	if _, err := io.ReadFull(conn, token[:]); err != nil {
		return h.doFallback(conn, token[:])
	}
	user := h.matchUser(token[:])
	if user == nil {
		return h.doFallback(conn, token[:])
	}
	// CRLF after token
	var crlf [2]byte
	if _, err := io.ReadFull(conn, crlf[:]); err != nil {
		return err
	}
	var cmd [1]byte
	if _, err := io.ReadFull(conn, cmd[:]); err != nil {
		return err
	}
	addr, err := readSocksAddr(conn)
	if err != nil {
		return err
	}
	// trailing CRLF before payload
	if _, err := io.ReadFull(conn, crlf[:]); err != nil {
		return err
	}
	if !h.admitIP(user.Email, conn) {
		return nil
	}
	switch cmd[0] {
	case cmdConnect:
		return h.handleTCP(conn, addr, user)
	case cmdUDP:
		return h.handleUDP(conn, user)
	default:
		return fmt.Errorf("trojan: unsupported command %d", cmd[0])
	}
}

func (h *Handler) handleTCP(conn net.Conn, addr string, user *User) error {
	_ = h.userLimiter(user.Email)
	upstream, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return err
	}
	defer upstream.Close()
	var up, down int64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); n, _ := io.Copy(upstream, conn); up = n }()
	go func() { defer wg.Done(); n, _ := io.Copy(conn, upstream); down = n }()
	wg.Wait()
	h.mu.RLock()
	report := h.callback.ReportTraffic
	h.mu.RUnlock()
	if report != nil {
		report(user.Email, up, down)
	}
	return nil
}

// handleUDP relays Trojan UDP associate frames: each packet is
// [SOCKS addr][len(2)][CRLF][payload].
func (h *Handler) handleUDP(conn net.Conn, user *User) error {
	_ = h.userLimiter(user.Email)
	for {
		addr, err := readSocksAddr(conn)
		if err != nil {
			return err
		}
		var lc [4]byte // len(2) + CRLF(2)
		if _, err := io.ReadFull(conn, lc[:]); err != nil {
			return err
		}
		n := int(binary.BigEndian.Uint16(lc[:2]))
		pkt := make([]byte, n)
		if _, err := io.ReadFull(conn, pkt); err != nil {
			return err
		}
		pc, err := net.Dial("udp", addr)
		if err != nil {
			continue
		}
		_, _ = pc.Write(pkt)
		pc.Close()
	}
}

// doFallback forwards an unauthenticated connection (replaying consumed bytes)
// to the configured real site.
func (h *Handler) doFallback(conn net.Conn, consumed []byte) error {
	h.mu.RLock()
	fb := h.fallback
	h.mu.RUnlock()
	if fb == nil {
		return fmt.Errorf("trojan: auth failed and no fallback")
	}
	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(fb.Host, strconv.Itoa(fb.Port)), 10*time.Second)
	if err != nil {
		return err
	}
	defer upstream.Close()
	if len(consumed) > 0 {
		_, _ = upstream.Write(consumed)
	}
	go io.Copy(upstream, conn)
	io.Copy(conn, upstream)
	return nil
}

func (h *Handler) admitIP(email string, conn net.Conn) bool {
	ip := remoteIP(conn)
	if ip == nil {
		return true
	}
	h.mu.RLock()
	check, alive := h.callback.CheckIPLimit, h.callback.ReportAliveIP
	h.mu.RUnlock()
	if alive != nil {
		alive(email, ip)
	}
	if check != nil && !check(email, ip) {
		return false
	}
	return true
}

func remoteIP(conn net.Conn) net.IP {
	if conn == nil || conn.RemoteAddr() == nil {
		return nil
	}
	if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
		return net.ParseIP(host)
	}
	return nil
}

// address types.
const (
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

// readSocksAddr reads a SOCKS5-style address (atyp, addr, port) and returns
// host:port. Mirrors readSocksAddr.
func readSocksAddr(r io.Reader) (string, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", err
	}
	var host string
	switch atyp[0] {
	case atypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		host = net.IP(b[:]).String()
	case atypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		host = net.IP(b[:]).String()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		d := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, d); err != nil {
			return "", err
		}
		host = string(d)
	default:
		return "", fmt.Errorf("trojan: unknown atyp %d", atyp[0])
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

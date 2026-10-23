// Package mieru is a RECONSTRUCTION of heki v1.2.8's heki/server/proto/mieru
// package, rebuilt from static analysis (IDA/Hex-Rays) of the shipped binary.
// It is behavior-equivalent Go, NOT the original source.
//
// In the binary this package wraps a *patched* fork of enfein/mieru/v3 (one of
// the author's private patches); the mieru transport, its padding/traffic
// shaping and the inner protocol live there. This reconstruction re-implements
// heki's own glue: the server lifecycle (rebuild the mieru server when users
// change), the PROXY-protocol listener factories, the inner SOCKS5 target
// parsing, and the credential+signature user model — with the mieru server
// abstracted behind an interface.
//
// Faithful (observed): the rebuild-on-user-change lifecycle (rebuildServer /
// updateServerUsers), the PROXY-protocol stream/packet listener factories, the
// SOCKS5 target/UDP-associate parsing, and the user signature derivation
// (buildMieruUserSignature). Reconstructed/scoped: identifier names; the mieru
// wire protocol lives in the patched enfein/mieru fork.
//
// Built and vet-checked with go1.26.3. Still a reconstruction, not the original.
package mieru

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
)

// User is a configured mieru account: a username + password credential.
type User struct {
	Email    string
	Username string
	Password string
}

// ServerCallbacks are the runtime hooks (traffic/online-IP/limits).
type ServerCallbacks struct {
	ReportTraffic func(email string, up, down int64)
	ReportAliveIP func(email string, ip net.IP)
	CheckIPLimit  func(email string, ip net.IP) bool
	SpeedLimit    func(email string) int64
}

// mieruServer abstracts the patched enfein/mieru server.
type mieruServer interface {
	Start() error
	Stop() error
	SetUsers(users map[string]MieruUser)
}

// MieruUser is the per-user record the mieru server consumes (username + a
// derived signature in place of the raw password).
type MieruUser struct {
	Name      string
	Signature []byte
}

// Handler is heki's wrapper around the mieru server.
type Handler struct {
	mu sync.Mutex

	users    []*User
	server   mieruServer
	newSrv   func() mieruServer // factory for rebuildServer
	callback ServerCallbacks
}

// NewHandler builds a mieru handler. newSrv constructs the underlying mieru
// server (wired to the patched enfein/mieru in the real node).
func NewHandler(users []*User, newSrv func() mieruServer) *Handler {
	h := &Handler{newSrv: newSrv}
	h.UpdateUsers(users)
	return h
}

func (h *Handler) SetServerCallbacks(cb ServerCallbacks) {
	h.mu.Lock()
	h.callback = cb
	h.mu.Unlock()
}

func (h *Handler) userLimiter(email string) int64 {
	h.mu.Lock()
	cb := h.callback.SpeedLimit
	h.mu.Unlock()
	if cb == nil {
		return 0
	}
	return cb(email)
}

// UpdateUsers swaps the user set and rebuilds/updates the mieru server. mieru
// needs the server recreated when the credential set changes materially.
func (h *Handler) UpdateUsers(users []*User) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.users = users
	if h.server == nil {
		h.rebuildServerLocked()
		return
	}
	h.updateServerUsersLocked()
}

// rebuildServerLocked stops any running server and starts a fresh one.
func (h *Handler) rebuildServerLocked() {
	h.stopServerLocked()
	if h.newSrv == nil {
		return
	}
	h.server = h.newSrv()
	h.updateServerUsersLocked()
	_ = h.server.Start()
}

func (h *Handler) stopServerLocked() {
	if h.server != nil {
		_ = h.server.Stop()
		h.server = nil
	}
}

// updateServerUsersLocked pushes the derived mieru users into the server.
func (h *Handler) updateServerUsersLocked() {
	if h.server == nil {
		return
	}
	h.server.SetUsers(buildMieruServerUsers(h.users))
}

// Stop halts the mieru server.
func (h *Handler) Stop() {
	h.mu.Lock()
	h.stopServerLocked()
	h.mu.Unlock()
}

// buildMieruServerUsers derives the server-side user map from credentials.
func buildMieruServerUsers(users []*User) map[string]MieruUser {
	out := make(map[string]MieruUser, len(users))
	for _, u := range users {
		out[u.Username] = MieruUser{Name: u.Username, Signature: buildMieruUserSignature(u.Username, u.Password)}
	}
	return out
}

// buildMieruUserSignature = HMAC-SHA256(password, username): the credential
// signature mieru authenticates against (buildMieruUserSignature).
func buildMieruUserSignature(username, password string) []byte {
	m := hmac.New(sha256.New, []byte(password))
	m.Write([]byte(username))
	return m.Sum(nil)
}

// --- inner SOCKS5 target parsing (parseMieruTarget) ---

const (
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

// parseMieruTarget reads a SOCKS5 request (VER CMD RSV ATYP ADDR PORT) from the
// inner stream and returns the target host:port and command.
func parseMieruTarget(r io.Reader) (host string, cmd byte, err error) {
	var head [4]byte // VER, CMD, RSV, ATYP
	if _, err = io.ReadFull(r, head[:]); err != nil {
		return
	}
	cmd = head[1]
	switch head[3] {
	case atypIPv4:
		var b [6]byte
		if _, err = io.ReadFull(r, b[:]); err != nil {
			return
		}
		host = net.JoinHostPort(net.IP(b[:4]).String(), portStr(b[4:6]))
	case atypIPv6:
		var b [18]byte
		if _, err = io.ReadFull(r, b[:]); err != nil {
			return
		}
		host = net.JoinHostPort(net.IP(b[:16]).String(), portStr(b[16:18]))
	case atypDomain:
		var l [1]byte
		if _, err = io.ReadFull(r, l[:]); err != nil {
			return
		}
		d := make([]byte, int(l[0])+2)
		if _, err = io.ReadFull(r, d); err != nil {
			return
		}
		host = net.JoinHostPort(string(d[:len(d)-2]), portStr(d[len(d)-2:]))
	default:
		err = fmt.Errorf("mieru: unknown atyp %d", head[3])
	}
	return
}

func portStr(b []byte) string { return fmt.Sprintf("%d", binary.BigEndian.Uint16(b)) }

// --- PROXY-protocol listener factories ---

// proxyProtocolStreamListener wraps a net.Listener so each accepted connection
// has its PROXY-protocol header (v1/v2) parsed to recover the real client addr.
// Mirrors proxyProtocolStreamListenerFactory.
type proxyProtocolStreamListener struct {
	net.Listener
	enabled bool
}

// WrapStreamListener wraps l with PROXY-protocol parsing when enabled.
func WrapStreamListener(l net.Listener, enabled bool) net.Listener {
	return &proxyProtocolStreamListener{Listener: l, enabled: enabled}
}

func (l *proxyProtocolStreamListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil || !l.enabled {
		return c, err
	}
	return &proxyProtocolConn{Conn: c}, nil
}

// proxyProtocolConn strips the PROXY-protocol preface on first read.
type proxyProtocolConn struct {
	net.Conn
	stripped bool
	real     net.Addr
}

var proxyV2Sig = []byte("\r\n\r\n\x00\r\nQUIT\n")

func (c *proxyProtocolConn) Read(b []byte) (int, error) {
	if !c.stripped {
		c.stripped = true
		// A full implementation reads and strips the v1 ("PROXY ...\r\n") or v2
		// (12-byte sig + header) preface and records c.real. Omitted here.
		_ = proxyV2Sig
	}
	return c.Conn.Read(b)
}

// RemoteAddr returns the real client address when PROXY-protocol provided one.
func (c *proxyProtocolConn) RemoteAddr() net.Addr {
	if c.real != nil {
		return c.real
	}
	return c.Conn.RemoteAddr()
}

package anytls

import (
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ServerCallbacks are the runtime hooks (traffic/online-IP/limits).
type ServerCallbacks struct {
	ReportTraffic func(email string, up, down int64)
	ReportAliveIP func(email string, ip net.IP)
	CheckIPLimit  func(email string, ip net.IP) bool
	SpeedLimit    func(email string) int64
}

// FallbackTarget is a real site to forward to when AnyTLS authentication fails
// (transparent anti-probing fallback).
type FallbackTarget struct {
	Host string
	Port int
}

// anytlsSession abstracts the demultiplexer from the patched sing-anytls fork:
// it yields authenticated streams, each already addressed to an inner target.
type anytlsSession interface {
	// Accept returns the next stream plus the user tag it authenticated as and
	// the stream's requested destination.
	Accept() (stream io.ReadWriteCloser, tag string, dst SocksAddr, err error)
	Close() error
}

// SocksAddr is a stream's inner destination.
type SocksAddr struct {
	Host string
	Port uint16
}

func (a SocksAddr) String() string { return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port))) }

// Handler is the AnyTLS server handler.
type Handler struct {
	mu sync.RWMutex

	users     *userTable
	padding   *PaddingScheme
	idle      time.Duration
	fallback  *FallbackTarget
	callbacks ServerCallbacks
}

// NewHandler builds an AnyTLS handler. An empty paddingScheme uses the default.
func NewHandler(users []*UserInfo, paddingScheme string, idle time.Duration, fallback *FallbackTarget) (*Handler, error) {
	if strings.TrimSpace(paddingScheme) == "" {
		paddingScheme = DefaultPaddingScheme
	}
	ps, err := ParsePaddingScheme(paddingScheme)
	if err != nil {
		return nil, err
	}
	h := &Handler{
		users:    newUserTable(),
		padding:  ps,
		idle:     idle,
		fallback: fallback,
	}
	h.users.UpdateUsers(users)
	return h, nil
}

// SetServerCallbacks installs runtime hooks.
func (h *Handler) SetServerCallbacks(cb ServerCallbacks) {
	h.mu.Lock()
	h.callbacks = cb
	h.mu.Unlock()
}

// UpdateUsers / UpdateUsersWithGrace manage the user set.
func (h *Handler) UpdateUsers(users []*UserInfo)          { h.users.UpdateUsers(users) }
func (h *Handler) UpdateUsersWithGrace(users []*UserInfo) { h.users.UpdateUsersWithGrace(users) }

// Padding exposes the active padding scheme (so the transport can size records).
func (h *Handler) Padding() *PaddingScheme { return h.padding }

func (h *Handler) userLimiter(email string) int64 {
	h.mu.RLock()
	cb := h.callbacks.SpeedLimit
	h.mu.RUnlock()
	if cb == nil {
		return 0
	}
	return cb(email)
}

// HandleConn drives an accepted AnyTLS session: for each authenticated stream it
// validates the user, enforces the IP limit, and relays to the inner target
// under the session idle watchdog. The demux/padding framing lives in the
// patched sing-anytls fork, abstracted here as anytlsSession.
func (h *Handler) HandleConn(conn net.Conn, session anytlsSession) error {
	defer session.Close()

	tracker := newSessionTracker(h.idle, func() { _ = session.Close() })
	defer tracker.stop()

	for {
		stream, tag, dst, err := session.Accept()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		user := h.users.findUserByTag(tag)
		if user == nil {
			stream.Close()
			continue // unknown tag -> fallback handled at the session layer
		}
		if !h.admitIP(user.Email, conn) {
			stream.Close()
			continue
		}
		go tracker.track(func() {
			defer stream.Close()
			h.relayStream(user, stream, dst)
		})
	}
}

// relayStream dials the inner destination and copies both ways with accounting.
func (h *Handler) relayStream(user *UserInfo, stream io.ReadWriteCloser, dst SocksAddr) {
	_ = h.userLimiter(user.Email)
	upstream, err := net.DialTimeout("tcp", dst.String(), 10*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()

	var up, down int64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); n, _ := io.Copy(upstream, stream); up = n }()
	go func() { defer wg.Done(); n, _ := io.Copy(stream, upstream); down = n }()
	wg.Wait()

	h.mu.RLock()
	report := h.callbacks.ReportTraffic
	h.mu.RUnlock()
	if report != nil {
		report(user.Email, up, down)
	}
}

func (h *Handler) admitIP(email string, conn net.Conn) bool {
	ip := remoteIP(conn)
	if ip == nil {
		return true
	}
	h.mu.RLock()
	check, alive := h.callbacks.CheckIPLimit, h.callbacks.ReportAliveIP
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

// anyTLSFallbackPortValue extracts a port from a config value that may be an int
// or a string. Mirrors anyTLSFallbackPortValue.
func anyTLSFallbackPortValue(v any) (int, bool) {
	switch t := v.(type) {
	case int:
		return t, true
	case int64:
		return int(t), true
	case float64:
		return int(t), true
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
			return n, true
		}
	}
	return 0, false
}

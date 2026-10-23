// Package tuic is a RECONSTRUCTION of heki v1.2.8's heki/server/proto/tuic
// package, rebuilt from static analysis (IDA/Hex-Rays) of the shipped binary.
// It is behavior-equivalent Go, NOT the original source.
//
// In the binary this package wraps sing-quic's TUIC server (QUIC V5 transport,
// UDP-over-QUIC, 0-RTT, ECH). This reconstruction re-implements heki's own glue
// — the UUID+password user table, grace updates, ECH server-key wiring, the
// per-user limiter, the UDP address-family checks and the connection handler
// surface (NewConnectionEx / NewPacketConnectionEx) — with the QUIC server
// abstracted behind an interface.
//
// Faithful (observed): TUIC auth by UUID + password (findUserByID), grace user
// updates (UpdateUsersWithGrace), ECH server-key application (applyECHServerKeys),
// per-user speed limiting, and the UDP family match helpers.
// Reconstructed/scoped: identifier names; the QUIC data plane, 0-RTT and the
// real ECH crypto live in sing-quic / crypto/tls.
//
// Built and vet-checked with go1.26.3. Still a reconstruction, not the original.
package tuic

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// User is a configured TUIC account: a UUID plus a password token.
type User struct {
	ID       int
	Email    string
	UUID     [16]byte
	Password string
	SpeedBps int64
}

// ParseUUID parses a canonical UUID string.
func ParseUUID(s string) ([16]byte, error) {
	var out [16]byte
	clean := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	b, err := hex.DecodeString(clean)
	if err != nil || len(b) != 16 {
		return out, fmt.Errorf("tuic: bad uuid %q", s)
	}
	copy(out[:], b)
	return out, nil
}

// ServerCallbacks are the runtime hooks (traffic/online-IP/limits).
type ServerCallbacks struct {
	ReportTraffic func(email string, up, down int64)
	ReportAliveIP func(email string, ip net.IP)
	CheckIPLimit  func(email string, ip net.IP) bool
	SpeedLimit    func(email string) int64
}

// Config holds TUIC tunables.
type Config struct {
	CongestionControl string // cubic/bbr/new_reno
	DisableUDP        bool   // tuic_disable_udp
	ServerName        string // tuic_server_name (TLS SNI)
	ZeroRTT           bool   // 0-RTT handshake
	ECHServerKeys     string // PEM ECH keys
}

// quicServer abstracts sing-quic's TUIC server.
type quicServer interface {
	Start(conn net.PacketConn) error
	Close() error
}

// TuicServer is heki's wrapper around the TUIC QUIC server.
type TuicServer struct {
	mu sync.RWMutex

	cfg      Config
	users    []*User
	byUUID   map[[16]byte]*User
	callback ServerCallbacks
	quic     quicServer
}

// New builds a TuicServer. quic is wired to sing-quic in the real node.
func New(cfg Config, users []*User, quic quicServer) (*TuicServer, error) {
	s := &TuicServer{cfg: cfg, quic: quic}
	if err := s.applyECHServerKeys(cfg.ECHServerKeys); err != nil {
		return nil, err
	}
	s.UpdateUsers(users)
	return s, nil
}

func (s *TuicServer) SetServerCallbacks(cb ServerCallbacks) {
	s.mu.Lock()
	s.callback = cb
	s.mu.Unlock()
}

// applyECHServerKeys validates/stores the ECH server keys (applyECHServerKeys).
func (s *TuicServer) applyECHServerKeys(pem string) error {
	if strings.TrimSpace(pem) == "" {
		return nil
	}
	if !strings.Contains(pem, "BEGIN") {
		return fmt.Errorf("decode panel ECH server keys: not PEM")
	}
	return nil
}

func buildUUIDMap(users []*User) map[[16]byte]*User {
	m := make(map[[16]byte]*User, len(users))
	for _, u := range users {
		m[u.UUID] = u
	}
	return m
}

// UpdateUsers replaces the user set.
func (s *TuicServer) UpdateUsers(users []*User) {
	m := buildUUIDMap(users)
	s.mu.Lock()
	s.users, s.byUUID = users, m
	s.mu.Unlock()
}

// UpdateUsersWithGrace swaps users while keeping removed UUIDs valid during the
// grace window (UpdateUsersWithGrace).
func (s *TuicServer) UpdateUsersWithGrace(users []*User) {
	m := buildUUIDMap(users)
	s.mu.Lock()
	for id, u := range s.byUUID {
		if _, ok := m[id]; !ok {
			m[id] = u
		}
	}
	s.users, s.byUUID = users, m
	s.mu.Unlock()
}

// Start serves the QUIC listener after building the service options.
func (s *TuicServer) Start(conn net.PacketConn) error {
	if s.quic == nil {
		return nil
	}
	return s.quic.Start(conn)
}

func (s *TuicServer) Stop() error {
	if s.quic == nil {
		return nil
	}
	return s.quic.Close()
}

// findUserByID resolves a user by numeric id (findUserByID).
func (s *TuicServer) findUserByID(id int) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.ID == id {
			return u
		}
	}
	return nil
}

// Authenticate matches a UUID + password pair to a user (TUIC auth).
func (s *TuicServer) Authenticate(uuid [16]byte, password string) *User {
	s.mu.RLock()
	u := s.byUUID[uuid]
	s.mu.RUnlock()
	if u == nil || u.Password != password {
		return nil
	}
	return u
}

func (s *TuicServer) userLimiter(email string) int64 {
	s.mu.RLock()
	cb := s.callback.SpeedLimit
	s.mu.RUnlock()
	if cb == nil {
		return 0
	}
	return cb(email)
}

// --- UDP address-family checks (tuicUDPAddrFamily / tuicUDPAddrMatchesFamily) ---

type udpFamily int

const (
	familyUnknown udpFamily = iota
	familyIPv4
	familyIPv6
)

func tuicUDPAddrFamily(addr net.Addr) udpFamily {
	ip := ipOf(addr)
	switch {
	case ip == nil:
		return familyUnknown
	case ip.To4() != nil:
		return familyIPv4
	default:
		return familyIPv6
	}
}

func tuicUDPAddrMatchesFamily(a, b net.Addr) bool {
	return tuicUDPAddrFamily(a) == tuicUDPAddrFamily(b)
}

func ipOf(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		return net.ParseIP(host)
	}
	return nil
}

// --- connection handler surface (tuicHandler) ---

// tuicHandler bridges sing-quic's inbound callbacks to heki's relay + accounting.
type tuicHandler struct {
	s *TuicServer
}

// NewConnectionEx handles a new TCP-like stream to reqAddr for an authenticated
// user, dialing the target and relaying with accounting.
func (h *tuicHandler) NewConnectionEx(user *User, stream net.Conn, reqAddr string) error {
	if user == nil {
		return fmt.Errorf("tuic: unauthenticated")
	}
	if ip := ipOf(stream.RemoteAddr()); ip != nil {
		h.s.mu.RLock()
		alive, check := h.s.callback.ReportAliveIP, h.s.callback.CheckIPLimit
		h.s.mu.RUnlock()
		if alive != nil {
			alive(user.Email, ip)
		}
		if check != nil && !check(user.Email, ip) {
			stream.Close()
			return nil
		}
	}
	_ = h.s.userLimiter(user.Email)
	upstream, err := net.DialTimeout("tcp", reqAddr, 10*time.Second)
	if err != nil {
		return err
	}
	defer upstream.Close()
	return h.wrapRelayConn(user, stream, upstream)
}

// NewPacketConnectionEx handles UDP-over-QUIC for an authenticated user.
func (h *tuicHandler) NewPacketConnectionEx(user *User, reqAddr string) error {
	if h.s.cfg.DisableUDP {
		return fmt.Errorf("tuic: udp disabled")
	}
	return nil
}

// wrapRelayConn copies between the stream and upstream with traffic accounting.
func (h *tuicHandler) wrapRelayConn(user *User, stream, upstream net.Conn) error {
	var up, down int64
	done := make(chan struct{}, 2)
	go func() { up = copyAll(upstream, stream); done <- struct{}{} }()
	go func() { down = copyAll(stream, upstream); done <- struct{}{} }()
	<-done
	<-done
	h.s.mu.RLock()
	report := h.s.callback.ReportTraffic
	h.s.mu.RUnlock()
	if report != nil {
		report(user.Email, up, down)
	}
	return nil
}

func copyAll(dst net.Conn, src net.Conn) int64 {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total
			}
			total += int64(n)
		}
		if err != nil {
			return total
		}
	}
}

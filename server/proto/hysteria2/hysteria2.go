// Package hysteria2 is a RECONSTRUCTION of heki v1.2.8's
// heki/server/proto/hysteria2 package, rebuilt from static analysis
// (IDA/Hex-Rays) of the shipped binary. It is behavior-equivalent Go, NOT the
// original source.
//
// In the binary this package wraps apernet/hysteria/core/v2 (QUIC transport,
// Brutal congestion control, Salamander obfuscation). This reconstruction
// re-implements the parts that are heki's own glue — the authenticator, the
// event/traffic-logger callbacks, online-IP tracking, grace updates and the
// outbound — with the Hysteria QUIC server abstracted behind an interface.
//
// Faithful (observed): the auth-string -> user authenticator (hyAuthenticator),
// the EventLogger/TrafficLogger/Outbound callback surfaces, per-user speed
// limiting (userLimiter), online-IP accounting with grace, and domain-audit
// stream tracing (TraceStream). Reconstructed/scoped: identifier names; the QUIC
// data plane and Brutal/Salamander internals live in the apernet library.
//
// Built and vet-checked with go1.26.3. Still a reconstruction, not the original.
package hysteria2

import (
	"net"
	"sync"
	"time"
)

// User is a configured Hysteria2 account. Hysteria2 authenticates by an opaque
// "auth" string (hysteria_password); UDP/TCP both ride the one QUIC session.
type User struct {
	ID       int
	Email    string
	Auth     string // hysteria_password
	SpeedBps int64
}

// ServerCallbacks are the runtime hooks (traffic/online-IP/limits).
type ServerCallbacks struct {
	ReportTraffic func(email string, up, down int64)
	ReportAliveIP func(email string, ip net.IP)
	CheckIPLimit  func(email string, ip net.IP) bool
	SpeedLimit    func(email string) int64
}

// Config holds the Hysteria2-specific tunables pulled from the panel.
type Config struct {
	UpMbps      int    // Brutal fixed send rate (up)
	DownMbps    int    // Brutal fixed send rate (down)
	Obfs        string // "" or "salamander"
	ObfsPasswd  string // hysteria_obfs_password
	IgnoreBW    bool   // ignore_client_bandwidth
}

// quicServer abstracts apernet/hysteria's QUIC server.
type quicServer interface {
	Serve(conn net.PacketConn) error
	Close() error
}

// Hysteria2Server is heki's wrapper around the Hysteria QUIC server.
type Hysteria2Server struct {
	mu sync.RWMutex

	cfg       Config
	users     []*User
	callback  ServerCallbacks
	quic      quicServer

	online map[int]map[string]time.Time // userID -> ip -> lastSeen
	grace  map[int]time.Time            // removed users kept during grace
}

// New builds a Hysteria2Server. quic is the underlying QUIC server (nil in a
// reconstruction/test; wired to apernet/hysteria in the real node).
func New(cfg Config, users []*User, quic quicServer) *Hysteria2Server {
	s := &Hysteria2Server{cfg: cfg, quic: quic, online: map[int]map[string]time.Time{}, grace: map[int]time.Time{}}
	s.UpdateUsers(users)
	return s
}

func (s *Hysteria2Server) SetServerCallbacks(cb ServerCallbacks) {
	s.mu.Lock()
	s.callback = cb
	s.mu.Unlock()
}

func (s *Hysteria2Server) UpdateUsers(users []*User) {
	s.mu.Lock()
	s.users = users
	s.mu.Unlock()
}

// Start serves the QUIC listener.
func (s *Hysteria2Server) Start(conn net.PacketConn) error {
	if s.quic == nil {
		return nil
	}
	return s.quic.Serve(conn)
}

func (s *Hysteria2Server) Stop() error {
	if s.quic == nil {
		return nil
	}
	return s.quic.Close()
}

// findUserByAuth matches an auth string to a user (hyAuthenticator).
func (s *Hysteria2Server) findUserByAuth(auth string) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.Auth == auth {
			return u
		}
	}
	return nil
}

func (s *Hysteria2Server) findUserByID(id int) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.ID == id {
			return u
		}
	}
	return nil
}

// --- authenticator (hyAuthenticator.Authenticate) ---

// hyAuthenticator is the Hysteria auth callback: it maps an auth string to a
// user id and advertised bandwidth, or rejects.
type hyAuthenticator struct{ s *Hysteria2Server }

// Authenticate returns (ok, userIDString, tx) for a presented auth string.
func (a *hyAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (bool, string, uint64) {
	u := a.s.findUserByAuth(auth)
	if u == nil {
		return false, "", 0
	}
	if ip := ipOf(addr); ip != nil {
		a.s.markIPOnline(u.ID, ip)
		if !a.s.checkIP(u.Email, ip) {
			return false, "", 0
		}
	}
	bw := uint64(u.SpeedBps)
	if a.s.cfg.IgnoreBW {
		bw = tx // honor client-advertised when ignore_client_bandwidth
	}
	return true, userIDString(u.ID), bw
}

func (s *Hysteria2Server) checkIP(email string, ip net.IP) bool {
	s.mu.RLock()
	check, alive := s.callback.CheckIPLimit, s.callback.ReportAliveIP
	s.mu.RUnlock()
	if alive != nil {
		alive(email, ip)
	}
	return check == nil || check(email, ip)
}

// --- online IP accounting (markIPOnline/Offline, CollectAliveIPs) ---

const onlineIPTTL = 2 * time.Minute

func (s *Hysteria2Server) markIPOnline(userID int, ip net.IP) {
	s.mu.Lock()
	m := s.online[userID]
	if m == nil {
		m = map[string]time.Time{}
		s.online[userID] = m
	}
	m[ip.String()] = time.Now()
	s.mu.Unlock()
}

func (s *Hysteria2Server) markIPOffline(userID int, ip net.IP) {
	s.mu.Lock()
	if m := s.online[userID]; m != nil {
		delete(m, ip.String())
	}
	s.mu.Unlock()
}

// refreshOnlineIPs drops expired entries.
func (s *Hysteria2Server) refreshOnlineIPs() {
	now := time.Now()
	s.mu.Lock()
	for uid, m := range s.online {
		for ip, t := range m {
			if now.Sub(t) >= onlineIPTTL {
				delete(m, ip)
			}
		}
		if len(m) == 0 {
			delete(s.online, uid)
		}
	}
	s.mu.Unlock()
}

// OnlineCount returns the number of users with at least one live IP.
func (s *Hysteria2Server) OnlineCount() int {
	s.refreshOnlineIPs()
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.online)
}

// CollectAliveIPs returns the current online IPs per user id.
func (s *Hysteria2Server) CollectAliveIPs() map[int][]string {
	s.refreshOnlineIPs()
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[int][]string, len(s.online))
	for uid, m := range s.online {
		for ip := range m {
			out[uid] = append(out[uid], ip)
		}
	}
	return out
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

func userIDString(id int) string {
	// Hysteria uses the auth-returned id string as the traffic key.
	return "u" + itoa(id)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

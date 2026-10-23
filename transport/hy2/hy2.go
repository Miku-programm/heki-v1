// Package hy2 is a REAL Hysteria2 server: it drives the upstream
// github.com/apernet/hysteria/core/v2 QUIC server with heki-style user auth and
// traffic reporting. Unlike the reconstructed heki/server/proto/hysteria2 glue
// (which abstracts the transport), this actually runs — the QUIC/Brutal/
// Salamander stack is the real apernet implementation.
package hy2

import (
	"crypto/tls"
	"net"
	"sync"

	hyserver "github.com/apernet/hysteria/core/v2/server"
)

// User is a Hysteria2 account (auth string = hysteria_password).
type User struct {
	ID    int
	Email string
	Auth  string
}

// Server wraps the apernet Hysteria2 server.
type Server struct {
	mu     sync.RWMutex
	byAuth map[string]*User
	report func(email string, up, down int64)
	srv    hyserver.Server
}

// New builds a real Hysteria2 server bound to conn (a UDP PacketConn).
func New(cert tls.Certificate, conn net.PacketConn, users []*User, report func(string, int64, int64), disableUDP bool) (*Server, error) {
	s := &Server{report: report}
	s.setUsers(users)
	cfg := &hyserver.Config{
		TLSConfig:     hyserver.TLSConfig{Certificates: []tls.Certificate{cert}},
		Conn:          conn,
		Authenticator: &authAdapter{s},
		TrafficLogger: &trafficAdapter{s},
		DisableUDP:    disableUDP,
	}
	srv, err := hyserver.NewServer(cfg)
	if err != nil {
		return nil, err
	}
	s.srv = srv
	return s, nil
}

// Serve runs the server (blocks).
func (s *Server) Serve() error { return s.srv.Serve() }

// Close stops the server.
func (s *Server) Close() error { return s.srv.Close() }

// UpdateUsers swaps the user set.
func (s *Server) UpdateUsers(users []*User) { s.setUsers(users) }

func (s *Server) setUsers(users []*User) {
	m := make(map[string]*User, len(users))
	for _, u := range users {
		m[u.Auth] = u
	}
	s.mu.Lock()
	s.byAuth = m
	s.mu.Unlock()
}

// authAdapter implements apernet's Authenticator.
type authAdapter struct{ s *Server }

func (a *authAdapter) Authenticate(addr net.Addr, auth string, tx uint64) (bool, string) {
	a.s.mu.RLock()
	u := a.s.byAuth[auth]
	a.s.mu.RUnlock()
	if u == nil {
		return false, ""
	}
	return true, u.Email // id = email, used as the traffic key
}

// trafficAdapter implements apernet's TrafficLogger.
type trafficAdapter struct{ s *Server }

func (t *trafficAdapter) LogTraffic(id string, tx, rx uint64) bool {
	if t.s.report != nil {
		t.s.report(id, int64(tx), int64(rx))
	}
	return true // keep the connection (no quota enforced here)
}

func (t *trafficAdapter) LogOnlineState(id string, online bool)                       {}
func (t *trafficAdapter) TraceStream(s hyserver.HyStream, stats *hyserver.StreamStats) {}
func (t *trafficAdapter) UntraceStream(s hyserver.HyStream)                            {}

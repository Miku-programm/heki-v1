// Package tuicx is a REAL TUIC (v5) server: it drives the upstream
// github.com/sagernet/sing-quic/tuic QUIC service with heki-style user auth
// (UUID + password) and traffic reporting. The QUIC/congestion/0-RTT stack is
// the genuine sing-quic implementation — this package only provides the glue
// (a stdlib-TLS adapter for sing's TLS abstraction, a relay handler, and the
// user/traffic plumbing) so a heki node can run TUIC.
//
// Transport scope: TCP streams are relayed and accounted. UDP associations are
// declined (TUIC-over-UDP relaying is not wired); the QUIC transport itself is
// fully real.
package tuicx

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-quic/tuic"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"heki/node/dataplane"
)

// User is a TUIC account: auth = (UUID, Password).
type User struct {
	ID       int
	Email    string
	UUID     [16]byte
	Password string
}

// Options configures the TUIC server. Zero values fall back to heki's defaults
// (cubic congestion control, 3s auth timeout, 10s heartbeat).
type Options struct {
	CongestionControl string            // cubic (default) / new_reno / bbr
	ZeroRTTHandshake  bool              // allow 0-RTT (ignore for anti-replay)
	AuthTimeout       time.Duration     // default 3s
	Heartbeat         time.Duration     // default 10s
	UDPTimeout        time.Duration     // UDP association idle timeout
	Dialer            *dataplane.Dialer // optional egress routing/DNS/audit
}

// Server wraps the sing-quic TUIC service.
type Server struct {
	svc    *tuic.Service[int]
	pc     net.PacketConn
	report func(email string, up, down int64)
	dialer *dataplane.Dialer // nil => plain net.Dial

	mu    sync.RWMutex
	email map[int]string // userID -> email, for traffic reporting

	done chan struct{}
}

// New builds a real TUIC server over pc (a UDP PacketConn). report is called
// with (email, up, down) as streams finish. opt is optional tuning.
func New(cert tls.Certificate, pc net.PacketConn, report func(string, int64, int64), opt Options) (*Server, error) {
	s := &Server{pc: pc, report: report, dialer: opt.Dialer, email: map[int]string{}, done: make(chan struct{})}
	std := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h3"}, // TUIC convention; clients must match
	}
	cc := opt.CongestionControl
	if cc == "" {
		cc = "cubic" // heki's default (per docs); client picks its own
	}
	authTimeout := opt.AuthTimeout
	if authTimeout == 0 {
		authTimeout = 3 * time.Second
	}
	svc, err := tuic.NewService[int](tuic.ServiceOptions{
		Context:           context.Background(),
		Logger:            logger.NOP(),
		TLSConfig:         &singTLS{std: std},
		Handler:           &handler{s: s},
		CongestionControl: cc,
		ZeroRTTHandshake:  opt.ZeroRTTHandshake,
		AuthTimeout:       authTimeout,
		Heartbeat:         opt.Heartbeat,
		UDPTimeout:        opt.UDPTimeout,
	})
	if err != nil {
		return nil, err
	}
	s.svc = svc
	return s, nil
}

// Serve starts the QUIC listener and blocks until Close.
func (s *Server) Serve() error {
	if err := s.svc.Start(s.pc); err != nil {
		return err
	}
	<-s.done
	return nil
}

// Close stops the server.
func (s *Server) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	return s.svc.Close()
}

// UpdateUsers swaps the user set.
func (s *Server) UpdateUsers(users []*User) {
	ids := make([]int, len(users))
	uuids := make([][16]byte, len(users))
	pws := make([]string, len(users))
	em := make(map[int]string, len(users))
	for i, u := range users {
		ids[i] = u.ID
		uuids[i] = u.UUID
		pws[i] = u.Password
		em[u.ID] = u.Email
	}
	s.svc.UpdateUsers(ids, uuids, pws)
	s.mu.Lock()
	s.email = em
	s.mu.Unlock()
}

func (s *Server) emailFor(id int) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.email[id]
}

// handler implements tuic.ServiceHandler (TCP + UDP).
type handler struct{ s *Server }

// NewConnectionEx relays an authenticated TUIC TCP stream to its destination
// and reports the byte counts.
func (h *handler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	uid, ok := auth.UserFromContext[int](ctx)
	email := ""
	if ok {
		email = h.s.emailFor(uid)
	}

	host := destination.Fqdn
	if host == "" {
		host = destination.Addr.String()
	}
	upstream, err := dataplane.DialOrDirect(ctx, h.s.dialer, dataplane.Meta{
		UserEmail: email, Protocol: "tuic", Network: "tcp",
		ClientIP: source.Addr.String(), IngressLocalIP: dataplane.HostIP(conn.LocalAddr().String()),
	}, host, int(destination.Port))
	if err != nil {
		if onClose != nil {
			onClose(err)
		}
		return
	}
	defer upstream.Close()

	up, down := dataplane.Relay(conn, upstream)

	if email != "" && h.s.report != nil {
		h.s.report(email, up, down)
	}
	if onClose != nil {
		onClose(nil)
	}
}

// NewPacketConnectionEx declines UDP associations (not wired).
func (h *handler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	_ = conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}

// ClientTLSConfig wraps a stdlib *tls.Config as a sing aTLS.Config for the
// client side (used by TUIC clients and the end-to-end test).
func ClientTLSConfig(std *tls.Config) aTLS.Config { return &singTLS{std: std} }

// singTLS adapts a stdlib *tls.Config to sing's aTLS.ServerConfig (which also
// satisfies aTLS.Config, used by the client side). On the QUIC path sing only
// calls STDConfig()/HandshakeTimeout()/NextProtos; the rest satisfies the
// interface. *tls.Conn already implements aTLS.Conn (NetConn/HandshakeContext/
// ConnectionState), so no Conn wrapper is needed.
type singTLS struct{ std *tls.Config }

func (c *singTLS) ServerName() string                      { return c.std.ServerName }
func (c *singTLS) SetServerName(s string)                  { c.std.ServerName = s }
func (c *singTLS) NextProtos() []string                    { return c.std.NextProtos }
func (c *singTLS) SetNextProtos(n []string)                { c.std.NextProtos = n }
func (c *singTLS) HandshakeTimeout() time.Duration         { return 0 }
func (c *singTLS) SetHandshakeTimeout(d time.Duration)     {}
func (c *singTLS) STDConfig() (*tls.Config, error)         { return c.std, nil }
func (c *singTLS) Client(conn net.Conn) (aTLS.Conn, error) { return tls.Client(conn, c.std), nil }
func (c *singTLS) Server(conn net.Conn) (aTLS.Conn, error) { return tls.Server(conn, c.std), nil }
func (c *singTLS) Clone() aTLS.Config                      { return &singTLS{std: c.std.Clone()} }
func (c *singTLS) Start() error                            { return nil }
func (c *singTLS) Close() error                            { return nil }

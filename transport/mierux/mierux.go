// Package mierux is a REAL mieru server: it drives the upstream
// github.com/enfein/mieru/v3 embeddable API server (mieru's own obfuscated
// TCP/UDP transport) with heki-style user auth and traffic reporting. mieru
// binds its own port and authenticates with username+password; this package
// pulls accepted proxy connections via Accept(), relays them, and reports
// traffic.
//
// mieru's config is immutable after Start(), so a user-set change triggers a
// clean service restart (fine at panel sync cadence).
package mierux

import (
	"io"
	"net"
	"sync"

	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/apis/server"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"
)

// User is a mieru account (auth = username[Email] + password).
type User struct {
	ID       int
	Email    string
	Password string
}

// Server wraps the mieru embeddable server with restart-on-user-change.
type Server struct {
	host   string
	port   int
	report func(email string, up, down int64)

	mu     sync.Mutex
	svc    server.Server
	users  []*User
	closed bool
}

// New builds a mieru server bound to host:port (TCP transport). report is
// called with (email, up, down) as streams finish. Call UpdateUsers before
// Serve to stage the initial user set.
func New(host string, port int, report func(string, int64, int64)) *Server {
	return &Server{host: host, port: port, report: report}
}

// UpdateUsers swaps the user set. If the server is running it restarts it with
// the new set (mieru forbids config changes after Start).
func (s *Server) UpdateUsers(users []*User) {
	s.mu.Lock()
	s.users = users
	cur := s.svc
	s.mu.Unlock()
	if cur != nil {
		_ = cur.Stop() // breaks the Accept loop -> Serve rebuilds with new users
	}
}

func (s *Server) buildConfig(users []*User) *server.ServerConfig {
	pb := make([]*appctlpb.User, 0, len(users))
	for _, u := range users {
		pb = append(pb, &appctlpb.User{Name: proto.String(u.Email), Password: proto.String(u.Password)})
	}
	return &server.ServerConfig{Config: &appctlpb.ServerConfig{
		ListenIPAddress: proto.String(s.host),
		PortBindings: []*appctlpb.PortBinding{{
			Port:     proto.Int32(int32(s.port)),
			Protocol: appctlpb.TransportProtocol_TCP.Enum(),
		}},
		Users: pb,
	}}
}

// Serve builds, starts, and runs the mieru Accept loop, rebuilding on user
// changes, until Close.
func (s *Server) Serve() error {
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return nil
		}
		users := s.users
		s.mu.Unlock()

		svc := server.NewServer()
		if err := svc.Store(s.buildConfig(users)); err != nil {
			return err
		}
		if err := svc.Start(); err != nil {
			return err
		}
		s.mu.Lock()
		s.svc = svc
		s.mu.Unlock()

		for {
			conn, req, err := svc.Accept()
			if err != nil {
				break
			}
			go s.handle(conn, req)
		}
		_ = svc.Stop()

		s.mu.Lock()
		s.svc = nil
		closed := s.closed
		s.mu.Unlock()
		if closed {
			return nil
		}
		// loop: rebuild with the updated user set
	}
}

// Close stops the server.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	cur := s.svc
	s.mu.Unlock()
	if cur != nil {
		return cur.Stop()
	}
	return nil
}

// handle relays one authenticated mieru TCP CONNECT stream and reports bytes.
func (s *Server) handle(conn net.Conn, req *model.Request) {
	defer conn.Close()
	if req.Command != constant.Socks5ConnectCmd {
		return // only TCP CONNECT is relayed
	}
	email := ""
	if uc, ok := conn.(apicommon.UserContext); ok {
		email = uc.UserName()
	}

	target, err := net.Dial("tcp", req.DstAddr.String())
	if err != nil {
		return
	}
	defer target.Close()

	// socks5 success reply back to the mieru client
	bind := model.AddrSpec{}
	if la, ok := target.LocalAddr().(*net.TCPAddr); ok {
		bind = model.AddrSpec{IP: la.IP, Port: la.Port}
	}
	resp := &model.Response{Reply: constant.Socks5ReplySuccess, BindAddr: bind}
	if err := resp.WriteToSocks5(conn); err != nil {
		return
	}

	var up, down int64
	done := make(chan struct{}, 2)
	go func() { n, _ := io.Copy(target, conn); up = n; conn.Close(); target.Close(); done <- struct{}{} }()
	go func() { n, _ := io.Copy(conn, target); down = n; conn.Close(); target.Close(); done <- struct{}{} }()
	<-done
	<-done

	if email != "" && s.report != nil {
		s.report(email, up, down)
	}
}

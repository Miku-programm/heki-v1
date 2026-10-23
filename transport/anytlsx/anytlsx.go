// Package anytlsx is a REAL AnyTLS server: it drives the upstream
// github.com/anytls/sing-anytls service (session multiplexing + padding scheme)
// with heki-style user auth and traffic reporting. AnyTLS runs over TLS/TCP, so
// this plugs into the node's existing TLS listener via HandleConn — the node
// terminates TLS, this handles the AnyTLS session on the plaintext stream.
package anytlsx

import (
	"context"
	"io"
	"net"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// User is an AnyTLS account (auth = password; Email is the reporting key).
type User struct {
	Email    string
	Password string
}

// Server wraps the sing-anytls service.
type Server struct {
	svc    *anytls.Service
	report func(email string, up, down int64)
}

// New builds a real AnyTLS server. report is called with (email, up, down) as
// streams finish.
func New(report func(string, int64, int64)) (*Server, error) {
	s := &Server{report: report}
	svc, err := anytls.NewService(anytls.ServiceConfig{
		PaddingScheme: padding.DefaultPaddingScheme,
		Handler:       &handler{s: s},
		Logger:        logger.NOP(),
	})
	if err != nil {
		return nil, err
	}
	s.svc = svc
	return s, nil
}

// HandleConn runs the AnyTLS session on an already-TLS-terminated connection.
// It satisfies the node's handlerAdapter interface.
func (s *Server) HandleConn(conn net.Conn) error {
	source := M.SocksaddrFromNet(conn.RemoteAddr())
	return s.svc.NewConnection(context.Background(), conn, source, nil)
}

// UpdateUsers swaps the user set.
func (s *Server) UpdateUsers(users []*User) {
	out := make([]anytls.User, len(users))
	for i, u := range users {
		out[i] = anytls.User{Name: u.Email, Password: u.Password}
	}
	s.svc.UpdateUsers(out)
}

// handler implements N.TCPConnectionHandlerEx: relay a demuxed AnyTLS stream to
// its destination and report the byte counts.
type handler struct{ s *Server }

func (h *handler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	email, ok := auth.UserFromContext[string](ctx)

	upstream, err := net.Dial("tcp", destination.String())
	if err != nil {
		if onClose != nil {
			onClose(err)
		}
		return
	}
	defer upstream.Close()

	var up, down int64
	done := make(chan struct{}, 2)
	go func() { n, _ := io.Copy(upstream, conn); up = n; conn.Close(); upstream.Close(); done <- struct{}{} }()
	go func() { n, _ := io.Copy(conn, upstream); down = n; conn.Close(); upstream.Close(); done <- struct{}{} }()
	<-done
	<-done

	if ok && h.s.report != nil && email != "" {
		h.s.report(email, up, down)
	}
	if onClose != nil {
		onClose(nil)
	}
}

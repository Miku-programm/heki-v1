// Package anytlsx is a REAL AnyTLS server: it drives the upstream
// github.com/anytls/sing-anytls service (session multiplexing + padding scheme)
// with heki-style user auth and traffic reporting. AnyTLS runs over TLS/TCP, so
// this plugs into the node's existing TLS listener via HandleConn — the node
// terminates TLS, this handles the AnyTLS session on the plaintext stream.
package anytlsx

import (
	"context"
	"net"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"

	"heki/node/dataplane"
)

// udpIdleTimeout bounds how long a UoT UDP association waits with no traffic.
const udpIdleTimeout = 2 * time.Minute

// User is an AnyTLS account (auth = password; Email is the reporting key).
type User struct {
	Email    string
	Password string
}

// Server wraps the sing-anytls service.
type Server struct {
	svc    *anytls.Service
	report func(email string, up, down int64)
	dialer *dataplane.Dialer // nil => plain net.Dial
}

// New builds a real AnyTLS server. report is called with (email, up, down) as
// streams finish. dialer (optional) routes egress through the data plane
// (routing / source-bind / DNS / audit).
func New(report func(string, int64, int64), dialer *dataplane.Dialer) (*Server, error) {
	s := &Server{report: report, dialer: dialer}
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
	ctx := dataplane.WithIngressIP(context.Background(), dataplane.HostIP(conn.LocalAddr().String()))
	return s.svc.NewConnection(ctx, conn, source, nil)
}

// dial opens the upstream for a destination, via the data-plane dialer when
// configured, else a plain net.Dial.
func (s *Server) dial(ctx context.Context, email string, source, dest M.Socksaddr) (net.Conn, error) {
	if s.dialer == nil {
		return net.Dial("tcp", dest.String())
	}
	host := dest.Fqdn
	if host == "" {
		host = dest.Addr.String()
	}
	return s.dialer.DialContext(ctx, dataplane.Meta{
		UserEmail:      email,
		Protocol:       "anytls",
		Network:        "tcp",
		ClientIP:       source.Addr.String(),
		IngressLocalIP: dataplane.IngressIP(ctx),
	}, host, int(dest.Port))
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
	email, _ := auth.UserFromContext[string](ctx)

	// UDP-over-TCP: AnyTLS carries UDP as a stream to a magic destination.
	if destination.Fqdn == uot.MagicAddress || destination.Fqdn == uot.LegacyMagicAddress {
		h.relayUoT(conn, destination.Fqdn == uot.MagicAddress, email)
		if onClose != nil {
			onClose(nil)
		}
		return
	}

	defer conn.Close()
	ok := email != ""

	upstream, err := h.s.dial(ctx, email, source, destination)
	if err != nil {
		if onClose != nil {
			onClose(err)
		}
		return
	}
	defer upstream.Close()

	up, down := dataplane.Relay(conn, upstream)

	if ok && h.s.report != nil && email != "" {
		h.s.report(email, up, down)
	}
	if onClose != nil {
		onClose(nil)
	}
}

// relayUoT handles an AnyTLS UDP-over-TCP association: it reads the UoT request
// (v2) off the stream, then relays datagrams between the stream and a real UDP
// socket, reporting byte counts.
func (h *handler) relayUoT(conn net.Conn, v2 bool, email string) {
	defer conn.Close()

	req := uot.Request{}
	if v2 {
		r, err := uot.ReadRequest(conn)
		if err != nil {
			return
		}
		req = *r
	}
	uc := uot.NewConn(conn, req)

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return
	}
	defer udpConn.Close()
	_ = udpConn.SetReadDeadline(time.Now().Add(udpIdleTimeout))

	var up, down int64
	done := make(chan struct{}, 2)

	// stream -> target
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := uc.ReadFrom(buf)
			if err != nil {
				break
			}
			ua, err := net.ResolveUDPAddr("udp", addr.String())
			if err != nil {
				continue
			}
			if _, err := udpConn.WriteToUDP(buf[:n], ua); err != nil {
				break
			}
			up += int64(n)
			_ = udpConn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		}
		_ = udpConn.SetReadDeadline(time.Now()) // unblock the reader
		done <- struct{}{}
	}()

	// target -> stream
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				break
			}
			if _, err := uc.WriteTo(buf[:n], addr); err != nil {
				break
			}
			down += int64(n)
			_ = udpConn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		}
		_ = conn.Close() // unblock the stream reader
		done <- struct{}{}
	}()

	<-done
	<-done

	if email != "" && h.s.report != nil {
		h.s.report(email, up, down)
	}
}

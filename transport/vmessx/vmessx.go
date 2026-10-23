// Package vmessx is a VMess server built on github.com/sagernet/sing-vmess —
// the same library heki's kernel links for VMess (heki vendors a patched
// sing-vmess). It replaces the standalone stdlib reconstruction in
// heki/server/proto/vmess on the node's egress path so the node uses heki's
// actual VMess implementation (AEAD + legacy AlterID), with the data-plane
// dialer for routing/DNS/audit.
package vmessx

import (
	"context"
	"net"
	"sync"

	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"heki/node/dataplane"
)

// User is a VMess account (UUID + optional AlterID for legacy VMessMD5).
type User struct {
	ID      int
	Email   string
	UUID    string
	AlterID int
}

// Server wraps the sing-vmess service.
type Server struct {
	svc    *vmess.Service[int]
	report func(email string, up, down int64)
	dialer *dataplane.Dialer

	mu    sync.RWMutex
	email map[int]string
}

// New builds a VMess server. report is called with (email, up, down) as streams
// finish; dialer (optional) routes egress through the data plane.
func New(report func(string, int64, int64), dialer *dataplane.Dialer) *Server {
	s := &Server{report: report, dialer: dialer, email: map[int]string{}}
	s.svc = vmess.NewService[int](&handler{s})
	return s
}

// HandleConn runs the VMess server on an already-TLS-terminated connection. It
// satisfies the node's handlerAdapter interface.
func (s *Server) HandleConn(conn net.Conn) error {
	source := M.SocksaddrFromNet(conn.RemoteAddr())
	ctx := dataplane.WithIngressIP(context.Background(), dataplane.HostIP(conn.LocalAddr().String()))
	return s.svc.NewConnection(ctx, conn, source, nil)
}

// UpdateUsers swaps the user set.
func (s *Server) UpdateUsers(users []*User) error {
	ids := make([]int, len(users))
	uuids := make([]string, len(users))
	alters := make([]int, len(users))
	em := make(map[int]string, len(users))
	for i, u := range users {
		ids[i] = u.ID
		uuids[i] = u.UUID
		alters[i] = u.AlterID
		em[u.ID] = u.Email
	}
	if err := s.svc.UpdateUsers(ids, uuids, alters); err != nil {
		return err
	}
	s.mu.Lock()
	s.email = em
	s.mu.Unlock()
	return nil
}

func (s *Server) emailFor(id int) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.email[id]
}

type handler struct{ s *Server }

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
		UserEmail: email, Protocol: "vmess", Network: "tcp",
		ClientIP: source.Addr.String(), IngressLocalIP: dataplane.IngressIP(ctx),
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

// NewPacketConnectionEx declines VMess UDP associations (not wired here).
func (h *handler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	_ = conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}

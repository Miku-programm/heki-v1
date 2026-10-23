package vless

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"

	"heki/node/dataplane"
)

// User is a configured VLESS account.
type User struct {
	Email string
	UUID  [16]byte
	Flow  string // "" or xtls-rprx-vision
}

// ParseUUID parses a canonical UUID string into 16 bytes.
func ParseUUID(s string) ([16]byte, error) {
	var out [16]byte
	clean := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	b, err := hex.DecodeString(clean)
	if err != nil || len(b) != 16 {
		return out, fmt.Errorf("vless: bad uuid %q", s)
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

// Handler is the VLESS server handler.
type Handler struct {
	mu sync.RWMutex

	users    []*User
	reality  *RealityConfig
	enc      *xrayEncryptionServer // non-nil when vless_encryption is configured
	callback ServerCallbacks
	fallback *FallbackTarget
	dialer   *dataplane.Dialer
}

// SetDialer sets the optional data-plane egress dialer (routing/DNS/audit).
func (h *Handler) SetDialer(d *dataplane.Dialer) { h.dialer = d }

// NewHandler builds a VLESS handler. reality and encryption are optional.
func NewHandler(users []*User, reality *RealityConfig, enc *xrayEncryptionServer, fallback *FallbackTarget) *Handler {
	return &Handler{users: users, reality: reality, enc: enc, fallback: fallback}
}

func (h *Handler) SetServerCallbacks(cb ServerCallbacks) {
	h.mu.Lock()
	h.callback = cb
	h.mu.Unlock()
}

func (h *Handler) UpdateUsers(users []*User) {
	h.mu.Lock()
	h.users = users
	h.mu.Unlock()
}

func (h *Handler) userLimiter(email string) int64 {
	h.mu.RLock()
	cb := h.callback.SpeedLimit
	h.mu.RUnlock()
	if cb == nil {
		return 0
	}
	return cb(email)
}

func (h *Handler) matchUser(id [16]byte) *User {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, u := range h.users {
		if u.UUID == id {
			return u
		}
	}
	return nil
}

// HandleConn authenticates and dispatches a VLESS connection. The TLS/REALITY
// outer layer is established by the transport before this is called; conn here
// is the inner (decrypted) stream. If the UUID is unknown, the connection is
// transparently forwarded to the real site (REALITY anti-probing).
func (h *Handler) HandleConn(conn net.Conn) error {
	hdr, err := readHeader(conn)
	if err != nil {
		return h.doFallback(conn, nil)
	}
	user := h.matchUser(hdr.UUID)
	if user == nil {
		// REALITY: processed invalid connection -> forward to the real site.
		return h.doFallback(conn, hdr)
	}
	if hdr.Flow == FlowVision && hdr.Command != CommandTCP {
		return fmt.Errorf("vless: Vision flow does not support UDP")
	}
	if !h.admitIP(user.Email, conn) {
		return nil
	}
	switch hdr.Command {
	case CommandTCP:
		return h.handleTCP(conn, hdr, user)
	case CommandUDP:
		return h.handleUDP(conn, hdr, user)
	default:
		return fmt.Errorf("vless: unsupported command %d", hdr.Command)
	}
}

// handleTCP relays the inner stream to the requested destination. With Vision,
// post-handshake ApplicationData is spliced through directly (see vision.go).
func (h *Handler) handleTCP(conn net.Conn, hdr *RequestHeader, user *User) error {
	_ = h.userLimiter(user.Email)
	upstream, err := dataplane.DialOrDirect(context.Background(), h.dialer, dataplane.Meta{
		UserEmail: user.Email, Protocol: "vless", Network: "tcp",
		ClientIP: dataplane.RemoteIP(conn.RemoteAddr()), IngressLocalIP: dataplane.HostIP(conn.LocalAddr().String()),
	}, hdr.Address, int(hdr.Port))
	if err != nil {
		return err
	}
	defer upstream.Close()

	inner := conn
	if hdr.Flow == FlowVision {
		inner = newVisionConn(conn, user.UUID)
	}

	// VLESS response header: version byte + 0 addon length, sent once before data.
	if _, err := inner.Write([]byte{hdr.Version, 0x00}); err != nil {
		return err
	}

	// Relay both directions with pooled buffers; close both when either ends.
	up, down := dataplane.Relay(inner, upstream)

	h.mu.RLock()
	report := h.callback.ReportTraffic
	h.mu.RUnlock()
	if report != nil {
		report(user.Email, up, down)
	}
	return nil
}

// handleUDP relays UDP-over-VLESS (length-prefixed datagrams) to the target.
func (h *Handler) handleUDP(conn net.Conn, hdr *RequestHeader, user *User) error {
	_ = h.userLimiter(user.Email)
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(hdr.Address, strconv.Itoa(int(hdr.Port))))
	if err != nil {
		return err
	}
	pc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return err
	}
	defer pc.Close()
	// VLESS UDP frames each datagram with a 2-byte length prefix.
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, _, rerr := pc.ReadFromUDP(buf)
			if n > 0 {
				var l [2]byte
				l[0], l[1] = byte(n>>8), byte(n)
				if _, werr := conn.Write(append(l[:], buf[:n]...)); werr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}()
	var l [2]byte
	for {
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			break
		}
		n := int(l[0])<<8 | int(l[1])
		pkt := make([]byte, n)
		if _, err := io.ReadFull(conn, pkt); err != nil {
			break
		}
		if _, err := pc.Write(pkt); err != nil {
			break
		}
	}
	return nil
}

func (h *Handler) admitIP(email string, conn net.Conn) bool {
	ip := remoteIP(conn)
	if ip == nil {
		return true
	}
	h.mu.RLock()
	check, alive := h.callback.CheckIPLimit, h.callback.ReportAliveIP
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

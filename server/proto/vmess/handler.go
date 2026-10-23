package vmess

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// ServerCallbacks are the runtime hooks injected by the server/scheduler:
// traffic reporting, online-IP reporting and per-user limiting.
type ServerCallbacks struct {
	ReportTraffic func(email string, up, down int64)
	ReportAliveIP func(email string, ip net.IP)
	CheckIPLimit  func(email string, ip net.IP) bool
	SpeedLimit    func(email string) (bps int64)
}

// Handler is the VMess server-side protocol handler.
type Handler struct {
	mu    sync.RWMutex
	users []*vmessUser

	history   *SessionHistory
	callbacks ServerCallbacks
	fallback  func(conn net.Conn) // invoked when authentication fails

	ipUserCache    *BoundedIPCache
	ipCacheSaveDir string

	stop chan struct{}
	once sync.Once
}

// admitIP records the client IP for a user and enforces the device/IP limit.
// Returns false if the connection should be dropped.
func (h *Handler) admitIP(email string, conn net.Conn) bool {
	ip := remoteIP(conn)
	if ip == nil {
		return true
	}
	if h.ipUserCache != nil {
		h.ipUserCache.Add(email, ip)
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

// NewHandler builds a handler for the given users. ipCacheSaveDir is where the
// online-IP cache is persisted (empty => /etc/heki); maxIPPerUser bounds the
// device/IP count per account.
func NewHandler(users []*User, ipCacheSaveDir string, maxIPPerUser int) *Handler {
	h := &Handler{
		history:        NewSessionHistory(2 * time.Minute),
		ipUserCache:    NewBoundedIPCache(maxIPPerUser),
		ipCacheSaveDir: ipCacheSaveDir,
		stop:           make(chan struct{}),
	}
	h.UpdateUsers(users)
	_ = h.loadIPCacheFromDisk()
	go h.ipCacheSaveLoop(time.Minute)
	return h
}

// SetServerCallbacks installs the runtime hooks.
func (h *Handler) SetServerCallbacks(cb ServerCallbacks) {
	h.mu.Lock()
	h.callbacks = cb
	h.mu.Unlock()
}

// SetFallback sets the handler invoked when a connection fails authentication
// (REALITY/real-site fallback in the original).
func (h *Handler) SetFallback(fn func(net.Conn)) {
	h.mu.Lock()
	h.fallback = fn
	h.mu.Unlock()
}

// UpdateUsers replaces the user set (diff-applied by the server in the original;
// here a full swap with precomputed matcher state).
func (h *Handler) UpdateUsers(users []*User) {
	vus := make([]*vmessUser, 0, len(users))
	for _, u := range users {
		vus = append(vus, newVMessUser(u))
	}
	h.mu.Lock()
	h.users = vus
	h.mu.Unlock()
}

// Stop releases background resources.
func (h *Handler) Stop() {
	h.once.Do(func() {
		close(h.stop)
		if h.history != nil {
			h.history.Stop()
		}
	})
}

// userLimiter returns the configured speed limit for a user (0 = unlimited).
func (h *Handler) userLimiter(email string) int64 {
	h.mu.RLock()
	cb := h.callbacks.SpeedLimit
	h.mu.RUnlock()
	if cb == nil {
		return 0
	}
	return cb(email)
}

// HandleConn is the connection entry point: authenticate, then relay. On auth
// failure it falls back (transparent forward to a real site) when configured.
func (h *Handler) HandleConn(conn net.Conn) error {
	br := newPeekReader(conn)
	hdr, vu, err := h.authenticate(br)
	if err != nil {
		h.mu.RLock()
		fb := h.fallback
		h.mu.RUnlock()
		if fb != nil {
			fb(br.restored(conn))
			return nil
		}
		return err
	}
	switch hdr.Command {
	case CommandTCP:
		return h.handleTCP(conn, hdr, vu)
	case CommandUDP:
		return h.handleUDP(conn, hdr, vu)
	default:
		return fmt.Errorf("vmess: unsupported command %d", hdr.Command)
	}
}

// authenticate reads the AuthID, matches a user, then AEAD-decrypts the request
// header. Replayed handshakes are rejected via SessionHistory.
func (h *Handler) authenticate(r *peekReader) (*RequestHeader, *vmessUser, error) {
	var authID [16]byte
	if _, err := io.ReadFull(r, authID[:]); err != nil {
		return nil, nil, err
	}
	vu := h.matchUserAEAD(authID[:])
	if vu == nil {
		return nil, nil, fmt.Errorf("vmess: no matching user")
	}
	if !h.history.AddIfNotExists(sessionKey(authID)) {
		return nil, nil, fmt.Errorf("VMess replay detected user %s", vu.user.Email)
	}
	hdr, err := h.decryptRequestAEAD(r, authID, vu)
	if err != nil {
		return nil, nil, err
	}
	hdr.User = vu.user
	return hdr, vu, nil
}

// decryptRequestAEAD implements the VMess AEAD request-header decryption:
// an AEAD-protected length field followed by the AEAD-protected header, both
// keyed by KDF(cmdKey, label, authID, connectionNonce), with authID as AAD.
func (h *Handler) decryptRequestAEAD(r io.Reader, authID [16]byte, vu *vmessUser) (*RequestHeader, error) {
	var encLen [18]byte // 2-byte length + 16-byte GCM tag
	if _, err := io.ReadFull(r, encLen[:]); err != nil {
		return nil, err
	}
	var nonce [8]byte
	if _, err := io.ReadFull(r, nonce[:]); err != nil {
		return nil, err
	}
	ck := vu.cmdKey[:]

	lenKey := kdf(ck, labelHeaderLenKey, string(authID[:]), string(nonce[:]))[:16]
	lenNonce := kdf(ck, labelHeaderLenNonce, string(authID[:]), string(nonce[:]))[:12]
	lenAEAD, err := newDataAEAD(lenKey)
	if err != nil {
		return nil, err
	}
	lenPlain, err := lenAEAD.Open(nil, lenNonce, encLen[:], authID[:])
	if err != nil {
		return nil, fmt.Errorf("vmess: decrypt length: %w", err)
	}
	hdrLen := int(binary.BigEndian.Uint16(lenPlain))

	encHdr := make([]byte, hdrLen+16) // header + GCM tag
	if _, err := io.ReadFull(r, encHdr); err != nil {
		return nil, err
	}
	hKey := kdf(ck, labelHeaderKey, string(authID[:]), string(nonce[:]))[:16]
	hNonce := kdf(ck, labelHeaderNonce, string(authID[:]), string(nonce[:]))[:12]
	hAEAD, err := newDataAEAD(hKey)
	if err != nil {
		return nil, err
	}
	hdrPlain, err := hAEAD.Open(nil, hNonce, encHdr, authID[:])
	if err != nil {
		return nil, fmt.Errorf("vmess: decrypt header: %w", err)
	}
	if len(hdrPlain) < 4 {
		return nil, fmt.Errorf("vmess: header too short")
	}
	body, sum := hdrPlain[:len(hdrPlain)-4], hdrPlain[len(hdrPlain)-4:]
	var want [4]byte
	binary.BigEndian.PutUint32(want[:], fnvHash32(body))
	if subtle.ConstantTimeCompare(sum, want[:]) != 1 {
		return nil, fmt.Errorf("vmess: header checksum mismatch")
	}
	return parseVMessHeader(body)
}

// handleTCP and handleUDP are implemented in relay.go and udp.go.

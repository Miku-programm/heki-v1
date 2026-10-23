package ssr

import (
	"crypto/cipher"
	"fmt"
	"net"
	"sync"
)

// User is a configured SSR account. In single-port-multi-user mode each user has
// a distinct UID; the node shares one cipher method / obfs / protocol.
type User struct {
	Email    string
	UID      uint32
	Password string
}

// ServerCallbacks are the runtime hooks (traffic/online-IP/limits).
type ServerCallbacks struct {
	ReportTraffic func(email string, up, down int64)
	ReportAliveIP func(email string, ip net.IP)
	CheckIPLimit  func(email string, ip net.IP) bool
	SpeedLimit    func(email string) int64
}

// Handler is the SSR server handler.
type Handler struct {
	mu sync.RWMutex

	method   string // cipher method, e.g. aes-256-cfb
	protocol string // e.g. auth_chain_a
	obfs     string // e.g. tls1.2_ticket_auth
	nodePass string // node-level password (single_port carrier)

	serverKey []byte // EVP(nodePass, cipherKeyLen): auth HMAC key
	proto     Protocol
	users     []*User

	callbacks ServerCallbacks
	nat       *ssrNatTable
}

// NewHandler builds an SSR handler for a node.
func NewHandler(method, protocol, obfs, nodePassword string, users []*User) (*Handler, error) {
	f, ok := cipherRegistry[method]
	if !ok {
		return nil, fmt.Errorf("ssr: unknown cipher %q", method)
	}
	h := &Handler{
		method:    method,
		protocol:  protocol,
		obfs:      obfs,
		nodePass:  nodePassword,
		serverKey: EVPBytesToKey(nodePassword, f.keyLen),
		proto:     newProtocol(protocol),
		nat:       newSSRNatTable(),
	}
	h.UpdateUsers(users)
	return h, nil
}

// SetServerCallbacks installs runtime hooks.
func (h *Handler) SetServerCallbacks(cb ServerCallbacks) {
	h.mu.Lock()
	h.callbacks = cb
	h.mu.Unlock()
}

// UpdateUsers replaces the user set.
func (h *Handler) UpdateUsers(users []*User) {
	h.mu.Lock()
	h.users = users
	h.mu.Unlock()
}

func (h *Handler) userLimiter(email string) int64 {
	h.mu.RLock()
	cb := h.callbacks.SpeedLimit
	h.mu.RUnlock()
	if cb == nil {
		return 0
	}
	return cb(email)
}

// findUserByUID returns the user with the given UID (verifyAndFindUser).
func (h *Handler) findUserByUID(uid uint32) *User {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, u := range h.users {
		if u.UID == uid {
			return u
		}
	}
	return nil
}

// userCipher builds the per-user stream cipher. In SSR single-port mode each
// user's stream key is EVP(userPassword) (or the node password when the user has
// none).
func (h *Handler) userCipher(u *User) (*StreamCipher, error) {
	pass := u.Password
	if pass == "" {
		pass = h.nodePass
	}
	return NewStreamCipher(h.method, pass)
}

// HandleConn authenticates a new SSR connection: strip obfs, extract the UID
// from the protocol header, find (or brute-force) the user, then decrypt and
// relay. The data-plane relay threads through the server runtime and is a
// documented skeleton here.
func (h *Handler) HandleConn(conn net.Conn, firstBytes []byte) error {
	obfs := newObfs(h.obfs, h.serverKey)
	payload, ok := obfs.ServerDecode(firstBytes)
	if !ok {
		return fmt.Errorf("ssr: obfs handshake invalid")
	}

	user, dec, err := h.authenticate(payload)
	if err != nil {
		return err
	}

	if !h.admitIP(user.Email, conn) {
		return nil
	}
	_ = dec // the decryption stream for the request body
	_ = h.userLimiter(user.Email)
	// parse SOCKS target from the decrypted head, dial upstream, relay with
	// accounting -> lives in the server runtime.
	return fmt.Errorf("ssr: relay not reconstructed (data-plane lives in the server runtime)")
}

// authenticate recovers the user and prepares the request-decryption stream.
// It first tries the protocol's UID extraction + direct lookup, then falls back
// to brute-forcing every user's key (bruteForceUID / tryDecryptWithUsers).
func (h *Handler) authenticate(payload []byte) (*User, cipher.Stream, error) {
	ivLen := cipherRegistry[h.method].ivLen
	if len(payload) < ivLen {
		return nil, nil, fmt.Errorf("ssr: short payload")
	}
	iv := payload[:ivLen]
	header := payload[ivLen:]

	if uid, _, ok := h.proto.ExtractUID(header, h.serverKey); ok {
		if u := h.findUserByUID(uid); u != nil {
			if dec, err := h.decrypterFor(u, iv); err == nil {
				return u, dec, nil
			}
		}
	}
	// fallback: try each user's cipher (bruteForceUID)
	if u, dec := h.bruteForceUID(iv, header); u != nil {
		return u, dec, nil
	}
	return nil, nil, fmt.Errorf("ssr: no matching user")
}

func (h *Handler) decrypterFor(u *User, iv []byte) (cipher.Stream, error) {
	sc, err := h.userCipher(u)
	if err != nil {
		return nil, err
	}
	return sc.Decrypter(iv)
}

// bruteForceUID tries each user's key until one decrypts a well-formed header.
func (h *Handler) bruteForceUID(iv, header []byte) (*User, cipher.Stream) {
	h.mu.RLock()
	users := append([]*User(nil), h.users...)
	h.mu.RUnlock()
	for _, u := range users {
		dec, err := h.decrypterFor(u, iv)
		if err != nil {
			continue
		}
		probe := make([]byte, min(len(header), 8))
		dec2, _ := h.decrypterFor(u, iv) // fresh stream for the probe
		plain := make([]byte, len(probe))
		dec2.XORKeyStream(plain, header[:len(probe)])
		if looksLikeSocksAddr(plain) {
			return u, dec
		}
	}
	return nil, nil
}

// looksLikeSocksAddr is a cheap plausibility check used by the brute-force path.
func looksLikeSocksAddr(b []byte) bool {
	return len(b) > 0 && (b[0] == atypIPv4 || b[0] == atypDomain || b[0] == atypIPv6)
}

func (h *Handler) admitIP(email string, conn net.Conn) bool {
	ip := remoteIP(conn)
	if ip == nil {
		return true
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

package ss

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// User is a configured Shadowsocks account. For SS-AEAD, Password derives the
// key; for SS-2022, PSK is the user's pre-shared key (base64).
type User struct {
	Email    string
	Password string
	PSK      string // SS-2022 user PSK (base64)

	psk []byte // decoded PSK
	key []byte // SS-AEAD master key
}

// ServerCallbacks are the runtime hooks (traffic/online-IP/limits).
type ServerCallbacks struct {
	ReportTraffic func(email string, up, down int64)
	ReportAliveIP func(email string, ip net.IP)
	CheckIPLimit  func(email string, ip net.IP) bool
	SpeedLimit    func(email string) int64
}

// Handler is the Shadowsocks server handler.
type Handler struct {
	mu sync.RWMutex

	method string
	keyLen int
	is2022 bool

	iPSK  []byte // node identity PSK (SS-2022 multi-user)
	users []*User

	callback ServerCallbacks
	nat      *natTable
}

// NewHandler builds an SS handler. For SS-2022, nodePSK is the node iPSK (base64).
func NewHandler(method, nodePSK string, users []*User) (*Handler, error) {
	h := &Handler{method: method, is2022: is2022Method(method), nat: newNATTable()}
	if h.is2022 {
		h.keyLen = ss2022KeyLen[method]
		psk, err := decodePSK(nodePSK)
		if err != nil {
			return nil, err
		}
		h.iPSK = psk
	} else {
		spec, ok := aeadSpecs[method]
		if !ok {
			return nil, fmt.Errorf("ss: unknown method %q", method)
		}
		h.keyLen = spec.keyLen
	}
	if err := h.UpdateUsers(users); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *Handler) SetServerCallbacks(cb ServerCallbacks) {
	h.mu.Lock()
	h.callback = cb
	h.mu.Unlock()
}

// UpdateUsers precomputes per-user keys/PSKs.
func (h *Handler) UpdateUsers(users []*User) error {
	for _, u := range users {
		if h.is2022 {
			if u.PSK != "" {
				psk, err := decodePSK(u.PSK)
				if err != nil {
					return err
				}
				u.psk = psk
			}
		} else {
			u.key = EVPBytesToKey(u.Password, h.keyLen)
		}
	}
	h.mu.Lock()
	h.users = users
	h.mu.Unlock()
	return nil
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

// HandleConn dispatches an SS TCP connection to the AEAD or 2022 path.
func (h *Handler) HandleConn(conn net.Conn) error {
	if h.is2022 {
		return h.handleConn2022(conn)
	}
	return h.handleConnAEAD(conn)
}

// handleConnAEAD authenticates an SS-AEAD connection: read the salt, derive the
// subkey for each user until one decrypts the first chunk, then relay.
func (h *Handler) handleConnAEAD(conn net.Conn) error {
	spec := aeadSpecs[h.method]
	salt := make([]byte, spec.saltLen)
	if _, err := io.ReadFull(conn, salt); err != nil {
		return err
	}
	user, reader, err := h.tryDecryptFirstAEAD(conn, salt, spec)
	if err != nil {
		return err
	}
	// first decrypted bytes begin with the SOCKS target address
	head := make([]byte, 512)
	n, _ := reader.Read(head)
	addr, consumed, err := parseSocksAddr(head[:n])
	if err != nil {
		return err
	}
	if !h.admitIP(user.Email, conn) {
		return nil
	}
	return h.relay(user, conn, reader, salt, spec, addr, head[consumed:n])
}

// tryDecryptFirstAEAD finds the user whose subkey decrypts the first chunk
// (tryDecryptFirstAEAD / tryDecryptSingleByID).
func (h *Handler) tryDecryptFirstAEAD(conn net.Conn, salt []byte, spec aeadSpec) (*User, *aeadReader, error) {
	h.mu.RLock()
	users := append([]*User(nil), h.users...)
	h.mu.RUnlock()
	for _, u := range users {
		subkey, err := hkdfSha1(u.key, salt, spec.keyLen)
		if err != nil {
			continue
		}
		aead, err := spec.newAEAD(subkey)
		if err != nil {
			continue
		}
		reader := newAEADReader(conn, aead)
		// probe: a successful first readChunk means this is the right user.
		if chunk, err := reader.readChunk(); err == nil {
			// re-seat the decrypted chunk as the reader's buffer
			reader.buf, reader.off = chunk, 0
			return u, reader, nil
		}
	}
	return nil, nil, fmt.Errorf("ss: no matching user")
}

// relay copies between the client (AEAD) and the upstream, with accounting.
func (h *Handler) relay(user *User, conn net.Conn, reader *aeadReader, salt []byte, spec aeadSpec, addr string, initial []byte) error {
	_ = h.userLimiter(user.Email)
	upstream, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return err
	}
	defer upstream.Close()
	if len(initial) > 0 {
		_, _ = upstream.Write(initial)
	}

	// response path: new salt + AEAD writer
	respSalt := make([]byte, spec.saltLen)
	_, _ = randRead(respSalt)
	respSub, _ := hkdfSha1(user.key, respSalt, spec.keyLen)
	respAEAD, _ := spec.newAEAD(respSub)
	_, _ = conn.Write(respSalt)
	writer := newAEADWriter(conn, respAEAD)

	var up, down int64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); n, _ := io.Copy(upstream, reader); up = n }()
	go func() { defer wg.Done(); n, _ := io.Copy(writer, upstream); down = n }()
	wg.Wait()

	h.mu.RLock()
	report := h.callback.ReportTraffic
	h.mu.RUnlock()
	if report != nil {
		report(user.Email, up, down)
	}
	return nil
}

// handleConn2022 authenticates an SS-2022 connection via the EIH identity header.
func (h *Handler) handleConn2022(conn net.Conn) error {
	salt := make([]byte, h.keyLen)
	if _, err := io.ReadFull(conn, salt); err != nil {
		return err
	}
	eih := make([]byte, 16)
	if _, err := io.ReadFull(conn, eih); err != nil {
		return err
	}
	user := h.matchUserByIdentity(salt, eih)
	if user == nil {
		return fmt.Errorf("ss2022: no matching identity")
	}
	if !h.admitIP(user.Email, conn) {
		return nil
	}
	// session key = blake3(uPSK, salt); AES-GCM stream follows. The full 2022
	// framing (separate header AEAD + length-prefixed chunks) layers on top.
	_ = blake3DeriveKey("shadowsocks 2022 session subkey", append(append([]byte{}, user.psk...), salt...), h.keyLen)
	return fmt.Errorf("ss2022: session relay not reconstructed (needs blake3 for wire compatibility)")
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

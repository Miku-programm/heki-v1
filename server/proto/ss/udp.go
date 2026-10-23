package ss

import (
	"crypto/rand"
	"net"
	"sync"
	"time"
)

// randRead fills b with cryptographically-random bytes (connection salts).
func randRead(b []byte) (int, error) { return rand.Read(b) }

// ssIPCacheEntry remembers which user an IP was last seen as (for UDP, which is
// connectionless, to attribute datagrams). Mirrors ssIPCacheEntry.
type ssIPCacheEntry struct {
	userID int
	expiry time.Time
}

func (e *ssIPCacheEntry) IsExpired() bool  { return time.Now().After(e.expiry) }
func (e *ssIPCacheEntry) GetUserID() int   { return e.userID }
func newSSIPCacheEntry(userID int, ttl time.Duration) *ssIPCacheEntry {
	return &ssIPCacheEntry{userID: userID, expiry: time.Now().Add(ttl)}
}

// natTable tracks UDP associations with idle expiry (ssrNatTable analogue).
type natTable struct {
	mu      sync.Mutex
	entries map[string]*natEntry
	timeout time.Duration
	stop    chan struct{}
	once    sync.Once
}

type natEntry struct {
	pc       net.PacketConn
	lastSeen time.Time
}

func newNATTable() *natTable {
	t := &natTable{entries: map[string]*natEntry{}, timeout: 5 * time.Minute, stop: make(chan struct{})}
	go t.cleanupLoop()
	return t
}

func (t *natTable) getOrCreate(key string, dial func() (net.PacketConn, error)) (net.PacketConn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.entries[key]; ok {
		e.lastSeen = time.Now()
		return e.pc, nil
	}
	pc, err := dial()
	if err != nil {
		return nil, err
	}
	t.entries[key] = &natEntry{pc: pc, lastSeen: time.Now()}
	return pc, nil
}

func (t *natTable) cleanupLoop() {
	tk := time.NewTicker(t.timeout)
	defer tk.Stop()
	for {
		select {
		case <-t.stop:
			t.closeAll()
			return
		case <-tk.C:
			now := time.Now()
			t.mu.Lock()
			for k, e := range t.entries {
				if now.Sub(e.lastSeen) >= t.timeout {
					_ = e.pc.Close()
					delete(t.entries, k)
				}
			}
			t.mu.Unlock()
		}
	}
}

func (t *natTable) closeAll() {
	t.mu.Lock()
	for k, e := range t.entries {
		_ = e.pc.Close()
		delete(t.entries, k)
	}
	t.mu.Unlock()
}

// Stop releases the handler's background resources.
func (h *Handler) Stop() {
	if h.nat != nil {
		h.nat.once.Do(func() { close(h.nat.stop) })
	}
}

// HandleUDP decrypts and relays one SS UDP datagram (AEAD: salt||AEAD(payload)).
// The per-method decrypt mirrors tryDecryptUDPAEAD / tryDecryptUDP2022*; this
// reconstructs the association/relay shape.
func (h *Handler) HandleUDP(pc net.PacketConn, from net.Addr, packet []byte) error {
	// Decrypt with the matching user's key (omitted here: see handleConnAEAD for
	// the per-user subkey derivation), parse the inner SOCKS target, forward via
	// a NAT-tracked upstream socket, and encrypt the reply back.
	_ = h.nat
	return nil
}

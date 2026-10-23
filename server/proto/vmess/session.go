package vmess

import (
	"sync"
	"time"
)

// sessionKey identifies a request by its AuthID (or header hash) so a replayed
// handshake can be detected and dropped.
type sessionKey [16]byte

// SessionHistory records recently-seen sessions and rejects duplicates within a
// TTL. Mirrors heki's SessionHistory.AddIfNotExists / cleanupLoop.
type SessionHistory struct {
	mu    sync.Mutex
	seen  map[sessionKey]time.Time
	ttl   time.Duration
	stop  chan struct{}
	once  sync.Once
}

// NewSessionHistory starts a history with the given retention and a background
// cleanup loop.
func NewSessionHistory(ttl time.Duration) *SessionHistory {
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	h := &SessionHistory{
		seen: make(map[sessionKey]time.Time),
		ttl:  ttl,
		stop: make(chan struct{}),
	}
	go h.cleanupLoop()
	return h
}

// AddIfNotExists records the key and returns true if it was new (accept), or
// false if it was already seen within the TTL (replay -> reject).
func (h *SessionHistory) AddIfNotExists(key sessionKey) bool {
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	if t, ok := h.seen[key]; ok && now.Sub(t) < h.ttl {
		return false
	}
	h.seen[key] = now
	return true
}

func (h *SessionHistory) cleanupLoop() {
	t := time.NewTicker(h.ttl)
	defer t.Stop()
	for {
		select {
		case <-h.stop:
			return
		case <-t.C:
			h.removeExpired()
		}
	}
}

func (h *SessionHistory) removeExpired() {
	now := time.Now()
	h.mu.Lock()
	for k, t := range h.seen {
		if now.Sub(t) >= h.ttl {
			delete(h.seen, k)
		}
	}
	h.mu.Unlock()
}

// Stop halts the cleanup loop.
func (h *SessionHistory) Stop() {
	h.once.Do(func() { close(h.stop) })
}

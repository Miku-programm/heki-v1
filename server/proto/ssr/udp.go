package ssr

import (
	"net"
	"sync"
	"time"
)

// ssrUDPAssociationKey identifies a UDP session by client address + user.
func ssrUDPAssociationKey(client net.Addr, email string) string {
	return email + "|" + client.String()
}

// natEntry is one UDP association: the upstream socket plus last-seen time.
type natEntry struct {
	pc       net.PacketConn
	lastSeen time.Time
}

// ssrNatTable tracks UDP associations with idle expiry (mirrors ssrNatTable).
type ssrNatTable struct {
	mu      sync.Mutex
	entries map[string]*natEntry
	timeout time.Duration
	stop    chan struct{}
	once    sync.Once
}

func newSSRNatTable() *ssrNatTable {
	t := &ssrNatTable{
		entries: make(map[string]*natEntry),
		timeout: 5 * time.Minute,
		stop:    make(chan struct{}),
	}
	go t.startCleanup()
	return t
}

// getOrCreate returns the association for key, creating the upstream socket via
// dial if absent.
func (t *ssrNatTable) getOrCreate(key string, dial func() (net.PacketConn, error)) (net.PacketConn, error) {
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

func (t *ssrNatTable) delete(key string) {
	t.mu.Lock()
	if e, ok := t.entries[key]; ok {
		_ = e.pc.Close()
		delete(t.entries, key)
	}
	t.mu.Unlock()
}

func (t *ssrNatTable) startCleanup() {
	tk := time.NewTicker(t.timeout)
	defer tk.Stop()
	for {
		select {
		case <-t.stop:
			t.closeAll()
			return
		case <-tk.C:
			t.cleanup()
		}
	}
}

func (t *ssrNatTable) cleanup() {
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

func (t *ssrNatTable) closeAll() {
	t.mu.Lock()
	for k, e := range t.entries {
		_ = e.pc.Close()
		delete(t.entries, k)
	}
	t.mu.Unlock()
}

// Stop halts the cleanup loop and closes all associations.
func (t *ssrNatTable) Stop() {
	t.once.Do(func() { close(t.stop) })
}

// Stop releases the handler's background resources.
func (h *Handler) Stop() {
	if h.nat != nil {
		h.nat.Stop()
	}
}

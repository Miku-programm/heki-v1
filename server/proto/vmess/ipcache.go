package vmess

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ipCacheEntry is a single remembered client IP with an expiry.
type ipCacheEntry struct {
	IP     string    `json:"ip"`
	Expiry time.Time `json:"expiry"`
}

// IsExpired reports whether the entry's expiry is in the past.
func (e *ipCacheEntry) IsExpired() bool {
	return time.Now().After(e.Expiry)
}

// ipCacheTTL is how long a client IP is remembered.
const ipCacheTTL = 10 * time.Minute

// BoundedIPCache maps a user email to a bounded set of recent client IPs,
// used for multi-device / online-IP limiting. Mirrors heki/types.BoundedIPCache.
type BoundedIPCache struct {
	mu       sync.Mutex
	maxPerID int
	m        map[string]map[string]ipCacheEntry // email -> ip -> entry
}

func NewBoundedIPCache(maxPerID int) *BoundedIPCache {
	if maxPerID <= 0 {
		maxPerID = 3
	}
	return &BoundedIPCache{maxPerID: maxPerID, m: make(map[string]map[string]ipCacheEntry)}
}

// Add records an IP for an email, evicting expired entries and respecting the
// per-user cap.
func (c *BoundedIPCache) Add(email string, ip net.IP) {
	if ip == nil {
		return
	}
	key := ip.String()
	c.mu.Lock()
	defer c.mu.Unlock()
	set := c.m[email]
	if set == nil {
		set = make(map[string]ipCacheEntry)
		c.m[email] = set
	}
	for k, e := range set {
		if e.IsExpired() {
			delete(set, k)
		}
	}
	set[key] = ipCacheEntry{IP: key, Expiry: time.Now().Add(ipCacheTTL)}
	// enforce cap: drop the soonest-to-expire until within bound
	for len(set) > c.maxPerID {
		var oldestK string
		var oldestT time.Time
		for k, e := range set {
			if oldestK == "" || e.Expiry.Before(oldestT) {
				oldestK, oldestT = k, e.Expiry
			}
		}
		delete(set, oldestK)
	}
}

// Count returns the number of live IPs for a user.
func (c *BoundedIPCache) Count(email string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, e := range c.m[email] {
		if !e.IsExpired() {
			n++
		}
	}
	return n
}

// snapshot returns a serializable copy.
func (c *BoundedIPCache) snapshot() map[string][]ipCacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string][]ipCacheEntry, len(c.m))
	for email, set := range c.m {
		for _, e := range set {
			if !e.IsExpired() {
				out[email] = append(out[email], e)
			}
		}
	}
	return out
}

func (c *BoundedIPCache) load(data map[string][]ipCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for email, entries := range data {
		set := make(map[string]ipCacheEntry)
		for _, e := range entries {
			if !e.IsExpired() {
				set[e.IP] = e
			}
		}
		if len(set) > 0 {
			c.m[email] = set
		}
	}
}

// defaultIPCacheDir matches the binary's fallback directory.
const defaultIPCacheDir = "/etc/heki"

const ipCacheFileName = "vmess_ip_user_cache.json"

// ipCachePath is the cache file path (ipCacheSaveDir or /etc/heki, joined with
// the fixed filename).
func (h *Handler) ipCachePath() string {
	dir := h.ipCacheSaveDir
	if dir == "" {
		dir = defaultIPCacheDir
	}
	return filepath.Join(dir, ipCacheFileName)
}

// saveIPCacheToDisk writes a JSON snapshot of the live IP cache.
func (h *Handler) saveIPCacheToDisk() error {
	if h.ipUserCache == nil {
		return nil
	}
	data, err := json.Marshal(h.ipUserCache.snapshot())
	if err != nil {
		return err
	}
	return os.WriteFile(h.ipCachePath(), data, 0o600)
}

// loadIPCacheFromDisk restores a previously saved snapshot.
func (h *Handler) loadIPCacheFromDisk() error {
	if h.ipUserCache == nil {
		return nil
	}
	b, err := os.ReadFile(h.ipCachePath())
	if err != nil {
		return err
	}
	var data map[string][]ipCacheEntry
	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}
	h.ipUserCache.load(data)
	return nil
}

// ipCacheSaveLoop periodically persists the cache until the handler stops.
func (h *Handler) ipCacheSaveLoop(interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-h.stop:
			_ = h.saveIPCacheToDisk()
			return
		case <-t.C:
			_ = h.saveIPCacheToDisk()
		}
	}
}

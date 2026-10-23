package dataplane

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Record is one domain-audit entry, matching heki's JSONL schema.
type Record struct {
	Time       string `json:"time"`
	NodeID     int    `json:"node_id"`
	UserID     int    `json:"user_id"`
	Protocol   string `json:"protocol"`
	Network    string `json:"network"`
	ClientIP   string `json:"client_ip"`
	Target     string `json:"target"`
	TargetHost string `json:"target_host"`
	TargetIP   string `json:"target_ip,omitempty"`
	TargetPort int    `json:"target_port"`
	Outbound   string `json:"outbound,omitempty"`
	Status     string `json:"status"`
}

// Auditor writes domain-audit records (one JSONL file per node per UTC date)
// for connections whose target matches one of the configured rules. Writes go
// through a non-blocking queue; short-window de-duplication avoids floods.
type Auditor struct {
	dir       string
	rules     []string
	retention int // days, 0 = keep forever

	queue chan Record
	wg    sync.WaitGroup

	mu        sync.Mutex
	dedup     map[string]time.Time
	nowFn     func() time.Time
	openFile  func(path string) (writer, error)
	closeOnce sync.Once

	// touched only by the single loop goroutine (and Close after it returns)
	curFile writer
	curName string
}

// dedupWindow is the short window within which identical (user, protocol,
// network, target) records are collapsed.
const dedupWindow = 5 * time.Second

// dedupMax caps the dedup map so it cannot grow without bound; when exceeded,
// entries older than the window are pruned.
const dedupMax = 8192

type writer interface {
	Write([]byte) (int, error)
	Close() error
}

// NewAuditor builds an auditor. domains is heki's domain_audit_domains list;
// an empty list records nothing. dir is domain_audit_log_dir.
func NewAuditor(dir string, domains []string, retentionDays int) *Auditor {
	a := &Auditor{
		dir:       dir,
		rules:     domains,
		retention: retentionDays,
		queue:     make(chan Record, 1024),
		dedup:     map[string]time.Time{},
		nowFn:     time.Now,
	}
	a.openFile = func(path string) (writer, error) {
		return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	}
	a.wg.Add(1)
	go a.loop()
	return a
}

// Record enqueues a record if its target matches an audit rule (non-blocking).
func (a *Auditor) Record(r Record) {
	if a == nil || len(a.rules) == 0 {
		return
	}
	host, _, _ := net.SplitHostPort(r.Target)
	if host == "" {
		host = r.TargetHost
	}
	var ip net.IP
	if r.TargetIP != "" {
		ip = net.ParseIP(r.TargetIP)
	} else {
		ip = net.ParseIP(host)
	}
	t := Target{Host: hostForRules(host), IP: ip, Port: r.TargetPort}
	if !matchAny(a.rules, t) {
		return
	}
	if r.Time == "" {
		r.Time = a.nowFn().UTC().Format("2006-01-02T15:04:05.000Z")
	}
	// short-window dedup by (user, protocol, network, target)
	key := fmt.Sprintf("%d|%s|%s|%s", r.UserID, r.Protocol, r.Network, r.Target)
	a.mu.Lock()
	now := a.nowFn()
	if last, ok := a.dedup[key]; ok && now.Sub(last) < dedupWindow {
		a.mu.Unlock()
		return
	}
	if len(a.dedup) >= dedupMax {
		for k, t := range a.dedup {
			if now.Sub(t) >= dedupWindow {
				delete(a.dedup, k)
			}
		}
	}
	a.dedup[key] = now
	a.mu.Unlock()

	select {
	case a.queue <- r:
	default: // queue full: drop (non-blocking)
	}
}

func (a *Auditor) loop() {
	defer a.wg.Done()
	defer func() {
		if a.curFile != nil {
			a.curFile.Close()
			a.curFile = nil
		}
	}()
	for r := range a.queue {
		a.write(r)
	}
}

// write appends one record, keeping the current day's file open (reopened only
// when the node/date-derived name changes) to avoid an open+close per record.
// Only the single loop goroutine touches curFile/curName, so no lock is needed.
func (a *Auditor) write(r Record) {
	if a.dir == "" || a.dir == "false" {
		return
	}
	name := fmt.Sprintf("domain-audit-node-%d-%s.jsonl", r.NodeID, a.nowFn().UTC().Format("2006-01-02"))
	if name != a.curName {
		if a.curFile != nil {
			a.curFile.Close()
			a.curFile = nil
		}
		if err := os.MkdirAll(a.dir, 0o755); err != nil {
			return
		}
		f, err := a.openFile(filepath.Join(a.dir, name))
		if err != nil {
			a.curName = ""
			return
		}
		a.curFile, a.curName = f, name
	}
	if a.curFile == nil {
		return
	}
	b, _ := json.Marshal(r)
	b = append(b, '\n')
	_, _ = a.curFile.Write(b)
}

// Close flushes and stops the auditor. Safe to call more than once.
func (a *Auditor) Close() {
	if a == nil {
		return
	}
	a.closeOnce.Do(func() {
		close(a.queue)
		a.wg.Wait()
	})
}

// CleanupRetention removes audit files older than the retention window.
func (a *Auditor) CleanupRetention() {
	if a == nil || a.retention <= 0 || a.dir == "" || a.dir == "false" {
		return
	}
	cutoff := a.nowFn().AddDate(0, 0, -a.retention)
	entries, err := os.ReadDir(a.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		info, err := e.Info()
		if err == nil && info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(a.dir, e.Name()))
		}
	}
}

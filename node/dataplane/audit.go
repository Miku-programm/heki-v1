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
}

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
	if last, ok := a.dedup[key]; ok && now.Sub(last) < 5*time.Second {
		a.mu.Unlock()
		return
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
	for r := range a.queue {
		a.write(r)
	}
}

func (a *Auditor) write(r Record) {
	if a.dir == "" || a.dir == "false" {
		return
	}
	if err := os.MkdirAll(a.dir, 0o755); err != nil {
		return
	}
	date := a.nowFn().UTC().Format("2006-01-02")
	name := fmt.Sprintf("domain-audit-node-%d-%s.jsonl", r.NodeID, date)
	f, err := a.openFile(filepath.Join(a.dir, name))
	if err != nil {
		return
	}
	defer f.Close()
	b, _ := json.Marshal(r)
	_, _ = f.Write(append(b, '\n'))
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

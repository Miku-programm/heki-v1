package panel

import (
	"log"
	"sync"
	"time"
)

// LicenseHooks are injected by the node bootstrap (SetLicenseHooks). The
// scheduler calls RefreshMaxUsers before each sync and RefreshOnlineIfStale on
// the heartbeat.
type LicenseHooks struct {
	RefreshMaxUsers      func() (int, error)
	RefreshOnlineIfStale func() error
	GetMaxUsers          func() int
}

// RuntimeGuard is the license revalidation callback invoked at node lifecycle
// stages. A non-nil return blocks the node.
type RuntimeGuard func(stage string) error

// UserSink applies the pulled user set to the data plane (server.UpdateUsers).
type UserSink interface {
	UpdateUsers(nodeID int, users []*UserInfo) error
}

// Scheduler wires a PanelClient to the data plane and the license, running the
// pull/report/heartbeat loops. Mirrors heki/panel.Scheduler.
type Scheduler struct {
	mu sync.Mutex

	cfg    SchedulerConfig
	client PanelClient
	sink   UserSink

	license LicenseHooks
	guard   RuntimeGuard

	lastNodeETag string
	lastUserETag string

	stop chan struct{}
	once sync.Once
}

// NewScheduler builds a scheduler for one node.
func NewScheduler(cfg SchedulerConfig, client PanelClient, sink UserSink) *Scheduler {
	if cfg.PullInterval <= 0 {
		cfg.PullInterval = 60 * time.Second
	}
	if cfg.PushInterval <= 0 {
		cfg.PushInterval = 60 * time.Second
	}
	if cfg.HeartbeatEvery <= 0 {
		cfg.HeartbeatEvery = 30 * time.Second
	}
	return &Scheduler{cfg: cfg, client: client, sink: sink, stop: make(chan struct{})}
}

// SetLicenseHooks injects the license callbacks.
func (s *Scheduler) SetLicenseHooks(h LicenseHooks) {
	s.mu.Lock()
	s.license = h
	s.mu.Unlock()
}

// SetRuntimeGuard injects the runtime guard.
func (s *Scheduler) SetRuntimeGuard(g RuntimeGuard) {
	s.mu.Lock()
	s.guard = g
	s.mu.Unlock()
}

// mustPassRuntimeGuard calls the guard for a lifecycle stage; on failure it logs
// a fatal message and exits the process (log.Fatalf -> os.Exit(1)), matching the
// binary. A nil guard is a no-op.
func (s *Scheduler) mustPassRuntimeGuard(stage string) {
	s.mu.Lock()
	g := s.guard
	nodeID := s.cfg.NodeID
	s.mu.Unlock()
	if g == nil {
		return
	}
	if err := g(stage); err != nil {
		log.Fatalf("[FATAL] [Node %d] %s failed during %s: %v", nodeID, "runtime-guard", stage, err)
	}
}

// Start runs the three loops after passing the node-start guard.
func (s *Scheduler) Start() {
	s.mustPassRuntimeGuard("before server start")
	go s.syncLoop()
	go s.reportLoop()
	go s.heartbeatLoop()
}

// Stop halts all loops.
func (s *Scheduler) Stop() { s.once.Do(func() { close(s.stop) }) }

func (s *Scheduler) syncLoop() {
	t := time.NewTicker(s.cfg.PullInterval)
	defer t.Stop()
	s.doSync()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.doSync()
		}
	}
}

// doSync refreshes the license (aborting the sync on failure), pulls node config
// and users, caps the user count by the license maximum, and applies the set.
func (s *Scheduler) doSync() {
	s.mu.Lock()
	lic, client, sink, nodeID, maxUsers := s.license, s.client, s.sink, s.cfg.NodeID, s.cfg.LicenseMaxUsers
	s.mu.Unlock()

	// 1. refresh license BEFORE sync; failure aborts (no users topped up)
	if lic.RefreshMaxUsers != nil {
		if m, err := lic.RefreshMaxUsers(); err != nil {
			log.Printf("[WARN] [Node %d] Refresh license before sync failed: %v", nodeID, err)
			return
		} else if m > 0 {
			maxUsers = m
		}
	}

	// 2. pull node config + users
	if _, err := client.GetNodeInfo(); err != nil {
		log.Printf("[WARN] [Node %d] get node config: %v", nodeID, err)
		return
	}
	users, err := client.GetUsers()
	if err != nil {
		log.Printf("[WARN] [Node %d] get users: %v", nodeID, err)
		return
	}
	users = dedupUsers(users)

	// 3. cap by license max users (LimitUsersByIDStable)
	if maxUsers > 0 && len(users) > maxUsers {
		log.Printf("[WARN] [Node %d] User count (%d) exceeds license limit (%d), only first %d users will be active",
			nodeID, len(users), maxUsers, maxUsers)
		users = users[:maxUsers]
	}

	// 4. apply to the data plane
	if sink != nil {
		if err := sink.UpdateUsers(nodeID, users); err != nil {
			log.Printf("[WARN] [Node %d] apply users: %v", nodeID, err)
		}
	}
}

// dedupUsers removes duplicate user rows by ID (stable, first wins).
func dedupUsers(in []*UserInfo) []*UserInfo {
	seen := make(map[int]struct{}, len(in))
	out := in[:0:0]
	for _, u := range in {
		if _, ok := seen[u.ID]; ok {
			continue
		}
		seen[u.ID] = struct{}{}
		out = append(out, u)
	}
	return out
}

func (s *Scheduler) reportLoop() {
	t := time.NewTicker(s.cfg.PushInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.doReport()
		}
	}
}

// doReport pushes accumulated traffic and alive-IP batches to the panel.
func (s *Scheduler) doReport() {
	s.mu.Lock()
	client, nodeID := s.client, s.cfg.NodeID
	s.mu.Unlock()
	// In the full node these batches come from the traffic accounting layer.
	if err := client.ReportTraffic(nil); err != nil {
		log.Printf("[WARN] [Node %d] Report traffic failed: %v", nodeID, err)
	}
	if err := client.ReportAliveIP(nil); err != nil {
		log.Printf("[WARN] [Node %d] Report alive ip: %v", nodeID, err)
	}
}

func (s *Scheduler) heartbeatLoop() {
	t := time.NewTicker(s.cfg.HeartbeatEvery)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.doHeartbeat()
		}
	}
}

// doHeartbeat refreshes the online license (allowing remote revocation) and
// reports node status.
func (s *Scheduler) doHeartbeat() {
	s.mu.Lock()
	lic, client, nodeID := s.license, s.client, s.cfg.NodeID
	s.mu.Unlock()
	if lic.RefreshOnlineIfStale != nil {
		_ = lic.RefreshOnlineIfStale()
	}
	if err := client.ReportNodeInfo(&NodeStatus{}); err != nil {
		log.Printf("[WARN] [Node %d] heartbeat: %v", nodeID, err)
	}
}

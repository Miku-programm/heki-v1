// Package node ties the reconstructed pieces into a minimal, runnable proxy
// node: it pulls users from a billing panel, listens for TLS connections, runs a
// protocol handler (trojan here), relays traffic, and reports usage back.
//
// This is the first end-to-end "minimal closed loop" over the library packages:
//
//	panel GetUsers -> handler.UpdateUsers
//	tls.Listen     -> handler.HandleConn (auth + relay)
//	traffic         -> accounting -> panel.ReportTraffic (periodic)
//
// It demonstrates that the reconstruction can actually run against a panel for
// trojan/TCP+TLS. Other protocols/transports are added the same way.
package node

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"heki/panel"
	"heki/server/proto/trojan"
)

// Config is the node configuration.
type Config struct {
	PanelType string // sspanel / xboard / ppanel / metron / hekiv1
	PanelURL  string
	PanelKey  string
	NodeID    int

	Listen  string // e.g. ":443" or "127.0.0.1:0"
	TLSCert string // path to cert PEM (ignored if TLSConfig set)
	TLSKey  string // path to key PEM

	Fallback *trojan.FallbackTarget // real-site fallback for bad auth

	SyncInterval   time.Duration // user pull period
	ReportInterval time.Duration // traffic push period

	// TLSConfig overrides cert/key file loading (used in tests).
	TLSConfig *tls.Config
}

// accounting accumulates per-user traffic between report pushes.
type accounting struct {
	mu   sync.Mutex
	up   map[string]int64
	down map[string]int64
}

func newAccounting() *accounting {
	return &accounting{up: map[string]int64{}, down: map[string]int64{}}
}

func (a *accounting) add(email string, up, down int64) {
	a.mu.Lock()
	a.up[email] += up
	a.down[email] += down
	a.mu.Unlock()
}

func (a *accounting) drain() map[string][2]int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string][2]int64, len(a.up))
	for e, u := range a.up {
		out[e] = [2]int64{u, a.down[e]}
	}
	a.up = map[string]int64{}
	a.down = map[string]int64{}
	return out
}

// Node is a running proxy node.
type Node struct {
	cfg     Config
	client  panel.PanelClient
	handler *trojan.Handler
	acct    *accounting

	mu        sync.RWMutex
	emailToID map[string]int

	ln   net.Listener
	stop chan struct{}
	once sync.Once
}

// New builds a node and wires the panel client and the trojan handler's
// traffic callback into the accounting layer.
func New(cfg Config) (*Node, error) {
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = 60 * time.Second
	}
	if cfg.ReportInterval <= 0 {
		cfg.ReportInterval = 30 * time.Second
	}
	client, err := panel.NewClient(cfg.PanelType, cfg.PanelURL, cfg.PanelKey, cfg.NodeID)
	if err != nil {
		return nil, err
	}
	n := &Node{
		cfg:       cfg,
		client:    client,
		acct:      newAccounting(),
		emailToID: map[string]int{},
		stop:      make(chan struct{}),
	}
	n.handler = trojan.NewHandler(nil, cfg.Fallback)
	n.handler.SetServerCallbacks(trojan.ServerCallbacks{
		ReportTraffic: func(email string, up, down int64) { n.acct.add(email, up, down) },
	})
	return n, nil
}

// Start pulls the initial user set, opens the TLS listener, and launches the
// sync / report / accept loops.
func (n *Node) Start() error {
	// node config is optional for the minimal loop; log and continue on error.
	if _, err := n.client.GetNodeInfo(); err != nil {
		log.Printf("[WARN] [Node %d] get node config: %v", n.cfg.NodeID, err)
	}
	if err := n.syncUsers(); err != nil {
		return fmt.Errorf("initial user sync: %w", err)
	}

	tlsCfg := n.cfg.TLSConfig
	if tlsCfg == nil {
		cert, err := tls.LoadX509KeyPair(n.cfg.TLSCert, n.cfg.TLSKey)
		if err != nil {
			return fmt.Errorf("load tls cert: %w", err)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}}
	}
	ln, err := tls.Listen("tcp", n.cfg.Listen, tlsCfg)
	if err != nil {
		return fmt.Errorf("listen %s: %w", n.cfg.Listen, err)
	}
	n.ln = ln
	log.Printf("[INFO] [Node %d] listening on %s (trojan/TLS)", n.cfg.NodeID, ln.Addr())

	go n.syncLoop()
	go n.reportLoop()
	go n.acceptLoop()
	return nil
}

// Addr reports the actual listen address (useful when Listen uses :0).
func (n *Node) Addr() net.Addr {
	if n.ln == nil {
		return nil
	}
	return n.ln.Addr()
}

func (n *Node) acceptLoop() {
	for {
		conn, err := n.ln.Accept()
		if err != nil {
			select {
			case <-n.stop:
			default:
			}
			return
		}
		go func() {
			defer conn.Close()
			if err := n.handler.HandleConn(conn); err != nil {
				log.Printf("[DEBUG] [Node %d] conn: %v", n.cfg.NodeID, err)
			}
		}()
	}
}

func (n *Node) syncLoop() {
	t := time.NewTicker(n.cfg.SyncInterval)
	defer t.Stop()
	for {
		select {
		case <-n.stop:
			return
		case <-t.C:
			if err := n.syncUsers(); err != nil {
				log.Printf("[WARN] [Node %d] sync users: %v", n.cfg.NodeID, err)
			}
		}
	}
}

// syncUsers pulls the panel user set into the trojan handler and refreshes the
// email->id map used for traffic reporting.
func (n *Node) syncUsers() error {
	users, err := n.client.GetUsers()
	if err != nil {
		return err
	}
	tu := make([]*trojan.User, 0, len(users))
	m := make(map[string]int, len(users))
	for _, u := range users {
		email := u.Email
		if email == "" {
			email = fmt.Sprintf("user-%d", u.ID)
		}
		tu = append(tu, &trojan.User{Email: email, Password: u.Password})
		m[email] = u.ID
	}
	n.handler.UpdateUsers(tu)
	n.mu.Lock()
	n.emailToID = m
	n.mu.Unlock()
	log.Printf("[INFO] [Node %d] synced %d users", n.cfg.NodeID, len(tu))
	return nil
}

func (n *Node) reportLoop() {
	t := time.NewTicker(n.cfg.ReportInterval)
	defer t.Stop()
	for {
		select {
		case <-n.stop:
			n.reportTraffic()
			return
		case <-t.C:
			n.reportTraffic()
		}
	}
}

// reportTraffic drains the accumulator and pushes a batch to the panel.
func (n *Node) reportTraffic() {
	batch := n.acct.drain()
	if len(batch) == 0 {
		return
	}
	n.mu.RLock()
	idOf := n.emailToID
	n.mu.RUnlock()
	var rows []panel.UserTraffic
	for email, ud := range batch {
		if id, ok := idOf[email]; ok {
			rows = append(rows, panel.UserTraffic{UserID: id, Upload: ud[0], Download: ud[1]})
		}
	}
	if len(rows) > 0 {
		if err := n.client.ReportTraffic(rows); err != nil {
			log.Printf("[WARN] [Node %d] report traffic: %v", n.cfg.NodeID, err)
		}
	}
}

// Stop shuts down the node.
func (n *Node) Stop() {
	n.once.Do(func() {
		close(n.stop)
		if n.ln != nil {
			_ = n.ln.Close()
		}
	})
}

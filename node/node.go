// Package node ties the reconstructed pieces into a runnable proxy node: it
// pulls users from a billing panel, listens (TLS or raw TCP depending on the
// protocol), runs a protocol handler, relays traffic, and reports usage back.
//
//	panel GetUsers -> handler.UpdateUsers
//	listen         -> handler.HandleConn (auth + relay)
//	traffic         -> accounting -> panel.ReportTraffic (periodic)
//
// Runnable protocols (TCP / TLS / HTTP transport): trojan, vmess, vless
// (non-REALITY), ss (AEAD), naive. QUIC/REALITY/mieru/anytls need their upstream
// transport libraries and are not wired here.
package node

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"heki/panel"
	"heki/server/proto/naive"
	"heki/server/proto/ss"
	"heki/server/proto/trojan"
	"heki/server/proto/vless"
	"heki/server/proto/vmess"
	"heki/transport/anytlsx"
	"heki/transport/hy2"
	"heki/transport/mierux"
	"heki/transport/realityx"
	"heki/transport/tuicx"
)

// Config is the node configuration.
type Config struct {
	Protocol string // trojan(default) / vmess / vless / ss / naive
	Method   string // ss cipher method (aes-256-gcm default)

	PanelType string
	PanelURL  string
	PanelKey  string
	NodeID    int

	Listen  string
	TLSCert string
	TLSKey  string

	Fallback *trojan.FallbackTarget

	SyncInterval   time.Duration
	ReportInterval time.Duration

	TLSConfig *tls.Config // overrides cert/key files (tests)

	Reality *RealityConfig // required for protocol "vless-reality"

	Hysteria2 *Hysteria2Config // optional tuning for protocol "hysteria2"
}

// Hysteria2Config holds optional Hysteria2 tuning (Salamander obfuscation and
// bandwidth caps), matching heki's obfs=salamander + obfs_password behavior.
type Hysteria2Config struct {
	ObfsPassword string // Salamander PSK; empty disables obfuscation
	UpMbps       int    // server egress cap, 0 = unlimited
	DownMbps     int    // server ingress cap, 0 = unlimited
}

// RealityConfig holds the node-level REALITY parameters (operator-provided,
// same shape as XrayR/xray: a private key, the borrowed Dest site, allowed
// SNIs and short IDs).
type RealityConfig struct {
	PrivateKey  []byte   // 32-byte x25519 private key
	ServerNames []string // allowed SNI (must include Dest's cert name)
	ShortIDs    []string // allowed short IDs (hex)
	Dest        string   // borrowed real TLS 1.3 site, host:port
}

type handlerAdapter interface {
	HandleConn(net.Conn) error
}

// udpService is a running QUIC-based protocol server (hysteria2, tuic).
type udpService interface {
	Serve() error
	Close() error
}

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
	a.up, a.down = map[string]int64{}, map[string]int64{}
	return out
}

// Node is a running proxy node.
type Node struct {
	cfg     Config
	client  panel.PanelClient
	acct    *accounting
	handler handlerAdapter
	syncFn  func([]*panel.UserInfo) map[string]int // applies users, returns email->id
	useTLS  bool

	// UDP/QUIC path, backed by real upstream libraries (hysteria2 -> apernet,
	// tuic -> sing-quic). udpNew builds the server on the bound PacketConn;
	// udpSync applies users to n.udpSrv and returns the email->id map.
	useUDP     bool
	selfListen bool // server binds its own socket (mieru); no PacketConn/TLS from node
	udpSrv     udpService
	udpNew     func(cert tls.Certificate, pc net.PacketConn) (udpService, error)
	udpSync    func(us []*panel.UserInfo) map[string]int
	pc         net.PacketConn

	// REALITY listener wrapper (protocol vless-reality): wraps the raw TCP
	// listener with the real sagernet/reality handshake.
	realityNew func(net.Listener) (net.Listener, error)

	mu        sync.RWMutex
	emailToID map[string]int

	ln   net.Listener
	stop chan struct{}
	once sync.Once
}

// New builds a node for the configured protocol.
func New(cfg Config) (*Node, error) {
	if cfg.Protocol == "" {
		cfg.Protocol = "trojan"
	}
	if cfg.Method == "" {
		cfg.Method = "aes-256-gcm"
	}
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
	n := &Node{cfg: cfg, client: client, acct: newAccounting(), emailToID: map[string]int{}, stop: make(chan struct{})}
	if err := n.buildHandler(); err != nil {
		return nil, err
	}
	return n, nil
}

// buildHandler constructs the protocol handler, its user-sync adapter, and
// whether it needs TLS.
func (n *Node) buildHandler() error {
	report := func(email string, up, down int64) { n.acct.add(email, up, down) }
	switch n.cfg.Protocol {
	case "trojan":
		h := trojan.NewHandler(nil, n.cfg.Fallback)
		h.SetServerCallbacks(trojan.ServerCallbacks{ReportTraffic: report})
		n.handler, n.useTLS = h, true
		n.syncFn = func(us []*panel.UserInfo) map[string]int {
			out := make([]*trojan.User, 0, len(us))
			m := map[string]int{}
			for _, u := range us {
				e := emailOf(u)
				out = append(out, &trojan.User{Email: e, Password: pwOf(u)})
				m[e] = u.ID
			}
			h.UpdateUsers(out)
			return m
		}
	case "vmess":
		h := vmess.NewHandler(nil, "", 0)
		h.SetServerCallbacks(vmess.ServerCallbacks{ReportTraffic: report})
		n.handler, n.useTLS = h, true
		n.syncFn = func(us []*panel.UserInfo) map[string]int {
			out := make([]*vmess.User, 0, len(us))
			m := map[string]int{}
			for _, u := range us {
				e := emailOf(u)
				out = append(out, &vmess.User{Email: e, UUID: vmess.ParseUUID(u.UUID)})
				m[e] = u.ID
			}
			h.UpdateUsers(out)
			return m
		}
	case "vless":
		h := vless.NewHandler(nil, nil, nil, visionFallback(n.cfg.Fallback))
		h.SetServerCallbacks(vless.ServerCallbacks{ReportTraffic: report})
		n.handler, n.useTLS = h, true
		n.syncFn = func(us []*panel.UserInfo) map[string]int {
			out := make([]*vless.User, 0, len(us))
			m := map[string]int{}
			for _, u := range us {
				e := emailOf(u)
				id, err := vless.ParseUUID(u.UUID)
				if err != nil {
					continue
				}
				out = append(out, &vless.User{Email: e, UUID: id})
				m[e] = u.ID
			}
			h.UpdateUsers(out)
			return m
		}
	case "vless-reality":
		if n.cfg.Reality == nil {
			return fmt.Errorf("node: protocol vless-reality requires Reality config")
		}
		h := vless.NewHandler(nil, nil, nil, visionFallback(n.cfg.Fallback))
		h.SetServerCallbacks(vless.ServerCallbacks{ReportTraffic: report})
		n.handler, n.useTLS = h, false // REALITY terminates the transport, not TLS
		rc := n.cfg.Reality
		n.realityNew = func(inner net.Listener) (net.Listener, error) {
			return realityx.NewListener(inner, realityx.Options{
				PrivateKey:  rc.PrivateKey,
				ServerNames: rc.ServerNames,
				ShortIDs:    rc.ShortIDs,
				Dest:        rc.Dest,
			})
		}
		n.syncFn = func(us []*panel.UserInfo) map[string]int {
			out := make([]*vless.User, 0, len(us))
			m := map[string]int{}
			for _, u := range us {
				e := emailOf(u)
				id, err := vless.ParseUUID(u.UUID)
				if err != nil {
					continue
				}
				out = append(out, &vless.User{Email: e, UUID: id})
				m[e] = u.ID
			}
			h.UpdateUsers(out)
			return m
		}
	case "ss":
		h, err := ss.NewHandler(n.cfg.Method, "", nil)
		if err != nil {
			return err
		}
		h.SetServerCallbacks(ss.ServerCallbacks{ReportTraffic: report})
		n.handler, n.useTLS = h, false // SS carries its own encryption
		n.syncFn = func(us []*panel.UserInfo) map[string]int {
			out := make([]*ss.User, 0, len(us))
			m := map[string]int{}
			for _, u := range us {
				e := emailOf(u)
				out = append(out, &ss.User{Email: e, Password: pwOf(u)})
				m[e] = u.ID
			}
			_ = h.UpdateUsers(out)
			return m
		}
	case "naive":
		h := naive.NewHandler(nil)
		h.SetServerCallbacks(naive.ServerCallbacks{ReportTraffic: report})
		n.handler, n.useTLS = h, true
		n.syncFn = func(us []*panel.UserInfo) map[string]int {
			out := make([]*naive.User, 0, len(us))
			m := map[string]int{}
			for _, u := range us {
				e := emailOf(u)
				out = append(out, &naive.User{Email: e, Username: e, Password: pwOf(u)})
				m[e] = u.ID
			}
			h.UpdateUsers(out)
			return m
		}
	case "hysteria2":
		n.useUDP = true
		n.udpNew = func(cert tls.Certificate, pc net.PacketConn) (udpService, error) {
			var opt hy2.Options
			if h := n.cfg.Hysteria2; h != nil {
				opt = hy2.Options{ObfsPassword: h.ObfsPassword, UpMbps: h.UpMbps, DownMbps: h.DownMbps}
			}
			return hy2.New(cert, pc, nil, report, opt)
		}
		n.udpSync = func(us []*panel.UserInfo) map[string]int {
			out := make([]*hy2.User, 0, len(us))
			m := map[string]int{}
			for _, u := range us {
				e := emailOf(u)
				out = append(out, &hy2.User{ID: u.ID, Email: e, Auth: pwOf(u)})
				m[e] = u.ID
			}
			if s, ok := n.udpSrv.(*hy2.Server); ok {
				s.UpdateUsers(out)
			}
			return m
		}
	case "anytls":
		h, err := anytlsx.New(report)
		if err != nil {
			return err
		}
		n.handler, n.useTLS = h, true
		n.syncFn = func(us []*panel.UserInfo) map[string]int {
			out := make([]*anytlsx.User, 0, len(us))
			m := map[string]int{}
			for _, u := range us {
				e := emailOf(u)
				out = append(out, &anytlsx.User{Email: e, Password: pwOf(u)})
				m[e] = u.ID
			}
			h.UpdateUsers(out)
			return m
		}
	case "tuic":
		n.useUDP = true
		n.udpNew = func(cert tls.Certificate, pc net.PacketConn) (udpService, error) {
			return tuicx.New(cert, pc, report)
		}
		n.udpSync = func(us []*panel.UserInfo) map[string]int {
			out := make([]*tuicx.User, 0, len(us))
			m := map[string]int{}
			for _, u := range us {
				e := emailOf(u)
				id, err := vless.ParseUUID(u.UUID)
				if err != nil {
					continue
				}
				out = append(out, &tuicx.User{ID: u.ID, Email: e, UUID: id, Password: pwOf(u)})
				m[e] = u.ID
			}
			if s, ok := n.udpSrv.(*tuicx.Server); ok {
				s.UpdateUsers(out)
			}
			return m
		}
	case "mieru":
		n.useUDP = true
		n.selfListen = true
		host, portStr, err := net.SplitHostPort(n.cfg.Listen)
		if err != nil {
			return fmt.Errorf("mieru listen addr %q: %w", n.cfg.Listen, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("mieru listen port %q: %w", portStr, err)
		}
		n.udpNew = func(_ tls.Certificate, _ net.PacketConn) (udpService, error) {
			return mierux.New(host, port, report), nil
		}
		n.udpSync = func(us []*panel.UserInfo) map[string]int {
			out := make([]*mierux.User, 0, len(us))
			m := map[string]int{}
			for _, u := range us {
				e := emailOf(u)
				out = append(out, &mierux.User{ID: u.ID, Email: e, Password: pwOf(u)})
				m[e] = u.ID
			}
			if s, ok := n.udpSrv.(*mierux.Server); ok {
				s.UpdateUsers(out)
			}
			return m
		}
	default:
		return fmt.Errorf("node: unsupported/unwired protocol %q (runnable: trojan/vmess/vless/vless-reality/ss/naive/anytls/hysteria2/tuic/mieru)", n.cfg.Protocol)
	}
	return nil
}

func emailOf(u *panel.UserInfo) string {
	if u.Email != "" {
		return u.Email
	}
	return fmt.Sprintf("user-%d", u.ID)
}
func pwOf(u *panel.UserInfo) string {
	if u.Password != "" {
		return u.Password
	}
	return u.UUID
}
func visionFallback(f *trojan.FallbackTarget) *vless.FallbackTarget {
	if f == nil {
		return nil
	}
	return &vless.FallbackTarget{Host: f.Host, Port: f.Port}
}

// Start pulls users, opens the listener (TLS or raw), and launches the loops.
func (n *Node) Start() error {
	if _, err := n.client.GetNodeInfo(); err != nil {
		log.Printf("[WARN] [Node %d] get node config: %v", n.cfg.NodeID, err)
	}

	// Non-TCP-listener path: real upstream server either on a UDP PacketConn
	// supplied by the node (hysteria2/tuic QUIC) or binding its own socket
	// (mieru, selfListen).
	if n.useUDP {
		var cert tls.Certificate
		var pc net.PacketConn
		if !n.selfListen {
			c, err := n.loadCert()
			if err != nil {
				return err
			}
			cert = c
			p, err := net.ListenPacket("udp", n.cfg.Listen)
			if err != nil {
				return fmt.Errorf("listen udp %s: %w", n.cfg.Listen, err)
			}
			pc = p
			n.pc = pc
		}
		srv, err := n.udpNew(cert, pc)
		if err != nil {
			if pc != nil {
				_ = pc.Close()
			}
			return fmt.Errorf("%s server: %w", n.cfg.Protocol, err)
		}
		n.udpSrv = srv
		if err := n.syncUsers(); err != nil {
			return fmt.Errorf("initial user sync: %w", err)
		}
		addr := n.cfg.Listen
		if pc != nil {
			addr = pc.LocalAddr().String()
		}
		log.Printf("[INFO] [Node %d] %s listening on %s", n.cfg.NodeID, n.cfg.Protocol, addr)
		go func() {
			if err := srv.Serve(); err != nil {
				log.Printf("[WARN] [Node %d] %s serve: %v", n.cfg.NodeID, n.cfg.Protocol, err)
			}
		}()
		go n.syncLoop()
		go n.reportLoop()
		return nil
	}

	if err := n.syncUsers(); err != nil {
		return fmt.Errorf("initial user sync: %w", err)
	}

	var ln net.Listener
	var err error
	if n.useTLS {
		tlsCfg := n.cfg.TLSConfig
		if tlsCfg == nil {
			cert, cerr := tls.LoadX509KeyPair(n.cfg.TLSCert, n.cfg.TLSKey)
			if cerr != nil {
				return fmt.Errorf("load tls cert: %w", cerr)
			}
			tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}}
		}
		ln, err = tls.Listen("tcp", n.cfg.Listen, tlsCfg)
	} else {
		ln, err = net.Listen("tcp", n.cfg.Listen)
	}
	if err != nil {
		return fmt.Errorf("listen %s: %w", n.cfg.Listen, err)
	}
	if n.realityNew != nil {
		rln, rerr := n.realityNew(ln)
		if rerr != nil {
			_ = ln.Close()
			return fmt.Errorf("reality listener: %w", rerr)
		}
		ln = rln
	}
	n.ln = ln
	log.Printf("[INFO] [Node %d] %s listening on %s (tls=%v)", n.cfg.NodeID, n.cfg.Protocol, ln.Addr(), n.useTLS)

	go n.syncLoop()
	go n.reportLoop()
	go n.acceptLoop()
	return nil
}

func (n *Node) Addr() net.Addr {
	if n.useUDP && n.pc != nil {
		return n.pc.LocalAddr()
	}
	if n.ln == nil {
		return nil
	}
	return n.ln.Addr()
}

func (n *Node) acceptLoop() {
	for {
		conn, err := n.ln.Accept()
		if err != nil {
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

// loadCert returns the TLS certificate from the config (TLSConfig override or
// cert/key files).
func (n *Node) loadCert() (tls.Certificate, error) {
	if n.cfg.TLSConfig != nil && len(n.cfg.TLSConfig.Certificates) > 0 {
		return n.cfg.TLSConfig.Certificates[0], nil
	}
	return tls.LoadX509KeyPair(n.cfg.TLSCert, n.cfg.TLSKey)
}

func (n *Node) syncUsers() error {
	users, err := n.client.GetUsers()
	if err != nil {
		return err
	}
	var m map[string]int
	if n.useUDP {
		m = n.udpSync(users)
	} else {
		m = n.syncFn(users)
	}
	n.mu.Lock()
	n.emailToID = m
	n.mu.Unlock()
	log.Printf("[INFO] [Node %d] synced %d users", n.cfg.NodeID, len(m))
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

func (n *Node) Stop() {
	n.once.Do(func() {
		close(n.stop)
		if n.ln != nil {
			_ = n.ln.Close()
		}
		if n.udpSrv != nil {
			_ = n.udpSrv.Close()
		}
		if n.pc != nil {
			_ = n.pc.Close()
		}
	})
}

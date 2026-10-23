package panel

import "time"

// PanelClient is the uniform interface every panel implementation satisfies.
// Recovered from the binary: six methods split into pull (node/users) and push
// (node status / traffic / alive-ip).
type PanelClient interface {
	GetNodeID() int
	GetNodeInfo() (*NodeInfo, error)
	GetUsers() ([]*UserInfo, error)
	ReportNodeInfo(status *NodeStatus) error
	ReportTraffic(reports []UserTraffic) error
	ReportAliveIP(reports []AliveIP) error
}

// ProtocolConfig is one protocol listener's configuration pulled from the panel.
type ProtocolConfig struct {
	Type     string            // vmess, vless, trojan, ss, ssr, anytls, hysteria2, tuic, mieru, naive
	Port     int
	Settings map[string]any    // protocol-specific
	Transport map[string]any   // ws/grpc/xhttp/kcp/quic...
	TLS      map[string]any
}

// NodeInfo is the node configuration returned by the panel.
type NodeInfo struct {
	NodeID     int
	SpeedLimit int // mbps, 0 = unlimited
	DeviceLimit int
	Protocols  []ProtocolConfig
	Routes     []string
	ETag       string // for conditional requests
	Raw        []byte // original body (debug)
}

// UserInfo is one account pulled from the panel.
type UserInfo struct {
	ID          int
	Email       string
	UUID        string
	Password    string
	Method      string // ss/ssr cipher
	SpeedLimit  int    // mbps
	DeviceLimit int
	AlterID     int
}

// NodeStatus is the node heartbeat/status payload pushed to the panel.
type NodeStatus struct {
	CPU       float64
	Mem       float64
	Uptime    int64
	Load      float64
	Version   string
}

// UserTraffic is one user's up/down counters pushed to the panel.
type UserTraffic struct {
	UserID   int
	Upload   int64
	Download int64
}

// AliveIP is one online client IP pushed to the panel.
type AliveIP struct {
	UserID int
	IP     string
}

// SchedulerConfig holds the loop intervals and license limits.
type SchedulerConfig struct {
	NodeID          int
	PullInterval    time.Duration // syncLoop
	PushInterval    time.Duration // reportLoop
	HeartbeatEvery  time.Duration
	LicenseMaxUsers int
}

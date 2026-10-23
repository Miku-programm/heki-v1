package license

import (
	"crypto/ed25519"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Mode is the effective license mode.
type Mode string

const (
	ModeOnline  Mode = "online"
	ModeOffline Mode = "offline"
	ModeFree    Mode = "free"
)

// License holds the signed claims (the JSON inside SignedLicense.Payload).
// JSON tags are recovered from the binary's struct metadata.
type License struct {
	LicenseKey             string            `json:"license_key,omitempty"`
	MachineID              string            `json:"machine_id,omitempty"`
	Fingerprint            string            `json:"fingerprint,omitempty"`
	ExpiredAt              time.Time         `json:"expired_at,omitempty"`
	ExpiresAt              time.Time         `json:"expires_at,omitempty"`
	AllowedTypes           []string          `json:"allowed_types,omitempty"`
	SupportedProtocols     []string          `json:"supported_protocols,omitempty"`
	MaxUsers               int               `json:"max_users,omitempty"`
	NodeID                 int               `json:"node_id,omitempty"`
	NodeClass              int               `json:"node_class,omitempty"`
	NodeGroup              int               `json:"node_group,omitempty"`
	NodeConnector          int               `json:"node_connector,omitempty"`
	NodeSpeedLimit         int               `json:"node_speedlimit,omitempty"`
	PanelURL               string            `json:"panel_url,omitempty"`
	ProtocolPanelBindings  map[string]string `json:"protocol_panel_bindings,omitempty"`
	BindingMode            string            `json:"binding_mode,omitempty"`
	LicenseKind            string            `json:"license_kind,omitempty"`
	OfflineGrace           int               `json:"offline_grace,omitempty"`
	Nonce                  string            `json:"nonce,omitempty"`
	Status                 string            `json:"status,omitempty"`
}

// SignedLicense is the wire wrapper: a base64 payload plus its Ed25519 signature.
type SignedLicense struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// LicenseHooks are injected into the panel scheduler (SetLicenseHooks).
type LicenseHooks struct {
	RefreshOnlineIfStale func() error
}

// Manager is the central authorization object. Construct with NewManager,
// NewOfflineManagerWithConstraints, or NewFreeManager.
type Manager struct {
	mu sync.Mutex

	mode       Mode
	machineID  string
	licenseKey string
	panelURL   string
	cacheDir   string

	pubKey  ed25519.PublicKey
	license *License

	// online state
	authURLs   []string
	httpClient *http.Client
	lastOnline time.Time
	permErr    error // permanent online rejection; once set the license is dead
	heartbeat  chan struct{}

	// offline state
	offline     bool
	offlineB64  string
	constraints *OfflineBuildConstraints
}

// NewManager builds an online-first manager. licenseKey/panelURL identify the
// node; cacheDir is where the signed license is cached between runs.
func NewManager(licenseKey, panelURL, cacheDir string) (*Manager, error) {
	pk, err := getPublicKey()
	if err != nil {
		return nil, fmt.Errorf("invalid embedded public key: %w", err)
	}
	fp, err := getMachineFingerprint()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(licenseKey) == "" {
		return nil, fmt.Errorf("license_key not found")
	}
	if strings.TrimSpace(panelURL) == "" {
		return nil, fmt.Errorf("panel_url is required")
	}
	return &Manager{
		mode:       ModeOnline,
		machineID:  fp,
		licenseKey: licenseKey,
		panelURL:   panelURL,
		cacheDir:   cacheDir,
		pubKey:     pk,
		authURLs:   getAuthServerURLs(),
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// NewFreeManager builds a restricted "free" manager with no server license.
func NewFreeManager() *Manager {
	pk, _ := getPublicKey()
	fp, _ := getMachineFingerprint()
	return &Manager{
		mode:      ModeFree,
		machineID: fp,
		pubKey:    pk,
		license:   &License{MaxUsers: 0, AllowedTypes: nil},
	}
}

// Stop halts background work (the heartbeat goroutine).
func (m *Manager) Stop() {
	m.mu.Lock()
	if m.heartbeat != nil {
		close(m.heartbeat)
		m.heartbeat = nil
	}
	m.mu.Unlock()
}

// setLicense stores the verified license under the lock.
func (m *Manager) setLicense(l *License) {
	m.mu.Lock()
	m.license = l
	m.lastOnline = time.Now()
	m.mu.Unlock()
}

// Verify performs the primary license check for the current mode.
func (m *Manager) Verify() error {
	switch m.mode {
	case ModeOffline:
		return m.loadOfflineLicense()
	case ModeFree:
		return nil
	default:
		return m.onlineVerify()
	}
}

// --- capability queries (read by server/features to gate behavior) ---

// GetTier returns the license tier string ("free" when unlicensed).
func (m *Manager) GetTier() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.license == nil {
		return string(ModeFree)
	}
	if m.license.LicenseKind != "" {
		return m.license.LicenseKind
	}
	return string(m.mode)
}

// GetMaxUsers returns the per-node user cap (0 when unlicensed).
func (m *Manager) GetMaxUsers() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.license == nil {
		return 0
	}
	return m.license.MaxUsers
}

// IsOfflineLicense reports whether the active license is an offline one.
func (m *Manager) IsOfflineLicense() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.offline || (m.license != nil && isOfflineLicense(m.license))
}

// HasOfflineProtocolPanelBindings reports whether protocol<->panel bindings exist.
func (m *Manager) HasOfflineProtocolPanelBindings() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.license != nil && len(m.license.ProtocolPanelBindings) > 0
}

// IsTypeAllowed reports whether a protocol type may run under the active license.
func (m *Manager) IsTypeAllowed(protocol string) bool {
	m.mu.Lock()
	lic := m.license
	m.mu.Unlock()
	return isTypeAllowedForLicense(lic, protocol)
}

// isTypeAllowedForLicense checks allowed_types/supported_protocols for a license.
// A nil license or an empty allow-list denies everything.
func isTypeAllowedForLicense(l *License, protocol string) bool {
	if l == nil {
		return false
	}
	want := strings.ToLower(strings.TrimSpace(NormalizeLicenseType(protocol)))
	list := l.AllowedTypes
	if len(list) == 0 {
		list = l.SupportedProtocols
	}
	if len(list) == 0 {
		return false
	}
	for _, t := range list {
		if strings.ToLower(strings.TrimSpace(NormalizeLicenseType(t))) == want {
			return true
		}
	}
	return false
}

// ResolveEffectiveMode decides online vs offline from an explicit mode string,
// falling back to the license kind.
func ResolveEffectiveMode(defaultMode, licenseKind, explicit string) (Mode, error) {
	s := strings.TrimSpace(explicit)
	if s == "" {
		s = strings.TrimSpace(defaultMode)
	}
	switch strings.ToLower(s) {
	case "", "auto":
		if strings.EqualFold(strings.TrimSpace(licenseKind), string(ModeOffline)) {
			return ModeOffline, nil
		}
		return ModeOnline, nil
	case string(ModeOnline):
		return ModeOnline, nil
	case string(ModeOffline):
		return ModeOffline, nil
	case string(ModeFree):
		return ModeFree, nil
	default:
		return "", fmt.Errorf("unknown license mode %q", s)
	}
}

// formatExpiry renders an expiry timestamp for log/error messages.
func formatExpiry(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Format(time.RFC3339)
}

// expiry returns the effective expiry (expired_at preferred, else expires_at).
func (l *License) expiry() time.Time {
	if !l.ExpiredAt.IsZero() {
		return l.ExpiredAt
	}
	return l.ExpiresAt
}

// NormalizeLicenseType lower-cases and trims a protocol/type token.
func NormalizeLicenseType(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// NormalizeLicenseTypes normalizes and de-duplicates a list of type tokens.
func NormalizeLicenseTypes(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		n := NormalizeLicenseType(s)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

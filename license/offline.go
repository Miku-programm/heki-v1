package license

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// OfflineBuildConstraints binds an offline license to a specific build so a
// license issued for one build cannot be reused with another.
type OfflineBuildConstraints struct {
	BindingMode string `json:"binding_mode,omitempty"`
	LicenseKind string `json:"license_kind,omitempty"`
	BuildID     string `json:"build_id,omitempty"`
	enabled     bool
}

// Enabled reports whether build-constraint checking is active.
func (c *OfflineBuildConstraints) Enabled() bool { return c != nil && c.enabled }

func normalizeOfflineBuildConstraints(c *OfflineBuildConstraints) *OfflineBuildConstraints {
	if c == nil {
		return nil
	}
	n := *c
	n.BindingMode = strings.TrimSpace(n.BindingMode)
	n.LicenseKind = strings.TrimSpace(n.LicenseKind)
	n.enabled = n.BindingMode != "" || n.LicenseKind != "" || n.BuildID != ""
	return &n
}

// NewOfflineManagerWithConstraints builds an offline manager whose license file
// is self-contained (validated by signature) and bound to the given build.
func NewOfflineManagerWithConstraints(licenseB64, cacheDir string, c *OfflineBuildConstraints) (*Manager, error) {
	pk, err := getPublicKey()
	if err != nil {
		return nil, fmt.Errorf("invalid embedded public key: %w", err)
	}
	fp, err := getMachineFingerprint()
	if err != nil {
		return nil, err
	}
	m := &Manager{
		mode:        ModeOffline,
		offline:     true,
		machineID:   fp,
		cacheDir:    cacheDir,
		pubKey:      pk,
		constraints: normalizeOfflineBuildConstraints(c),
	}
	m.offlineB64 = licenseB64
	return m, nil
}

// loadOfflineLicense decodes, signature-verifies and validates the embedded
// offline license, then stores it.
func (m *Manager) loadOfflineLicense() error {
	l, err := ValidateOfflinePayload(m.pubKey, m.offlineB64)
	if err != nil {
		return fmt.Errorf("offline license init failed: %w", err)
	}
	if err := VerifyOfflineKeyBinding(l, m.licenseKey); err != nil {
		return err
	}
	if err := VerifyOfflineBuildConstraints(l, m.constraints); err != nil {
		return err
	}
	m.setLicense(l)
	return nil
}

// ValidateOfflinePayload verifies a base64-wrapped SignedLicense with the
// embedded key and returns its claims. Requires license_kind == "offline".
func ValidateOfflinePayload(pub []byte, licenseB64 string) (*License, error) {
	raw, err := decodeBase64String(licenseB64)
	if err != nil {
		return nil, fmt.Errorf("offline payload validation failed: %w", err)
	}
	var sl SignedLicense
	if err := json.Unmarshal(raw, &sl); err != nil {
		return nil, fmt.Errorf("offline payload validation failed: %w", err)
	}
	m := &Manager{pubKey: pub}
	l, err := m.verifySignedLicense(&sl)
	if err != nil {
		return nil, fmt.Errorf("offline payload validation failed: %w", err)
	}
	if !isOfflineLicense(l) {
		return nil, fmt.Errorf("offline license_kind must be %q", string(ModeOffline))
	}
	return l, nil
}

// isOfflineLicense reports whether a license declares license_kind "offline".
func isOfflineLicense(l *License) bool {
	return l != nil && strings.EqualFold(strings.TrimSpace(l.LicenseKind), string(ModeOffline))
}

// VerifyOfflineKeyBinding checks the license is bound to the configured key.
func VerifyOfflineKeyBinding(l *License, licenseKey string) error {
	if licenseKey != "" && l.LicenseKey != "" && l.LicenseKey != licenseKey {
		return fmt.Errorf("offline binding validation failed: %w", fmt.Errorf("license key mismatch"))
	}
	return nil
}

// VerifyOfflineBuildConstraints enforces binding_mode / license_kind against the
// build constraints when they are enabled.
func VerifyOfflineBuildConstraints(l *License, c *OfflineBuildConstraints) error {
	if !c.Enabled() {
		return nil
	}
	if c.LicenseKind != "" && !strings.EqualFold(l.LicenseKind, c.LicenseKind) {
		return fmt.Errorf("offline build binding validation failed: %w",
			fmt.Errorf("offline license_kind must be %q", c.LicenseKind))
	}
	if c.BindingMode != "" && !strings.EqualFold(l.BindingMode, c.BindingMode) {
		return fmt.Errorf("offline build binding validation failed: %w",
			fmt.Errorf("offline binding_mode must be %q", c.BindingMode))
	}
	return nil
}

// RevalidateOfflineRuntime is the offline runtime guard (node bootstrap / before
// server start). It re-checks payload validity, key/build binding, expiry and
// protocol allowance; any failure blocks the node.
func (m *Manager) RevalidateOfflineRuntime() error {
	m.mu.Lock()
	l := m.license
	m.mu.Unlock()
	if l == nil || !isOfflineLicense(l) {
		return nil
	}
	if _, err := ValidateOfflinePayload(m.pubKey, m.offlineB64); err != nil {
		return err
	}
	if err := VerifyOfflineKeyBinding(l, m.licenseKey); err != nil {
		return err
	}
	if err := VerifyOfflineBuildConstraints(l, m.constraints); err != nil {
		return err
	}
	if exp := l.expiry(); !exp.IsZero() && time.Now().After(exp) {
		return fmt.Errorf("offline license expired at %s", formatExpiry(exp))
	}
	return nil
}

// RevalidateOfflineNodeRuntime re-checks after node config resolution.
func (m *Manager) RevalidateOfflineNodeRuntime(nodeID int) error {
	return m.RevalidateOfflineRuntime()
}

// RevalidateOfflineProtocolRuntime re-checks per-protocol allowance before the
// server starts a given protocol listener.
func (m *Manager) RevalidateOfflineProtocolRuntime(protocol, panelURL string) error {
	m.mu.Lock()
	l := m.license
	m.mu.Unlock()
	if l == nil {
		return fmt.Errorf("offline license requires protocol %q", protocol)
	}
	if !isTypeAllowedForLicense(l, protocol) {
		return fmt.Errorf("offline license does not allow server_type=%s", protocol)
	}
	if len(l.ProtocolPanelBindings) > 0 {
		if err := VerifyOfflineProtocolPanelBinding(l, protocol, panelURL); err != nil {
			return err
		}
	}
	return nil
}

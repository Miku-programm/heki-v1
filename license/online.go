package license

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Auth-server endpoints (failover), recovered from the binary.
const (
	authURLWorker = "https://heki-auth.jsdelcdn.workers.dev/api/v1/license"
	authURLDeno   = "https://slow-hare-84.hekicore.deno.net/api/v1/license"
)

func getAuthServerURLs() []string {
	return []string{authURLWorker, authURLDeno}
}

// onlineOfflineGraceDuration is how long a cached license keeps the node alive
// when the auth server is temporarily unreachable.
const onlineOfflineGraceDuration = 72 * time.Hour

// onlineAuthError distinguishes server responses; permanent ones kill the
// license immediately, temporary ones fall back to the grace window.
type onlineAuthError struct {
	permanent bool
	status    string
	err       error
}

func (e *onlineAuthError) Error() string {
	if e.status != "" {
		return fmt.Sprintf("online auth error (%s): %v", e.status, e.err)
	}
	return fmt.Sprintf("online auth error: %v", e.err)
}

func (e *onlineAuthError) Unwrap() error { return e.err }

// isPermanentOnlineRejection reports whether an error means the server
// definitively refused the license (revoked / invalid), vs a transient failure.
func isPermanentOnlineRejection(err error) bool {
	var ae *onlineAuthError
	if errors.As(err, &ae) {
		return ae.permanent
	}
	return false
}

// setPermanentOnlineError records a terminal rejection; once set the license is
// considered dead regardless of cache.
func (m *Manager) setPermanentOnlineError(err error) {
	m.mu.Lock()
	m.permErr = err
	m.license = nil
	m.mu.Unlock()
}

// onlineVerify POSTs {machine_id, license_key, panel_url} to the auth servers,
// verifies the returned signed license, validates its bindings, then caches it.
// On a temporary failure it falls back to the on-disk cache within the grace
// window; a permanent rejection fails hard.
func (m *Manager) onlineVerify() error {
	m.mu.Lock()
	if m.permErr != nil {
		err := m.permErr
		m.mu.Unlock()
		return err
	}
	m.mu.Unlock()

	signed, err := m.fetchSignedLicense()
	if err != nil {
		if isPermanentOnlineRejection(err) {
			m.setPermanentOnlineError(err)
			return err
		}
		// temporary: fall back to cache within grace
		if l, cErr := m.loadCachedLicense(); cErr == nil {
			if time.Since(m.lastOnline) <= onlineOfflineGraceDuration {
				m.setLicense(l)
				return nil
			}
		}
		return fmt.Errorf("license verification failed: %w", err)
	}

	l, err := m.verifySignedLicense(signed)
	if err != nil {
		return err
	}
	if err := m.validateBinding(m.expectedBinding(), l); err != nil {
		return err
	}
	if exp := l.expiry(); !exp.IsZero() && time.Now().After(exp) {
		return fmt.Errorf("license expired at %s", formatExpiry(exp))
	}
	m.setLicense(l)
	_ = m.cacheLicense(l)
	return nil
}

// fetchSignedLicense tries each auth URL until one returns a signed license.
func (m *Manager) fetchSignedLicense() (*SignedLicense, error) {
	reqBody, _ := json.Marshal(map[string]string{
		"machine_id":  m.machineID,
		"license_key": m.licenseKey,
		"panel_url":   m.panelURL,
	})
	var lastErr error
	for _, url := range m.authURLs {
		resp, err := m.httpClient.Post(url, "application/json", bytes.NewReader(reqBody))
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
			// server definitively refused -> permanent
			return nil, &onlineAuthError{permanent: true, status: resp.Status, err: fmt.Errorf("%s", strings.TrimSpace(string(body)))}
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = &onlineAuthError{status: resp.Status, err: fmt.Errorf("%s", resp.Status)}
			continue
		}
		var sl SignedLicense
		if err := json.Unmarshal(body, &sl); err != nil {
			lastErr = fmt.Errorf("unmarshal license: %w", err)
			continue
		}
		return &sl, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no auth server reachable")
	}
	return nil, lastErr
}

// verifySignedLicense base64-decodes the payload and signature, verifies the
// Ed25519 signature over the raw payload bytes with the embedded public key,
// and only then unmarshals the payload JSON. Verify-before-parse.
func (m *Manager) verifySignedLicense(sl *SignedLicense) (*License, error) {
	payload, err := decodeBase64String(sl.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	sig, err := decodeBase64String(sl.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(m.pubKey, payload, sig) {
		return nil, fmt.Errorf("Ed25519 signature invalid")
	}
	var l License
	if err := json.Unmarshal(payload, &l); err != nil {
		return nil, fmt.Errorf("unmarshal license: %w", err)
	}
	return &l, nil
}

// expectedBinding is the local view (what this node must match): license key,
// machine fingerprint and panel URL.
func (m *Manager) expectedBinding() *License {
	return &License{
		LicenseKey:  m.licenseKey,
		Fingerprint: m.machineID,
		MachineID:   m.machineID,
		PanelURL:    m.panelURL,
	}
}

// validateBinding enforces three equality checks in order: license key,
// machine fingerprint, then normalized panel domain. Each has a distinct error.
func (m *Manager) validateBinding(expected, got *License) error {
	if expected.LicenseKey != got.LicenseKey {
		return fmt.Errorf("license key mismatch")
	}
	gotFP := got.Fingerprint
	if gotFP == "" {
		gotFP = got.MachineID
	}
	if expected.Fingerprint != gotFP {
		return fmt.Errorf("machine fingerprint mismatch (license bound to different machine)")
	}
	if normalizePanelURL(expected.PanelURL) != normalizePanelURL(got.PanelURL) {
		return fmt.Errorf("panel domain mismatch: license bound to different panel")
	}
	return nil
}

// RevalidateOnlineRuntime is the online runtime guard: it refreshes the license
// if stale and fails if the server has permanently rejected it.
func (m *Manager) RevalidateOnlineRuntime() error {
	if err := m.RefreshOnlineIfStale(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.permErr != nil {
		return m.permErr
	}
	if m.license == nil {
		return fmt.Errorf("license not loaded")
	}
	if exp := m.license.expiry(); !exp.IsZero() && time.Now().After(exp) {
		return fmt.Errorf("license expired at %s", formatExpiry(exp))
	}
	return nil
}

// RefreshOnlineIfStale re-runs online verification if the last success is older
// than the grace window.
func (m *Manager) RefreshOnlineIfStale() error {
	m.mu.Lock()
	stale := time.Since(m.lastOnline) > onlineOfflineGraceDuration/2
	m.mu.Unlock()
	if !stale {
		return nil
	}
	return m.onlineVerify()
}

// StartHeartbeat launches a goroutine that periodically re-verifies online, so
// the server can revoke the license remotely.
func (m *Manager) StartHeartbeat(interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	m.mu.Lock()
	if m.heartbeat != nil {
		m.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	m.heartbeat = stop
	m.mu.Unlock()

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if err := m.onlineVerify(); err != nil && isPermanentOnlineRejection(err) {
					return
				}
			}
		}
	}()
}

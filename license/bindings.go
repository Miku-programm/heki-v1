package license

import (
	"fmt"
	"net/url"
	"strings"
)

// normalizePanelURL reduces a panel URL to a comparable host form (scheme and
// path stripped, lower-cased host), so binding comparison is robust to trailing
// slashes and scheme differences.
func normalizePanelURL(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return strings.ToLower(strings.TrimRight(raw, "/"))
	}
	return strings.ToLower(u.Host)
}

// NormalizeAndValidatePanelBindingURL normalizes a binding URL and rejects empties.
func NormalizeAndValidatePanelBindingURL(raw string) (string, error) {
	n := normalizePanelURL(raw)
	if n == "" {
		return "", fmt.Errorf("panel_url is required")
	}
	return n, nil
}

// isWildcardProtocolBindingKey reports whether a binding key matches all
// protocols ("*" or empty).
func isWildcardProtocolBindingKey(key string) bool {
	k := strings.TrimSpace(key)
	return k == "" || k == "*"
}

// normalizeProtocolBindings lower-cases keys and normalizes URL values.
func normalizeProtocolBindings(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[strings.ToLower(strings.TrimSpace(k))] = normalizePanelURL(v)
	}
	return out
}

// NormalizeProtocolPanelBindings is the exported normalizer.
func NormalizeProtocolPanelBindings(in map[string]string) map[string]string {
	return normalizeProtocolBindings(in)
}

// normalizePanelBindingURLList normalizes and de-dupes a list of binding URLs.
func normalizePanelBindingURLList(in []string) []string {
	return normalizeBindingValueList(in)
}

func normalizeBindingValueList(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		n := normalizePanelURL(s)
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

// VerifyOfflineProtocolPanelBinding checks that a protocol is bound to the given
// panel, honoring a wildcard binding. Absent bindings allow everything.
func VerifyOfflineProtocolPanelBinding(l *License, protocol, panelURL string) error {
	if l == nil || len(l.ProtocolPanelBindings) == 0 {
		return nil
	}
	want := normalizePanelURL(panelURL)
	key := strings.ToLower(strings.TrimSpace(NormalizeLicenseType(protocol)))
	if bound, ok := l.ProtocolPanelBindings[key]; ok {
		if normalizePanelURL(bound) == want {
			return nil
		}
		return fmt.Errorf("offline license missing protocol %q for panel", protocol)
	}
	for k, bound := range l.ProtocolPanelBindings {
		if isWildcardProtocolBindingKey(k) && normalizePanelURL(bound) == want {
			return nil
		}
	}
	return fmt.Errorf("offline license requires protocol %q", protocol)
}

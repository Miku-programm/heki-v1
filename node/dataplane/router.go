package dataplane

import (
	"math/rand"
	"strings"
)

// Outbound is one egress target (a [[routes.Outs]] entry). Only the fields the
// data-plane dialer acts on are kept; unknown proxy types are preserved so the
// dialer can report them honestly.
type Outbound struct {
	Type   string // direct / block / redirect / socks / http / trojan / vless
	Listen string // egress source IP to bind ("", a specific IP, or "auto")
	Server string // proxy/redirect target host
	Port   int    // proxy/redirect target port
	User   string // socks/http auth
	Pass   string // socks/http auth

	// proxy-outbound (chained) fields
	Password       string // trojan password
	UUID           string // vless uuid
	SNI            string // TLS server name
	Flow           string // vless flow (e.g. xtls-rprx-vision)
	SkipCertVerify bool
}

func (o *Outbound) normalizedType() string {
	switch strings.ToLower(strings.TrimSpace(o.Type)) {
	case "freedom", "direct", "":
		return "direct"
	case "reject", "block":
		return "block"
	case "socks5", "socks":
		return "socks"
	case "redirect":
		return "redirect"
	case "http":
		return "http"
	default:
		return strings.ToLower(strings.TrimSpace(o.Type))
	}
}

// Route is one [[routes]] block: a rule list and one or more outbounds (a random
// one is chosen on match).
type Route struct {
	Rules []string
	Outs  []Outbound
}

// Router applies routes.toml-style rules. When Enabled is true and no route
// matches, the connection is closed (heki semantics); when Enabled is false the
// dialer falls back to direct.
type Router struct {
	Enabled bool
	Routes  []Route
	rnd     func(n int) int
}

// NewRouter builds a router.
func NewRouter(enabled bool, routes []Route) *Router {
	return &Router{Enabled: enabled, Routes: routes, rnd: rand.Intn}
}

// Match returns the chosen outbound for a target, and whether a route matched.
// With Enabled==false it always returns a direct outbound (matched=true).
func (r *Router) Match(t Target) (Outbound, bool) {
	if r == nil || !r.Enabled {
		return Outbound{Type: "direct"}, true
	}
	for _, route := range r.Routes {
		if matchAny(route.Rules, t) {
			if len(route.Outs) == 0 {
				return Outbound{Type: "direct"}, true
			}
			idx := 0
			if len(route.Outs) > 1 {
				idx = r.rnd(len(route.Outs))
			}
			return route.Outs[idx], true
		}
	}
	return Outbound{}, false // no match -> caller closes the connection
}

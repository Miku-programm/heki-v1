// Package dataplane implements heki's node data-plane features on top of the
// reconstruction: rule-based routing to multiple outbounds (routes.toml),
// source-in-source-out egress binding (auto_out_ip), DNS rules (dns.yml),
// domain access auditing (JSONL), and PROXY-protocol real-IP recovery. The
// rule-matching syntax mirrors heki's (domain:/full:/ip:/port:/node_id:/geosite
// :/regexp:/cidr:/glob:/bare-substring/*).
package dataplane

import (
	"net"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// Target is what a rule is matched against.
type Target struct {
	Host   string // domain (may be empty if only IP is known)
	IP     net.IP // resolved/literal IP (may be nil)
	Port   int
	NodeID int
}

// matchRule reports whether a single heki rule matches the target. Unsupported
// predicates that need external data files (geosite:/geoip:) return false.
func matchRule(rule string, t Target) bool {
	rule = strings.TrimSpace(rule)
	if rule == "" {
		return false
	}
	if rule == "*" {
		return true
	}
	kind, val, has := strings.Cut(rule, ":")
	kind = strings.ToLower(strings.TrimSpace(kind))
	if !has || !knownPrefix[kind] {
		return matchBare(rule, t)
	}
	val = strings.TrimSpace(val)
	switch kind {
	case "domain", "domain-suffix", "domain_suffix":
		// domain and all subdomains
		h := t.Host
		return h == val || strings.HasSuffix(h, "."+val)
	case "domain-keyword", "domain_keyword":
		return t.Host != "" && strings.Contains(t.Host, val)
	case "full":
		return t.Host == val
	case "regexp", "regex":
		re, err := regexp.Compile(val)
		return err == nil && (re.MatchString(t.Host) || re.MatchString(hostPort(t)))
	case "glob":
		ok, _ := path.Match(val, t.Host)
		if !ok {
			ok, _ = path.Match(val, hostPort(t))
		}
		return ok
	case "ip", "cidr":
		return matchIP(val, t.IP)
	case "port":
		return matchPort(val, t.Port)
	case "node_id", "node-id":
		return matchNodeID(val, t.NodeID)
	case "geosite", "geoip":
		return false // needs geosite.dat / geoip.dat; not bundled
	default:
		return false
	}
}

var knownPrefix = map[string]bool{
	"domain": true, "domain-suffix": true, "domain_suffix": true,
	"domain-keyword": true, "domain_keyword": true, "full": true,
	"regexp": true, "regex": true, "glob": true, "ip": true, "cidr": true,
	"port": true, "node_id": true, "node-id": true, "geosite": true, "geoip": true,
}

// matchBare handles heki's unprefixed rule shorthands: IP, CIDR, host:port /
// ip:port, or a domain substring.
func matchBare(rule string, t Target) bool {
	if ip := net.ParseIP(rule); ip != nil {
		return t.IP != nil && t.IP.Equal(ip)
	}
	if strings.Contains(rule, "/") {
		if _, cidr, err := net.ParseCIDR(rule); err == nil {
			return t.IP != nil && cidr.Contains(t.IP)
		}
	}
	if h, p, err := net.SplitHostPort(rule); err == nil && h != "" {
		if !portEq(p, t.Port) {
			return false
		}
		if hip := net.ParseIP(h); hip != nil {
			return t.IP != nil && t.IP.Equal(hip)
		}
		return t.Host != "" && strings.Contains(t.Host, h)
	}
	return t.Host != "" && strings.Contains(t.Host, rule)
}

func portEq(s string, port int) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n == port
}

func hostPort(t Target) string {
	h := t.Host
	if h == "" && t.IP != nil {
		h = t.IP.String()
	}
	if t.Port == 0 {
		return h
	}
	return net.JoinHostPort(h, strconv.Itoa(t.Port))
}

func matchIP(val string, ip net.IP) bool {
	if ip == nil {
		return false
	}
	if strings.Contains(val, "/") {
		_, cidr, err := net.ParseCIDR(val)
		return err == nil && cidr.Contains(ip)
	}
	other := net.ParseIP(val)
	return other != nil && other.Equal(ip)
}

func matchPort(val string, port int) bool {
	if port == 0 {
		return false
	}
	for _, part := range strings.Split(val, ",") {
		part = strings.TrimSpace(part)
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			l, e1 := strconv.Atoi(strings.TrimSpace(lo))
			h, e2 := strconv.Atoi(strings.TrimSpace(hi))
			if e1 == nil && e2 == nil && port >= l && port <= h {
				return true
			}
			continue
		}
		if n, err := strconv.Atoi(part); err == nil && n == port {
			return true
		}
	}
	return false
}

func matchNodeID(val string, nodeID int) bool {
	for _, part := range strings.Split(val, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(part)); err == nil && n == nodeID {
			return true
		}
	}
	return false
}

// matchAny reports whether any rule in the list matches.
func matchAny(rules []string, t Target) bool {
	for _, r := range rules {
		if matchRule(r, t) {
			return true
		}
	}
	return false
}

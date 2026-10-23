package dataplane

import (
	"context"
	"net"
	"strings"
	"time"
)

// DNSRule maps a set of domain rules to an ordered DNS server list and a
// resolution strategy (ipv4_first / ipv4_only / ipv6_first / ipv6_only).
type DNSRule struct {
	Servers  []string // e.g. "8.8.8.8", "8.8.8.8:5353", "tcp://1.1.1.1"
	Strategy string
	Rules    []string // domain rules only
}

// Resolver resolves hostnames using heki's dns.yml precedence:
// matched DNS rule > default DNS > system resolver.
type Resolver struct {
	Rules      []DNSRule
	DefaultDNS []string
	Strategy   string // default strategy when a rule omits one
	dialTO     time.Duration
}

// NewResolver builds a resolver.
func NewResolver(rules []DNSRule, defaultDNS []string, strategy string) *Resolver {
	if strategy == "" {
		strategy = "ipv4_first"
	}
	return &Resolver{Rules: rules, DefaultDNS: defaultDNS, Strategy: strategy, dialTO: 5 * time.Second}
}

// Resolve returns the IPs for host, honoring the matched DNS rule's servers and
// strategy, then default DNS, then the system resolver.
func (r *Resolver) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	servers, strategy := r.pick(host)
	if len(servers) > 0 {
		if ips, err := r.resolveVia(ctx, servers, host); err == nil && len(ips) > 0 {
			return orderByStrategy(ips, strategy), nil
		}
	}
	// fall back to the system resolver
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return orderByStrategy(ips, strategy), nil
}

func (r *Resolver) pick(host string) (servers []string, strategy string) {
	t := Target{Host: host}
	for _, rule := range r.Rules {
		if matchAny(rule.Rules, t) {
			s := rule.Strategy
			if s == "" {
				s = r.Strategy
			}
			return rule.Servers, s
		}
	}
	return r.DefaultDNS, r.Strategy
}

func (r *Resolver) resolveVia(ctx context.Context, servers []string, host string) ([]net.IP, error) {
	var lastErr error
	for _, s := range servers {
		network, addr := parseDNSAddr(s)
		res := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: r.dialTO}
				return d.DialContext(ctx, network, addr)
			},
		}
		addrs, err := res.LookupIPAddr(ctx, host)
		if err != nil {
			lastErr = err
			continue
		}
		ips := make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
		if len(ips) > 0 {
			return ips, nil
		}
	}
	return nil, lastErr
}

// parseDNSAddr parses a heki DNS address into a (network, host:port) pair.
// Supports plain (udp:53), tcp://, and (best-effort) tcp-tls:// as tcp.
func parseDNSAddr(s string) (network, addr string) {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "tcp://"):
		return "tcp", withDefaultPort(strings.TrimPrefix(s, "tcp://"), "53")
	case strings.HasPrefix(s, "tcp-tls://"):
		return "tcp", withDefaultPort(strings.TrimPrefix(s, "tcp-tls://"), "853")
	case strings.HasPrefix(s, "https://"):
		// DoH is not implemented on the custom path; fall back to udp:53 of host
		h := strings.TrimPrefix(s, "https://")
		if i := strings.IndexByte(h, '/'); i >= 0 {
			h = h[:i]
		}
		return "udp", withDefaultPort(h, "53")
	default:
		return "udp", withDefaultPort(s, "53")
	}
}

func withDefaultPort(hostport, def string) string {
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	return net.JoinHostPort(hostport, def)
}

func orderByStrategy(ips []net.IP, strategy string) []net.IP {
	var v4, v6 []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	switch strings.ToLower(strategy) {
	case "ipv4_only":
		return v4
	case "ipv6_only":
		return v6
	case "ipv6_first":
		return append(v6, v4...)
	default: // ipv4_first
		return append(v4, v6...)
	}
}

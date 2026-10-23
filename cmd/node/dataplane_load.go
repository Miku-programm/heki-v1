package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"heki/node"
	"heki/node/dataplane"
)

// --- routes.toml ---

type tomlOutbound struct {
	Type     string `toml:"type"`
	Listen   string `toml:"listen"`
	Server   string `toml:"server"`
	Port     int    `toml:"port"`
	Username string `toml:"username"`
	Password string `toml:"password"`
}

type tomlRoute struct {
	Rules []string       `toml:"rules"`
	Outs  []tomlOutbound `toml:"Outs"`
}

type tomlRoutes struct {
	Enable bool        `toml:"enable"`
	Routes []tomlRoute `toml:"routes"`
}

// loadRoutes parses a routes.toml file into router config. A missing file is not
// an error (returns enabled=false).
func loadRoutes(path string) (enabled bool, routes []dataplane.Route, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil, nil
		}
		return false, nil, err
	}
	var cfg tomlRoutes
	if err := toml.Unmarshal(b, &cfg); err != nil {
		return false, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for _, r := range cfg.Routes {
		outs := make([]dataplane.Outbound, 0, len(r.Outs))
		for _, o := range r.Outs {
			outs = append(outs, dataplane.Outbound{
				Type: o.Type, Listen: o.Listen, Server: o.Server,
				Port: o.Port, User: o.Username, Pass: o.Password,
			})
		}
		routes = append(routes, dataplane.Route{Rules: r.Rules, Outs: outs})
	}
	return cfg.Enable, routes, nil
}

// --- dns.yml ---

// loadDNSRules parses a heki dns.yml file. Each top-level key is a
// comma-separated DNS server list; its value is either {strategy, rules} or a
// bare list of rules. A missing file is not an error.
func loadDNSRules(path string) ([]dataplane.DNSRule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var top yaml.Node
	if err := yaml.Unmarshal(b, &top); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(top.Content) == 0 || top.Content[0].Kind != yaml.MappingNode {
		return nil, nil
	}
	mapping := top.Content[0]
	var rules []dataplane.DNSRule
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		servers := splitCSV(mapping.Content[i].Value)
		val := mapping.Content[i+1]

		var r dataplane.DNSRule
		r.Servers = servers
		switch val.Kind {
		case yaml.SequenceNode: // bare list of rules
			_ = val.Decode(&r.Rules)
		case yaml.MappingNode:
			var sr struct {
				Strategy string   `yaml:"strategy"`
				Rules    []string `yaml:"rules"`
			}
			_ = val.Decode(&sr)
			r.Strategy = sr.Strategy
			r.Rules = sr.Rules
		}
		if len(r.Rules) > 0 {
			rules = append(rules, r)
		}
	}
	return rules, nil
}

// buildDataplane assembles the node DataplaneConfig from heki.conf-style fields
// plus the native routes.toml / dns.yml files. Returns nil when nothing is
// configured.
func buildDataplane(fc fileConfig, routesCLI, dnsCLI string) *node.DataplaneConfig {
	routesPath := firstNonEmpty(routesCLI, fc.RoutesFile, "routes.toml")
	dnsPath := firstNonEmpty(dnsCLI, fc.DNSRulesFile, "dns.yml")

	enabled, routes, err := loadRoutes(routesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] routes: %v\n", err)
	}
	dnsRules, err := loadDNSRules(dnsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] dns rules: %v\n", err)
	}

	dp := &node.DataplaneConfig{
		RoutesEnabled:      enabled,
		Routes:             routes,
		DNSRules:           dnsRules,
		DefaultDNS:         splitCSV(fc.DefaultDNS),
		DNSStrategy:        fc.DNSStrategy,
		AutoOutIP:          fc.AutoOutIP,
		AuditEnable:        fc.DomainAuditEnable,
		AuditDomains:       splitCSV(fc.DomainAuditDomains),
		AuditDir:           fc.DomainAuditLogDir,
		AuditRetentionDays: fc.DomainAuditRetentionDay,
		ProxyProtocol:      fc.ProxyProtocol,
		ForceProxyProtocol: fc.ForceProxyProtocol,
	}
	// nothing configured?
	if !dp.RoutesEnabled && len(dp.Routes) == 0 && len(dp.DNSRules) == 0 &&
		len(dp.DefaultDNS) == 0 && !dp.AutoOutIP && !dp.AuditEnable && !dp.ProxyProtocol {
		return nil
	}
	return dp
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

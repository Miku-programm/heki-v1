package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRoutesTOML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "routes.toml")
	os.WriteFile(p, []byte(`
enable=true

[[routes]]
rules=["domain:block.me"]
[[routes.Outs]]
type="block"

[[routes]]
rules=["geosite:netflix", "port:443"]
[[routes.Outs]]
type="socks"
server="proxy.example.com"
port=1080
username="u"
password="p"

[[routes]]
rules=["*"]
[[routes.Outs]]
type="direct"
listen="1.2.3.4"
`), 0o644)

	enabled, routes, err := loadRoutes(p)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled || len(routes) != 3 {
		t.Fatalf("enabled=%v routes=%d", enabled, len(routes))
	}
	if routes[0].Outs[0].Type != "block" {
		t.Fatalf("route0: %+v", routes[0])
	}
	if routes[1].Outs[0].Type != "socks" || routes[1].Outs[0].Server != "proxy.example.com" ||
		routes[1].Outs[0].Port != 1080 || routes[1].Outs[0].User != "u" {
		t.Fatalf("route1 outbound: %+v", routes[1].Outs[0])
	}
	if routes[2].Outs[0].Listen != "1.2.3.4" {
		t.Fatalf("route2 listen: %+v", routes[2].Outs[0])
	}

	// missing file is not an error
	if en, r, err := loadRoutes(filepath.Join(dir, "nope.toml")); err != nil || en || r != nil {
		t.Fatalf("missing file: en=%v r=%v err=%v", en, r, err)
	}
}

func TestLoadDNSYAML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dns.yml")
	os.WriteFile(p, []byte(`
8.8.8.8:53,1.1.1.1:
  strategy: ipv4_first
  rules:
    - domain:google.com
    - regexp:.*facebook\.com

1.1.1.1:
  - domain:youtube.com
`), 0o644)

	rules, err := loadDNSRules(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("rules=%d: %+v", len(rules), rules)
	}
	if len(rules[0].Servers) != 2 || rules[0].Servers[0] != "8.8.8.8:53" || rules[0].Strategy != "ipv4_first" {
		t.Fatalf("rule0: %+v", rules[0])
	}
	if len(rules[0].Rules) != 2 {
		t.Fatalf("rule0 rules: %+v", rules[0].Rules)
	}
	if len(rules[1].Servers) != 1 || rules[1].Rules[0] != "domain:youtube.com" {
		t.Fatalf("rule1 (bare list): %+v", rules[1])
	}
}

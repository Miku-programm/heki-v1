// Command node runs a minimal trojan-over-TLS proxy node against a billing
// panel, reconstructed from heki.
//
//	go build -o heki-node ./cmd/node
//	./heki-node -c config.json
//
// config.json:
//
//	{
//	  "panel_type": "sspanel",
//	  "panel_url":  "https://panel.example.com",
//	  "panel_key":  "mukey",
//	  "node_id":    1,
//	  "listen":     ":443",
//	  "tls_cert":   "/etc/heki/certs/fullchain.pem",
//	  "tls_key":    "/etc/heki/certs/privkey.pem",
//	  "fallback_host": "www.bing.com",
//	  "fallback_port": 443,
//	  "sync_interval_sec":   60,
//	  "report_interval_sec": 30
//	}
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"heki/node"
	"heki/server/proto/trojan"
	"heki/transport/realityx"
)

type realityFileConfig struct {
	PrivateKey  string   `json:"private_key"` // hex-encoded 32-byte x25519 key
	Dest        string   `json:"dest"`        // borrowed TLS 1.3 site, host:port
	ServerNames []string `json:"server_names"`
	ShortIDs    []string `json:"short_ids"` // hex
}

type fileConfig struct {
	Protocol          string               `json:"protocol"`
	Method            string               `json:"method"`
	PanelType         string               `json:"panel_type"`
	PanelURL          string               `json:"panel_url"`
	PanelKey          string               `json:"panel_key"`
	NodeID            int                  `json:"node_id"`
	Listen            string               `json:"listen"`
	TLSCert           string               `json:"tls_cert"`
	TLSKey            string               `json:"tls_key"`
	FallbackHost      string               `json:"fallback_host"`
	FallbackPort      int                  `json:"fallback_port"`
	SyncIntervalSec   int                  `json:"sync_interval_sec"`
	ReportIntervalSec int                  `json:"report_interval_sec"`
	Reality           *realityFileConfig   `json:"reality"`
	Hysteria2         *hysteria2FileConfig `json:"hysteria2"`
	TUIC              *tuicFileConfig      `json:"tuic"`

	// data plane (heki.conf-style)
	RoutesFile              string `json:"routes_file"`
	DNSRulesFile            string `json:"dns_rules_file"`
	DefaultDNS              string `json:"default_dns"` // comma-separated
	DNSStrategy             string `json:"dns_strategy"`
	AutoOutIP               bool   `json:"auto_out_ip"`
	ProxyProtocol           bool   `json:"proxy_protocol"`
	ForceProxyProtocol      bool   `json:"force_proxy_protocol"`
	DomainAuditEnable       bool   `json:"domain_audit_enable"`
	DomainAuditDomains      string `json:"domain_audit_domains"` // comma-separated
	DomainAuditLogDir       string `json:"domain_audit_log_dir"`
	DomainAuditRetentionDay int    `json:"domain_audit_retention_days"`

	// runtime tuning (heki supports GOGC / GOMEMLIMIT)
	GCPercent  int `json:"gc_percent"`   // GOGC; 0 = leave default
	MemLimitMB int `json:"mem_limit_mb"` // soft memory limit (GOMEMLIMIT); 0 = off
}

type hysteria2FileConfig struct {
	ObfsPassword string `json:"obfs_password"` // Salamander PSK (obfs=salamander)
	UpMbps       int    `json:"up_mbps"`
	DownMbps     int    `json:"down_mbps"`
}

type tuicFileConfig struct {
	CongestionControl string `json:"congestion_control"` // cubic (default) / new_reno / bbr
	ZeroRTTHandshake  bool   `json:"zero_rtt_handshake"`
	AuthTimeoutSec    int    `json:"auth_timeout_sec"`
	HeartbeatSec      int    `json:"heartbeat_sec"`
	UDPTimeoutSec     int    `json:"udp_timeout_sec"`
}

func main() {
	cfgPath := flag.String("c", "config.json", "path to config.json")
	routesPath := flag.String("r", "", "path to routes.toml (overrides routes_file)")
	dnsPath := flag.String("d", "", "path to dns.yml (overrides dns_rules_file)")
	genKey := flag.Bool("genkey", false, "generate a REALITY x25519 key pair (hex) and exit")
	flag.Parse()

	if *genKey {
		priv, pub, err := realityx.GenerateKeyPair()
		if err != nil {
			log.Fatalf("genkey: %v", err)
		}
		fmt.Printf("private_key (server): %s\npublic_key  (client): %s\n", hex.EncodeToString(priv), hex.EncodeToString(pub))
		return
	}

	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}
	var fc fileConfig
	if err := json.Unmarshal(raw, &fc); err != nil {
		log.Fatalf("parse config: %v", err)
	}

	// runtime memory tuning (GOGC / GOMEMLIMIT). Env vars still take precedence.
	if fc.GCPercent > 0 {
		debug.SetGCPercent(fc.GCPercent)
	}
	if fc.MemLimitMB > 0 {
		debug.SetMemoryLimit(int64(fc.MemLimitMB) * 1024 * 1024)
	}

	cfg := node.Config{
		Protocol:       fc.Protocol,
		Method:         fc.Method,
		PanelType:      fc.PanelType,
		PanelURL:       fc.PanelURL,
		PanelKey:       fc.PanelKey,
		NodeID:         fc.NodeID,
		Listen:         fc.Listen,
		TLSCert:        fc.TLSCert,
		TLSKey:         fc.TLSKey,
		SyncInterval:   time.Duration(fc.SyncIntervalSec) * time.Second,
		ReportInterval: time.Duration(fc.ReportIntervalSec) * time.Second,
	}
	if fc.FallbackHost != "" {
		cfg.Fallback = &trojan.FallbackTarget{Host: fc.FallbackHost, Port: fc.FallbackPort}
	}
	if fc.Reality != nil {
		priv, derr := hex.DecodeString(fc.Reality.PrivateKey)
		if derr != nil {
			log.Fatalf("reality private_key: %v", derr)
		}
		cfg.Reality = &node.RealityConfig{
			PrivateKey:  priv,
			ServerNames: fc.Reality.ServerNames,
			ShortIDs:    fc.Reality.ShortIDs,
			Dest:        fc.Reality.Dest,
		}
	}
	if fc.Hysteria2 != nil {
		cfg.Hysteria2 = &node.Hysteria2Config{
			ObfsPassword: fc.Hysteria2.ObfsPassword,
			UpMbps:       fc.Hysteria2.UpMbps,
			DownMbps:     fc.Hysteria2.DownMbps,
		}
	}
	if fc.TUIC != nil {
		cfg.TUIC = &node.TUICConfig{
			CongestionControl: fc.TUIC.CongestionControl,
			ZeroRTTHandshake:  fc.TUIC.ZeroRTTHandshake,
			AuthTimeoutSec:    fc.TUIC.AuthTimeoutSec,
			HeartbeatSec:      fc.TUIC.HeartbeatSec,
			UDPTimeoutSec:     fc.TUIC.UDPTimeoutSec,
		}
	}
	if dp := buildDataplane(fc, *routesPath, *dnsPath); dp != nil {
		cfg.Dataplane = dp
	}

	n, err := node.New(cfg)
	if err != nil {
		log.Fatalf("init node: %v", err)
	}
	if err := n.Start(); err != nil {
		log.Fatalf("start node: %v", err)
	}
	log.Printf("heki node running; press Ctrl+C to stop")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	n.Stop()
	log.Printf("stopped")
}

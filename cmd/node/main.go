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
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"heki/node"
	"heki/server/proto/trojan"
)

type fileConfig struct {
	PanelType         string `json:"panel_type"`
	PanelURL          string `json:"panel_url"`
	PanelKey          string `json:"panel_key"`
	NodeID            int    `json:"node_id"`
	Listen            string `json:"listen"`
	TLSCert           string `json:"tls_cert"`
	TLSKey            string `json:"tls_key"`
	FallbackHost      string `json:"fallback_host"`
	FallbackPort      int    `json:"fallback_port"`
	SyncIntervalSec   int    `json:"sync_interval_sec"`
	ReportIntervalSec int    `json:"report_interval_sec"`
}

func main() {
	cfgPath := flag.String("c", "config.json", "path to config.json")
	flag.Parse()

	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}
	var fc fileConfig
	if err := json.Unmarshal(raw, &fc); err != nil {
		log.Fatalf("parse config: %v", err)
	}

	cfg := node.Config{
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

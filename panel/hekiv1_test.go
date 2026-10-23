package panel

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHekiV1ClientSpec drives the client against a spec-accurate heki-v1 backend
// and asserts the wire contract: paths, Bearer auth, headers, the {"data":...}
// envelope, ETag/If-None-Match, and the traffic/alive-ips/status request bodies.
func TestHekiV1ClientSpec(t *testing.T) {
	const key = "dev-demo-key"
	var lastTraffic, lastAlive, lastStatus json.RawMessage
	var sawBearer, sawUA, sawNodeID bool

	mux := http.NewServeMux()
	mux.HandleFunc("/heki/api/v1/nodes/1", func(w http.ResponseWriter, r *http.Request) {
		sawBearer = r.Header.Get("Authorization") == "Bearer "+key
		sawUA = r.Header.Get("User-Agent") == "heki"
		sawNodeID = r.Header.Get("X-Heki-Node-Id") == "1"
		if r.Header.Get("If-None-Match") == `"node-v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"node-v1"`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{
			"protocol":"vless",
			"listen":{"port":443,"ip":"0.0.0.0"},
			"limits":{"speed_mbps":100,"traffic_rate":1.5},
			"scheduler":{"pull_interval_seconds":60,"push_interval_seconds":30},
			"security":{"mode":"reality","server_name":"a.example",
				"reality":{"private_key":"deadbeef","server_names":["a.example"],"short_ids":["01ab"],"dest":"www.example.com:443"}},
			"protocol_settings":{"flow":"xtls-rprx-vision"}
		}}`)
	})
	mux.HandleFunc("/heki/api/v1/nodes/1/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":[
			{"id":1,"uuid":"u-1","method":"aes-256-gcm","enabled":true},
			{"id":2,"password":"p2","banned":true},
			{"id":3,"password":"p3","disabled":true},
			{"id":4,"password":"p4","enabled":false},
			{"id":5,"uuid":"u-5"}
		]}`)
	})
	mux.HandleFunc("/heki/api/v1/nodes/1/traffic", func(w http.ResponseWriter, r *http.Request) {
		lastTraffic, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/heki/api/v1/nodes/1/alive-ips", func(w http.ResponseWriter, r *http.Request) {
		lastAlive, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/heki/api/v1/nodes/1/status", func(w http.ResponseWriter, r *http.Request) {
		lastStatus, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewHekiV1Client(srv.URL+"/heki", key, 1)
	c.SetRequestedProtocol("vless")

	// --- GET node ---
	ni, err := c.GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo: %v", err)
	}
	if !sawBearer || !sawUA || !sawNodeID {
		t.Fatalf("missing headers: bearer=%v ua=%v nodeid=%v", sawBearer, sawUA, sawNodeID)
	}
	if ni.Protocol != "vless" || ni.ListenPort != 443 || ni.TrafficRate != 1.5 {
		t.Fatalf("node parse: %+v", ni)
	}
	if ni.PullIntervalSec != 60 || ni.PushIntervalSec != 30 {
		t.Fatalf("scheduler parse: %+v", ni)
	}
	if ni.Reality == nil || ni.Reality.Dest != "www.example.com:443" ||
		len(ni.Reality.ServerNames) != 1 || len(ni.Reality.ShortIDs) != 1 {
		t.Fatalf("reality parse: %+v", ni.Reality)
	}

	// --- 304 path (ETag stored, If-None-Match sent) ---
	if _, err := c.GetNodeInfo(); err != nil {
		t.Fatalf("GetNodeInfo (304): %v", err)
	}

	// --- GET users (envelope + active filtering) ---
	users, err := c.GetUsers()
	if err != nil {
		t.Fatalf("GetUsers: %v", err)
	}
	if len(users) != 2 { // ids 1 and 5 are active; 2(banned),3(disabled),4(enabled=false) dropped
		t.Fatalf("expected 2 active users, got %d: %+v", len(users), users)
	}
	if users[0].ID != 1 || users[0].UUID != "u-1" || users[0].Method != "aes-256-gcm" {
		t.Fatalf("user parse: %+v", users[0])
	}

	// --- POST traffic (records envelope + u/d keys) ---
	if err := c.ReportTraffic([]UserTraffic{{UserID: 1, Upload: 1024, Download: 2048}}); err != nil {
		t.Fatalf("ReportTraffic: %v", err)
	}
	if s := string(lastTraffic); !strings.Contains(s, `"records"`) ||
		!strings.Contains(s, `"user_id":1`) || !strings.Contains(s, `"u":1024`) || !strings.Contains(s, `"d":2048`) {
		t.Fatalf("traffic body: %s", s)
	}

	// --- POST alive-ips (grouped per user) ---
	if err := c.ReportAliveIP([]AliveIP{{UserID: 1, IP: "1.2.3.4"}, {UserID: 1, IP: "5.6.7.8"}}); err != nil {
		t.Fatalf("ReportAliveIP: %v", err)
	}
	if s := string(lastAlive); !strings.Contains(s, `"ips":["1.2.3.4","5.6.7.8"]`) {
		t.Fatalf("alive-ips body: %s", s)
	}

	// --- POST status ---
	if err := c.ReportNodeInfo(&NodeStatus{CPU: 12.5, Uptime: 100, Load: 0.3}); err != nil {
		t.Fatalf("ReportNodeInfo: %v", err)
	}
	if s := string(lastStatus); !strings.Contains(s, `"cpu_percent":12.5`) || !strings.Contains(s, `"uptime_seconds":100`) {
		t.Fatalf("status body: %s", s)
	}
}

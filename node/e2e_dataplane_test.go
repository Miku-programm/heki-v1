package node

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"heki/node/dataplane"
)

// TestEndToEndDataplane exercises the node data plane end-to-end through AnyTLS:
// PROXY-protocol real-IP recovery, rule-based routing to a direct outbound, and
// domain auditing. The client prepends a PROXY v1 header before TLS; the node
// recovers the real IP, routes the echo port to direct, relays, and writes an
// audit record whose client_ip is the PROXY source.
func TestEndToEndDataplane(t *testing.T) {
	const password = "dp-pass"
	const realIP = "203.0.113.50"
	panelURL, reported, closePanel := fakePanel(t, 25,
		`[{"id":1,"email":"a@x","passwd":"`+password+`"}]`)
	defer closePanel()
	echoLn, echoHost, echoPort := startEcho(t)
	defer echoLn.Close()

	auditDir := t.TempDir()
	n, err := New(Config{
		Protocol: "anytls", PanelType: "sspanel", PanelURL: panelURL, PanelKey: "k", NodeID: 25,
		Listen: "127.0.0.1:0", TLSConfig: &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}},
		SyncInterval: time.Hour, ReportInterval: 120 * time.Millisecond,
		Dataplane: &DataplaneConfig{
			RoutesEnabled: true,
			Routes: []dataplane.Route{
				{Rules: []string{"port:" + itoaN(echoPort)}, Outs: []dataplane.Outbound{{Type: "direct"}}},
				{Rules: []string{"*"}, Outs: []dataplane.Outbound{{Type: "block"}}},
			},
			AuditEnable:  true,
			AuditDomains: []string{"*"},
			AuditDir:     auditDir,
			ProxyProtocol: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	defer n.Stop()

	addr := n.Addr().String()
	cli, err := anytls.NewClient(context.Background(), anytls.ClientConfig{
		Password: password,
		Logger:   logger.NOP(),
		DialOut: func(ctx context.Context) (net.Conn, error) {
			raw, err := net.Dial("tcp", addr)
			if err != nil {
				return nil, err
			}
			// PROXY protocol v1 header before the TLS handshake
			if _, err := raw.Write([]byte("PROXY TCP4 " + realIP + " 198.51.100.1 40000 443\r\n")); err != nil {
				raw.Close()
				return nil, err
			}
			tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
			if err := tc.Handshake(); err != nil {
				raw.Close()
				return nil, err
			}
			return tc, nil
		},
	})
	if err != nil {
		t.Fatalf("anytls client: %v", err)
	}

	conn, err := cli.CreateProxy(context.Background(), M.ParseSocksaddrHostPort(echoHost, uint16(echoPort)))
	if err != nil {
		t.Fatalf("create proxy: %v", err)
	}
	defer conn.Close()

	payload := []byte("dataplane-roundtrip")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := readFullT(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("relay mismatch: %q", got)
	}
	conn.Close()
	expectReport(t, reported, 1)

	// Give the async audit queue a moment, then flush by stopping the node.
	time.Sleep(100 * time.Millisecond)
	n.Stop()

	date := time.Now().UTC().Format("2006-01-02")
	data, err := os.ReadFile(filepath.Join(auditDir, "domain-audit-node-25-"+date+".jsonl"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var rec dataplane.Record
	first := strings.SplitN(strings.TrimSpace(string(data)), "\n", 2)[0]
	if err := json.Unmarshal([]byte(first), &rec); err != nil {
		t.Fatalf("audit json: %v (%s)", err, data)
	}
	if rec.ClientIP != realIP {
		t.Fatalf("audit client_ip = %q, want %q (PROXY protocol real IP)", rec.ClientIP, realIP)
	}
	if rec.UserID != 1 || rec.Status != "connected" || rec.TargetPort != echoPort {
		t.Fatalf("unexpected audit record: %+v", rec)
	}
	t.Logf("OK: real_ip=%s user=%d target=%s status=%s", rec.ClientIP, rec.UserID, rec.Target, rec.Status)
}

func readFullT(r net.Conn, p []byte) (int, error) {
	n := 0
	for n < len(p) {
		m, err := r.Read(p[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

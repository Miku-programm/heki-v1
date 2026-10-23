package node

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"heki/node/dataplane"
)

// TestEndToEndChainedOutbound proves a chained proxy outbound: a client reaches
// AnyTLS node A, whose data-plane routes all traffic to a Trojan outbound that
// forwards to Trojan node B, which relays to the echo upstream.
//
//	client -> nodeA(anytls) --route--> trojan outbound -> nodeB(trojan) -> echo
func TestEndToEndChainedOutbound(t *testing.T) {
	const pwA = "anytls-entry-pass"
	const pwB = "trojan-exit-pass"
	echoLn, echoHost, echoPort := startEcho(t)
	defer echoLn.Close()

	// --- node B: trojan exit -> echo (direct) ---
	panelB, _, closeB := fakePanel(t, 31, `[{"id":1,"email":"b@x","passwd":"`+pwB+`"}]`)
	defer closeB()
	nb, err := New(Config{
		Protocol: "trojan", PanelType: "sspanel", PanelURL: panelB, PanelKey: "k", NodeID: 31,
		Listen: "127.0.0.1:0", TLSConfig: &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}},
		SyncInterval: time.Hour, ReportInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := nb.Start(); err != nil {
		t.Fatal(err)
	}
	defer nb.Stop()
	bHost, bPortStr, _ := net.SplitHostPort(nb.Addr().String())
	bPort := atoi(bPortStr)

	// --- node A: anytls entry, routes everything to a trojan outbound -> node B ---
	panelA, reportedA, closeA := fakePanel(t, 30, `[{"id":1,"email":"a@x","passwd":"`+pwA+`"}]`)
	defer closeA()
	na, err := New(Config{
		Protocol: "anytls", PanelType: "sspanel", PanelURL: panelA, PanelKey: "k", NodeID: 30,
		Listen: "127.0.0.1:0", TLSConfig: &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}},
		SyncInterval: time.Hour, ReportInterval: 120 * time.Millisecond,
		Dataplane: &DataplaneConfig{
			RoutesEnabled: true,
			Routes: []dataplane.Route{{
				Rules: []string{"*"},
				Outs: []dataplane.Outbound{{
					Type: "trojan", Server: bHost, Port: bPort,
					Password: pwB, SkipCertVerify: true,
				}},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := na.Start(); err != nil {
		t.Fatal(err)
	}
	defer na.Stop()

	// --- client -> node A (anytls) ---
	cli, err := anytls.NewClient(context.Background(), anytls.ClientConfig{
		Password: pwA, Logger: logger.NOP(),
		DialOut: func(ctx context.Context) (net.Conn, error) {
			return tls.Dial("tcp", na.Addr().String(), &tls.Config{InsecureSkipVerify: true})
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

	payload := []byte("chained-outbound-roundtrip")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := readFullT(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("chain relay mismatch: %q", got)
	}
	conn.Close()
	expectReport(t, reportedA, 1)
	t.Log("OK: client -> anytls(A) -> trojan outbound -> trojan(B) -> echo")
}

// TestEndToEndChainedVLESS proves the VLESS chained outbound:
//
//	client -> nodeA(anytls) --route--> vless outbound -> nodeB(vless) -> echo
func TestEndToEndChainedVLESS(t *testing.T) {
	const pwA = "anytls-entry-2"
	const uuidB = "b831381d-6324-4d53-ad4f-8cda48b30811"
	echoLn, echoHost, echoPort := startEcho(t)
	defer echoLn.Close()

	panelB, _, closeB := fakePanel(t, 33, `[{"id":1,"email":"b@x","uuid":"`+uuidB+`"}]`)
	defer closeB()
	nb, err := New(Config{
		Protocol: "vless", PanelType: "sspanel", PanelURL: panelB, PanelKey: "k", NodeID: 33,
		Listen: "127.0.0.1:0", TLSConfig: &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}},
		SyncInterval: time.Hour, ReportInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := nb.Start(); err != nil {
		t.Fatal(err)
	}
	defer nb.Stop()
	bHost, bPortStr, _ := net.SplitHostPort(nb.Addr().String())

	panelA, reportedA, closeA := fakePanel(t, 32, `[{"id":1,"email":"a@x","passwd":"`+pwA+`"}]`)
	defer closeA()
	na, err := New(Config{
		Protocol: "anytls", PanelType: "sspanel", PanelURL: panelA, PanelKey: "k", NodeID: 32,
		Listen: "127.0.0.1:0", TLSConfig: &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}},
		SyncInterval: time.Hour, ReportInterval: 120 * time.Millisecond,
		Dataplane: &DataplaneConfig{
			RoutesEnabled: true,
			Routes: []dataplane.Route{{
				Rules: []string{"*"},
				Outs:  []dataplane.Outbound{{Type: "vless", Server: bHost, Port: atoi(bPortStr), UUID: uuidB, SkipCertVerify: true}},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := na.Start(); err != nil {
		t.Fatal(err)
	}
	defer na.Stop()

	cli, err := anytls.NewClient(context.Background(), anytls.ClientConfig{
		Password: pwA, Logger: logger.NOP(),
		DialOut: func(ctx context.Context) (net.Conn, error) {
			return tls.Dial("tcp", na.Addr().String(), &tls.Config{InsecureSkipVerify: true})
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
	payload := []byte("chained-vless-roundtrip")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := readFullT(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("vless chain mismatch: %q", got)
	}
	conn.Close()
	expectReport(t, reportedA, 1)
	t.Log("OK: client -> anytls(A) -> vless outbound -> vless(B) -> echo")
}

// chainThrough starts an echo, an exit node B, and an AnyTLS entry node A that
// routes everything to the given outbound, then runs a client roundtrip.
func chainThrough(t *testing.T, nodeBID, nodeAID int, nbCfg Config, out dataplane.Outbound) {
	t.Helper()
	echoLn, echoHost, echoPort := startEcho(t)
	defer echoLn.Close()

	nbCfg.Listen = "127.0.0.1:0"
	nbCfg.SyncInterval = time.Hour
	nbCfg.ReportInterval = time.Hour
	if nbCfg.TLSConfig == nil && nbCfg.Protocol != "ss" {
		nbCfg.TLSConfig = &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}}
	}
	nb, err := New(nbCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := nb.Start(); err != nil {
		t.Fatal(err)
	}
	defer nb.Stop()
	bHost, bPortStr, _ := net.SplitHostPort(nb.Addr().String())
	out.Server = bHost
	out.Port = atoi(bPortStr)

	const pwA = "anytls-entry-x"
	panelA, reportedA, closeA := fakePanel(t, nodeAID, `[{"id":1,"email":"a@x","passwd":"`+pwA+`"}]`)
	defer closeA()
	na, err := New(Config{
		Protocol: "anytls", PanelType: "sspanel", PanelURL: panelA, PanelKey: "k", NodeID: nodeAID,
		Listen: "127.0.0.1:0", TLSConfig: &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}},
		SyncInterval: time.Hour, ReportInterval: 120 * time.Millisecond,
		Dataplane: &DataplaneConfig{RoutesEnabled: true, Routes: []dataplane.Route{{Rules: []string{"*"}, Outs: []dataplane.Outbound{out}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := na.Start(); err != nil {
		t.Fatal(err)
	}
	defer na.Stop()

	cli, err := anytls.NewClient(context.Background(), anytls.ClientConfig{
		Password: pwA, Logger: logger.NOP(),
		DialOut: func(ctx context.Context) (net.Conn, error) {
			return tls.Dial("tcp", na.Addr().String(), &tls.Config{InsecureSkipVerify: true})
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
	payload := []byte("chain-" + out.Type + "-roundtrip")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := readFullT(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("%s chain mismatch: %q", out.Type, got)
	}
	conn.Close()
	expectReport(t, reportedA, 1)
	t.Logf("OK: client -> anytls(A) -> %s outbound -> %s(B) -> echo", out.Type, out.Type)
}

func TestEndToEndChainedSS(t *testing.T) {
	const pwB = "ss-exit-pass"
	panelB, _, closeB := fakePanel(t, 35, `[{"id":1,"email":"b@x","passwd":"`+pwB+`"}]`)
	defer closeB()
	chainThrough(t, 35, 34,
		Config{Protocol: "ss", Method: "aes-256-gcm", PanelType: "sspanel", PanelURL: panelB, PanelKey: "k", NodeID: 35},
		dataplane.Outbound{Type: "ss", Password: pwB, Cipher: "aes-256-gcm"})
}

func TestEndToEndChainedAnyTLS(t *testing.T) {
	const pwB = "anytls-exit-pass"
	panelB, _, closeB := fakePanel(t, 37, `[{"id":1,"email":"b@x","passwd":"`+pwB+`"}]`)
	defer closeB()
	chainThrough(t, 37, 36,
		Config{Protocol: "anytls", PanelType: "sspanel", PanelURL: panelB, PanelKey: "k", NodeID: 37},
		dataplane.Outbound{Type: "anytls", Password: pwB, SkipCertVerify: true})
}

func TestEndToEndChainedVMess(t *testing.T) {
	const uuidB = "b831381d-6324-4d53-ad4f-8cda48b30811"
	panelB, _, closeB := fakePanel(t, 39, `[{"id":1,"email":"b@x","uuid":"`+uuidB+`"}]`)
	defer closeB()
	chainThrough(t, 39, 38,
		Config{Protocol: "vmess", PanelType: "sspanel", PanelURL: panelB, PanelKey: "k", NodeID: 39},
		dataplane.Outbound{Type: "vmess", UUID: uuidB, TLS: true, SkipCertVerify: true})
}

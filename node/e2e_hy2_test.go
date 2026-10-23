package node

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	hyclient "github.com/apernet/hysteria/core/v2/client"
)

// TestEndToEndHysteria2 runs a REAL Hysteria2 loop: the node serves via the
// upstream apernet QUIC server, the upstream apernet client authenticates and
// opens a TCP stream to an echo upstream, and the node reports traffic to a fake
// panel. This proves hysteria2 actually works (real QUIC stack on both ends).
func TestEndToEndHysteria2(t *testing.T) {
	const auth = "hy2-pass-xyz"
	panelURL, reported, closePanel := fakePanel(t, 11,
		`[{"id":1,"email":"h@x","passwd":"`+auth+`"}]`)
	defer closePanel()
	echoLn, echoHost, echoPort := startEcho(t)
	defer echoLn.Close()

	n, err := New(Config{
		Protocol: "hysteria2", PanelType: "sspanel", PanelURL: panelURL, PanelKey: "k", NodeID: 11,
		Listen: "127.0.0.1:0", TLSConfig: &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}},
		SyncInterval: time.Hour, ReportInterval: 120 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	defer n.Stop()

	// real apernet hysteria2 client
	serverAddr := n.Addr().(*net.UDPAddr)
	cli, _, err := hyclient.NewClient(&hyclient.Config{
		ServerAddr: serverAddr,
		Auth:       auth,
		TLSConfig:  hyclient.TLSConfig{ServerName: "localhost", InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("hysteria2 client: %v", err)
	}
	defer cli.Close()

	stream, err := cli.TCP(net.JoinHostPort(echoHost, itoaN(echoPort)))
	if err != nil {
		t.Fatalf("client TCP: %v", err)
	}
	defer stream.Close()

	payload := []byte("hysteria2-real-roundtrip")
	if _, err := stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("relay mismatch: %q", got)
	}
	stream.Close()
	expectReport(t, reported, 1)
}

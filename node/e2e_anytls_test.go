package node

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

// TestEndToEndAnyTLS runs a REAL AnyTLS loop: the node serves via the upstream
// sing-anytls service over TLS, the upstream sing-anytls client authenticates
// and opens a muxed stream to an echo upstream, and the node reports traffic to
// a fake panel. Proves AnyTLS (session mux + padding) works end-to-end.
func TestEndToEndAnyTLS(t *testing.T) {
	const password = "anytls-pass-7"
	panelURL, reported, closePanel := fakePanel(t, 14,
		`[{"id":1,"email":"a@x","passwd":"`+password+`"}]`)
	defer closePanel()
	echoLn, echoHost, echoPort := startEcho(t)
	defer echoLn.Close()

	n, err := New(Config{
		Protocol: "anytls", PanelType: "sspanel", PanelURL: panelURL, PanelKey: "k", NodeID: 14,
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

	// real sing-anytls client: DialOut is a TLS dial to the node.
	addr := n.Addr().String()
	cli, err := anytls.NewClient(context.Background(), anytls.ClientConfig{
		Password: password,
		Logger:   logger.NOP(),
		DialOut: func(ctx context.Context) (net.Conn, error) {
			return tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
		},
	})
	if err != nil {
		t.Fatalf("anytls client: %v", err)
	}

	dest := M.ParseSocksaddrHostPort(echoHost, uint16(echoPort))
	conn, err := cli.CreateProxy(context.Background(), dest)
	if err != nil {
		t.Fatalf("create proxy: %v", err)
	}
	defer conn.Close()

	payload := []byte("anytls-real-roundtrip")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("relay mismatch: %q", got)
	}
	conn.Close()
	expectReport(t, reported, 1)
}

package node

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-quic/tuic"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"heki/transport/tuicx"
)

// TestEndToEndTUIC runs a REAL TUIC loop: the node serves via the upstream
// sing-quic TUIC service, the upstream sing-quic client authenticates (UUID +
// password) and opens a TCP stream to an echo upstream, and the node reports
// traffic to a fake panel. This proves TUIC actually works end-to-end on the
// real QUIC stack.
func TestEndToEndTUIC(t *testing.T) {
	const uuidStr = "b831381d-6324-4d53-ad4f-8cda48b30811"
	panelURL, reported, closePanel := fakePanel(t, 13,
		`[{"id":1,"email":"t@x","uuid":"`+uuidStr+`"}]`)
	defer closePanel()
	echoLn, echoHost, echoPort := startEcho(t)
	defer echoLn.Close()

	n, err := New(Config{
		Protocol: "tuic", PanelType: "sspanel", PanelURL: panelURL, PanelKey: "k", NodeID: 13,
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

	// real sing-quic TUIC client
	var uuid [16]byte
	b, _ := hex.DecodeString(strings.ReplaceAll(uuidStr, "-", ""))
	copy(uuid[:], b)

	serverAddr := n.Addr().(*net.UDPAddr)
	cli, err := tuic.NewClient(tuic.ClientOptions{
		Context:       context.Background(),
		Dialer:        N.SystemDialer,
		ServerAddress: M.SocksaddrFromNet(serverAddr),
		TLSConfig: tuicx.ClientTLSConfig(&tls.Config{
			ServerName: "localhost", InsecureSkipVerify: true,
			MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"},
		}),
		UUID:              uuid,
		Password:          uuidStr, // pwOf() falls back to the UUID when no passwd
		CongestionControl: "bbr",
	})
	if err != nil {
		t.Fatalf("tuic client: %v", err)
	}
	defer cli.CloseWithError(nil)

	dest := M.ParseSocksaddrHostPort(echoHost, uint16(echoPort))
	conn, err := cli.DialConn(context.Background(), dest)
	if err != nil {
		t.Fatalf("dial conn: %v", err)
	}
	defer conn.Close()

	payload := []byte("tuic-real-roundtrip")
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

package node

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	hyclient "github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/extras/v2/obfs"
)

// salamanderConnFactory makes client UDP PacketConns wrapped with Salamander
// obfuscation, so the apernet client speaks obfs to the node.
type salamanderConnFactory struct{ psk []byte }

func (f *salamanderConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	return obfs.WrapPacketConnSalamander(udp, f.psk)
}

// TestEndToEndHysteria2Obfs runs a REAL Hysteria2 loop with Salamander
// obfuscation on both ends (heki's obfs=salamander + obfs_password): the node
// wraps its UDP listener with Salamander, and only a client using the same PSK
// can complete the QUIC handshake, relay, and get traffic reported.
func TestEndToEndHysteria2Obfs(t *testing.T) {
	const auth = "hy2-obfs-pass"
	const obfsPSK = "salamander-secret"
	panelURL, reported, closePanel := fakePanel(t, 22,
		`[{"id":1,"email":"h@x","passwd":"`+auth+`"}]`)
	defer closePanel()
	echoLn, echoHost, echoPort := startEcho(t)
	defer echoLn.Close()

	n, err := New(Config{
		Protocol: "hysteria2", PanelType: "sspanel", PanelURL: panelURL, PanelKey: "k", NodeID: 22,
		Listen: "127.0.0.1:0", TLSConfig: &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}},
		Hysteria2:    &Hysteria2Config{ObfsPassword: obfsPSK, UpMbps: 100, DownMbps: 100},
		SyncInterval: time.Hour, ReportInterval: 120 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	defer n.Stop()

	serverAddr := n.Addr().(*net.UDPAddr)
	cli, _, err := hyclient.NewClient(&hyclient.Config{
		ServerAddr:  serverAddr,
		Auth:        auth,
		TLSConfig:   hyclient.TLSConfig{ServerName: "localhost", InsecureSkipVerify: true},
		ConnFactory: &salamanderConnFactory{psk: []byte(obfsPSK)},
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

	payload := []byte("hy2-obfs-roundtrip")
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

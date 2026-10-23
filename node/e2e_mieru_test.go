package node

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/enfein/mieru/v3/apis/client"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"
)

// TestEndToEndMieru runs a REAL mieru loop: the node serves via the upstream
// mieru embeddable server (mieru's own obfuscated transport), the upstream
// mieru client authenticates (username+password) and opens a stream to an echo
// upstream, and the node reports traffic to a fake panel.
func TestEndToEndMieru(t *testing.T) {
	const username = "m@x"
	const password = "mieru-pass-9"
	port := freePort(t)

	panelURL, reported, closePanel := fakePanel(t, 15,
		`[{"id":1,"email":"`+username+`","passwd":"`+password+`"}]`)
	defer closePanel()
	echoLn, echoHost, echoPort := startEcho(t)
	defer echoLn.Close()

	n, err := New(Config{
		Protocol: "mieru", PanelType: "sspanel", PanelURL: panelURL, PanelKey: "k", NodeID: 15,
		Listen:       net.JoinHostPort("127.0.0.1", itoaN(port)),
		SyncInterval: time.Hour, ReportInterval: 120 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	defer n.Stop()

	// real mieru client
	cli := client.NewClient()
	if err := cli.Store(&client.ClientConfig{Profile: &appctlpb.ClientProfile{
		ProfileName: proto.String("api"),
		User:        &appctlpb.User{Name: proto.String(username), Password: proto.String(password)},
		Servers: []*appctlpb.ServerEndpoint{{
			IpAddress: proto.String("127.0.0.1"),
			PortBindings: []*appctlpb.PortBinding{{
				Port: proto.Int32(int32(port)), Protocol: appctlpb.TransportProtocol_TCP.Enum(),
			}},
		}},
		Mtu: proto.Int32(1400),
	}}); err != nil {
		t.Fatalf("mieru client store: %v", err)
	}
	if err := cli.Start(); err != nil {
		t.Fatalf("mieru client start: %v", err)
	}
	defer cli.Stop()

	dest := &net.TCPAddr{IP: net.ParseIP(echoHost), Port: echoPort}
	var conn net.Conn
	// mieru server starts in a goroutine; retry the first dial until it is up.
	for i := 0; i < 40; i++ {
		conn, err = cli.DialContext(context.Background(), dest)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial conn: %v", err)
	}
	defer conn.Close()

	payload := []byte("mieru-real-roundtrip")
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

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

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
	"github.com/sagernet/sing/common/uot"
)

// startUDPEcho starts a UDP echo server on loopback.
func startUDPEcho(t *testing.T) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteToUDP(buf[:n], addr)
		}
	}()
	return pc
}

// TestEndToEndAnyTLSUoT proves AnyTLS UDP-over-TCP works end-to-end: the node
// serves AnyTLS, a real sing-anytls client opens a UoT stream (magic address +
// uot.Request) to a UDP echo upstream, a datagram round-trips through the real
// session, and the node reports the traffic.
func TestEndToEndAnyTLSUoT(t *testing.T) {
	const password = "anytls-uot-pass"
	panelURL, reported, closePanel := fakePanel(t, 24,
		`[{"id":1,"email":"a@x","passwd":"`+password+`"}]`)
	defer closePanel()
	udpEcho := startUDPEcho(t)
	defer udpEcho.Close()
	echoAddr := udpEcho.LocalAddr().(*net.UDPAddr)

	n, err := New(Config{
		Protocol: "anytls", PanelType: "sspanel", PanelURL: panelURL, PanelKey: "k", NodeID: 24,
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

	// open a UoT (v2) stream to the magic destination and send the request
	stream, err := cli.CreateProxy(context.Background(), uot.RequestDestination(uot.Version))
	if err != nil {
		t.Fatalf("create uot proxy: %v", err)
	}
	defer stream.Close()
	req := uot.Request{IsConnect: true, Destination: M.SocksaddrFromNet(echoAddr)}
	if err := uot.WriteRequest(stream, req); err != nil {
		t.Fatalf("write uot request: %v", err)
	}
	uc := uot.NewConn(stream, req)

	payload := []byte("anytls-uot-roundtrip")
	if _, err := uc.WriteTo(payload, echoAddr); err != nil {
		t.Fatalf("uot write: %v", err)
	}
	buf := make([]byte, 1500)
	_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
	n2, _, err := uc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("uot read: %v", err)
	}
	if !bytes.Equal(buf[:n2], payload) {
		t.Fatalf("uot relay mismatch: %q", buf[:n2])
	}
	stream.Close()
	expectReport(t, reported, 1)
}

package node

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"heki/transport/realityx"
	"heki/transport/realityx/realityc"
)

// TestEndToEndVLESSReality runs a REAL authorized vless-over-REALITY loop: the
// node serves VLESS behind the genuine sagernet/reality server (borrowing a
// local Dest TLS site), and a REAL uTLS-based REALITY client authenticates
// (session_id auth + cert HMAC check), opens a VLESS stream to an echo upstream,
// and the node reports traffic to a fake panel. This proves REALITY works
// end-to-end with an authorized client, not just the relay/fallback path.
func TestEndToEndVLESSReality(t *testing.T) {
	const uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
	const sni = "example.test"

	priv, pub, err := realityx.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// local Dest: a TLS 1.3 + X25519 server, borrowed by REALITY.
	destLn := startDestTLS(t)
	defer destLn.Close()

	panelURL, reported, closePanel := fakePanel(t, 16,
		`[{"id":1,"email":"r@x","uuid":"`+uuid+`"}]`)
	defer closePanel()
	echoLn, echoHost, echoPort := startEcho(t)
	defer echoLn.Close()

	n, err := New(Config{
		Protocol: "vless-reality", PanelType: "sspanel", PanelURL: panelURL, PanelKey: "k", NodeID: 16,
		Listen: "127.0.0.1:0",
		Reality: &RealityConfig{
			PrivateKey:  priv,
			ServerNames: []string{sni},
			ShortIDs:    []string{""}, // allow the empty short id
			Dest:        destLn.Addr().String(),
		},
		SyncInterval: time.Hour, ReportInterval: 120 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	defer n.Stop()

	// authorized REALITY client (real uTLS handshake)
	var short [8]byte
	conn, err := realityc.Dial("tcp", n.Addr().String(), pub, sni, short)
	if err != nil {
		t.Fatalf("reality dial: %v", err)
	}
	defer conn.Close()

	// VLESS request over the REALITY session
	uuidBytes, _ := hex.DecodeString(strings.ReplaceAll(uuid, "-", ""))
	var req bytes.Buffer
	req.WriteByte(0)     // version
	req.Write(uuidBytes) // 16-byte uuid
	req.WriteByte(0)     // addon length
	req.WriteByte(0x01)  // command: TCP
	req.Write([]byte{byte(echoPort >> 8), byte(echoPort)})
	req.WriteByte(0x01) // atyp ipv4
	req.Write(net.ParseIP(echoHost).To4())
	payload := []byte("vless-reality-roundtrip")
	req.Write(payload)
	if _, err := conn.Write(req.Bytes()); err != nil {
		t.Fatal(err)
	}

	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		t.Fatalf("read vless resp header: %v", err)
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

// startDestTLS starts a local TLS 1.3 + X25519 server for REALITY to borrow.
func startDestTLS(t *testing.T) net.Listener {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates:     []tls.Certificate{selfSignedCert(t)},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				tc := c.(*tls.Conn)
				_ = tc.Handshake()
				_, _ = io.Copy(io.Discard, tc)
				_ = tc.Close()
			}()
		}
	}()
	return ln
}

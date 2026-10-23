package node

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeHekiV1 is a minimal, spec-accurate heki-v1 backend for one node+user.
func fakeHekiV1(t *testing.T, nodeID int, usersJSON string) (url string, reported <-chan []byte, closeFn func()) {
	t.Helper()
	ch := make(chan []byte, 1)
	base := "/heki/api/v1/nodes/" + itoaN(nodeID)
	var mu sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc(base, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer k" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"protocol":"trojan","listen":{"port":0},"scheduler":{"pull_interval_seconds":3600,"push_interval_seconds":1}}}`)
	})
	mux.HandleFunc(base+"/users", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"data":`+usersJSON+`}`)
	})
	mux.HandleFunc(base+"/traffic", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		select {
		case ch <- b:
		default:
		}
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	return srv.URL + "/heki", ch, srv.Close
}

// TestEndToEndHekiV1Trojan runs the full loop against heki's OWN panel protocol
// (type=heki-v1): the node pulls its config + one user from the heki-v1 backend,
// a real trojan-over-TLS client authenticates and relays to an echo upstream,
// and the node reports traffic back in the heki-v1 {"records":[...]} shape.
func TestEndToEndHekiV1Trojan(t *testing.T) {
	const password = "heki-v1-pass"
	panelURL, reported, closePanel := fakeHekiV1(t, 20,
		`[{"id":1,"password":"`+password+`","enabled":true}]`)
	defer closePanel()
	echoLn, echoHost, echoPort := startEcho(t)
	defer echoLn.Close()

	n, err := New(Config{
		Protocol: "trojan", PanelType: "heki-v1", PanelURL: panelURL, PanelKey: "k", NodeID: 20,
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

	conn, err := tls.Dial("tcp", n.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum224([]byte(password))
	token := make([]byte, 56)
	hex.Encode(token, sum[:])
	var req bytes.Buffer
	req.Write(token)
	req.WriteString("\r\n")
	req.WriteByte(0x01) // CONNECT
	req.WriteByte(0x01) // atyp ipv4
	req.Write(net.ParseIP(echoHost).To4())
	req.WriteByte(byte(echoPort >> 8))
	req.WriteByte(byte(echoPort))
	req.WriteString("\r\n")
	payload := []byte("heki-v1-roundtrip")
	req.Write(payload)
	if _, err := conn.Write(req.Bytes()); err != nil {
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

	// verify the heki-v1 traffic report shape: {"records":[{"user_id","u","d"}]}
	select {
	case body := <-reported:
		var rep struct {
			Records []struct {
				UserID int   `json:"user_id"`
				U      int64 `json:"u"`
				D      int64 `json:"d"`
			} `json:"records"`
		}
		if err := json.Unmarshal(body, &rep); err != nil {
			t.Fatalf("bad traffic report: %v (%s)", err, body)
		}
		if len(rep.Records) != 1 || rep.Records[0].UserID != 1 {
			t.Fatalf("unexpected report: %s", body)
		}
		if rep.Records[0].U == 0 && rep.Records[0].D == 0 {
			t.Fatalf("no traffic counted: %s", body)
		}
		t.Logf("OK: heki-v1 report user=%d u=%d d=%d", rep.Records[0].UserID, rep.Records[0].U, rep.Records[0].D)
	case <-time.After(3 * time.Second):
		t.Fatal("heki-v1 backend never received a traffic report")
	}
}

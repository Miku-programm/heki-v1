package node

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestEndToEndTrojanOverTLS runs the full minimal loop against a fake SSPanel:
// the node pulls one user, a real trojan-over-TLS client authenticates and
// relays to an echo upstream, and the node reports the traffic back to the
// panel. This proves: panel pull users -> listen -> auth -> relay -> report.
func TestEndToEndTrojanOverTLS(t *testing.T) {
	const password = "s3cret-pass"

	// --- fake SSPanel (mod_mu) ---
	var mu sync.Mutex
	var trafficReport []byte
	reported := make(chan struct{}, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/mod_mu/nodes/9/info", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ret":1,"data":{"node_speedlimit":0}}`))
	})
	mux.HandleFunc("/mod_mu/users", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ret":1,"data":[{"id":1,"email":"u1@example.com","passwd":"` + password + `"}]}`))
	})
	mux.HandleFunc("/mod_mu/users/traffic", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		trafficReport = b
		mu.Unlock()
		select {
		case reported <- struct{}{}:
		default:
		}
		_, _ = w.Write([]byte(`{"ret":1}`))
	})
	panelSrv := httptest.NewServer(mux)
	defer panelSrv.Close()

	// --- echo upstream ---
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()

	// --- start node ---
	n, err := New(Config{
		PanelType:      "sspanel",
		PanelURL:       panelSrv.URL,
		PanelKey:       "mukey",
		NodeID:         9,
		Listen:         "127.0.0.1:0",
		TLSConfig:      &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}},
		SyncInterval:   time.Hour,
		ReportInterval: 150 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	defer n.Stop()

	// --- trojan-over-TLS client ---
	conn, err := tls.Dial("tcp", n.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}

	// trojan request: hex(SHA-224(password)) + CRLF + CMD(connect) + SOCKS addr + CRLF + payload
	sum := sha256.Sum224([]byte(password))
	token := make([]byte, 56)
	hex.Encode(token, sum[:])

	echoHost, echoPortStr, _ := net.SplitHostPort(echoLn.Addr().String())
	echoPort := atoi(echoPortStr)
	var req bytes.Buffer
	req.Write(token)
	req.WriteString("\r\n")
	req.WriteByte(0x01) // CONNECT
	req.WriteByte(0x01) // atyp IPv4
	req.Write(net.ParseIP(echoHost).To4())
	req.WriteByte(byte(echoPort >> 8))
	req.WriteByte(byte(echoPort))
	req.WriteString("\r\n")
	payload := []byte("heki-node-roundtrip")
	req.Write(payload)
	if _, err := conn.Write(req.Bytes()); err != nil {
		t.Fatal(err)
	}

	// read the echoed payload back through the relay
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("relay mismatch: got %q", got)
	}
	conn.Close() // ends the relay -> traffic is accounted

	// --- verify traffic reported to the panel ---
	select {
	case <-reported:
	case <-time.After(3 * time.Second):
		t.Fatal("panel never received a traffic report")
	}
	mu.Lock()
	body := trafficReport
	mu.Unlock()

	var rep struct {
		Data []struct {
			UserID int   `json:"user_id"`
			U      int64 `json:"u"`
			D      int64 `json:"d"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &rep); err != nil {
		t.Fatalf("bad traffic report: %v (%s)", err, body)
	}
	if len(rep.Data) != 1 || rep.Data[0].UserID != 1 {
		t.Fatalf("unexpected report: %s", body)
	}
	if rep.Data[0].U == 0 && rep.Data[0].D == 0 {
		t.Fatalf("no traffic counted: %s", body)
	}
	t.Logf("OK: user=%d up=%d down=%d relayed+reported", rep.Data[0].UserID, rep.Data[0].U, rep.Data[0].D)
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// selfSignedCert makes an in-memory self-signed TLS certificate for the test.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "heki-node-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

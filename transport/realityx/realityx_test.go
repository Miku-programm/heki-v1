package realityx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// TestRealityRelaysToDest exercises the REAL xtls/reality server behavior
// reachable in-process: a non-authorized client connecting through the REALITY
// listener must be transparently relayed to Dest and complete a TLS 1.3
// handshake presenting Dest's certificate (REALITY "steal-oneself"). This
// proves the genuine REALITY machinery is running and wired to Dest.
//
// (An authorized VLESS-over-REALITY round trip needs a uTLS REALITY client, as
// in xray/sing-box, and is validated with an external client.)
func TestRealityRelaysToDest(t *testing.T) {
	const destName = "dest.example"

	// local Dest: a real TLS 1.3 server with a self-signed cert
	destCert := selfSigned(t, destName)
	destLn, err := tls.Listen("tcp", "127.0.0.1:0",
		&tls.Config{Certificates: []tls.Certificate{destCert}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer destLn.Close()
	go func() {
		for {
			c, err := destLn.Accept()
			if err != nil {
				return
			}
			go func() {
				tc := c.(*tls.Conn)
				_ = tc.Handshake()
				_, _ = io.Copy(io.Discard, tc) // hold open until client closes
				_ = tc.Close()
			}()
		}
	}()

	// REALITY server in front of a raw TCP listener, borrowing Dest.
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rl, err := NewListener(raw, Options{
		PrivateKey:  priv,
		ServerNames: []string{destName},
		Dest:        destLn.Addr().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Close()
	// Drain authorized conns (none expected from a plain client).
	go func() {
		for {
			if _, err := rl.Accept(); err != nil {
				return
			}
		}
	}()

	// Non-authorized plain-TLS client: must transparently reach Dest.
	conn, err := tls.Dial("tcp", raw.Addr().String(), &tls.Config{
		ServerName: destName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("handshake via REALITY relay: %v", err)
	}
	defer conn.Close()

	cs := conn.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		t.Fatal("no peer certificate")
	}
	if cn := cs.PeerCertificates[0].Subject.CommonName; cn != destName {
		t.Fatalf("expected Dest cert CN %q, got %q", destName, cn)
	}
	if cs.Version != tls.VersionTLS13 {
		t.Fatalf("expected TLS 1.3, got %x", cs.Version)
	}
	t.Logf("OK: REALITY relayed the handshake to Dest; client saw Dest cert CN=%q", destName)
}

func selfSigned(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
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

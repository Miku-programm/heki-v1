package node

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha1"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"heki/server/proto/ss"
)

// fakePanel serves SSPanel mod_mu responses for one user and captures the
// traffic report. usersJSON is the "data" array for /mod_mu/users.
func fakePanel(t *testing.T, nodeID int, usersJSON string) (url string, reported <-chan []byte, closeFn func()) {
	ch := make(chan []byte, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/mod_mu/nodes/"+itoaN(nodeID)+"/info", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ret":1,"data":{"node_speedlimit":0}}`))
	})
	mux.HandleFunc("/mod_mu/users", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ret":1,"data":` + usersJSON + `}`))
	})
	mux.HandleFunc("/mod_mu/users/traffic", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		select {
		case ch <- b:
		default:
		}
		_, _ = w.Write([]byte(`{"ret":1}`))
	})
	srv := httptest.NewServer(mux)
	return srv.URL, ch, srv.Close
}

func startEcho(t *testing.T) (net.Listener, string, int) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	return ln, host, atoi(portStr)
}

func expectReport(t *testing.T, reported <-chan []byte, wantUser int) {
	t.Helper()
	select {
	case body := <-reported:
		var rep struct {
			Data []struct {
				UserID int   `json:"user_id"`
				U      int64 `json:"u"`
				D      int64 `json:"d"`
			} `json:"data"`
		}
		_ = json.Unmarshal(body, &rep)
		if len(rep.Data) == 0 || rep.Data[0].UserID != wantUser {
			t.Fatalf("unexpected report: %s", body)
		}
		t.Logf("OK: traffic reported for user %d", wantUser)
	case <-time.After(3 * time.Second):
		t.Fatal("no traffic report received")
	}
}

func ipv4SocksAddr(host string, port int) []byte {
	b := []byte{0x01}
	b = append(b, net.ParseIP(host).To4()...)
	return binary.BigEndian.AppendUint16(b, uint16(port))
}

// TestEndToEndVLESSOverTLS: VLESS (no encryption) over TLS against a fake panel.
func TestEndToEndVLESSOverTLS(t *testing.T) {
	const uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
	panelURL, reported, closePanel := fakePanel(t, 7,
		`[{"id":1,"email":"v@x","uuid":"`+uuid+`"}]`)
	defer closePanel()
	echoLn, echoHost, echoPort := startEcho(t)
	defer echoLn.Close()

	n, err := New(Config{
		Protocol: "vless", PanelType: "sspanel", PanelURL: panelURL, PanelKey: "k", NodeID: 7,
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
	uuidBytes, _ := hex.DecodeString(strings.ReplaceAll(uuid, "-", ""))
	var req bytes.Buffer
	req.WriteByte(0)          // version
	req.Write(uuidBytes)      // 16-byte uuid
	req.WriteByte(0)          // addon length
	req.WriteByte(0x01)       // command: TCP
	req.Write([]byte{byte(echoPort >> 8), byte(echoPort)})
	req.WriteByte(0x01) // atyp ipv4
	req.Write(net.ParseIP(echoHost).To4())
	payload := []byte("vless-roundtrip")
	req.Write(payload)
	if _, err := conn.Write(req.Bytes()); err != nil {
		t.Fatal(err)
	}
	// response: [version][addon-len=0] then echoed payload
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

// TestEndToEndSS: Shadowsocks AEAD (aes-256-gcm) over raw TCP against a panel.
func TestEndToEndSS(t *testing.T) {
	const password = "ss-pass-123"
	panelURL, reported, closePanel := fakePanel(t, 5,
		`[{"id":1,"email":"s@x","passwd":"`+password+`"}]`)
	defer closePanel()
	echoLn, echoHost, echoPort := startEcho(t)
	defer echoLn.Close()

	n, err := New(Config{
		Protocol: "ss", Method: "aes-256-gcm", PanelType: "sspanel", PanelURL: panelURL, PanelKey: "k", NodeID: 5,
		Listen: "127.0.0.1:0", SyncInterval: time.Hour, ReportInterval: 120 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	defer n.Stop()

	conn, err := net.Dial("tcp", n.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	master := ss.EVPBytesToKey(password, 32)

	// request: salt + AEAD(len) + AEAD(socksaddr+payload)
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	subkey, _ := hkdf.Key(sha1.New, master, salt, "ss-subkey", 32)
	block, _ := aes.NewCipher(subkey)
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)

	payload := []byte("ss-roundtrip")
	body := append(ipv4SocksAddr(echoHost, echoPort), payload...)
	var req bytes.Buffer
	req.Write(salt)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(body)))
	req.Write(aead.Seal(nil, nonce, l[:], nil))
	incNonceT(nonce)
	req.Write(aead.Seal(nil, nonce, body, nil))
	if _, err := conn.Write(req.Bytes()); err != nil {
		t.Fatal(err)
	}

	// response: respSalt + AEAD chunks of the echoed payload
	respSalt := make([]byte, 32)
	if _, err := io.ReadFull(conn, respSalt); err != nil {
		t.Fatalf("read resp salt: %v", err)
	}
	rsub, _ := hkdf.Key(sha1.New, master, respSalt, "ss-subkey", 32)
	rblock, _ := aes.NewCipher(rsub)
	raead, _ := cipher.NewGCM(rblock)
	rnonce := make([]byte, 12)
	// read one length chunk + payload chunk
	encLen := make([]byte, 2+raead.Overhead())
	if _, err := io.ReadFull(conn, encLen); err != nil {
		t.Fatalf("read resp len: %v", err)
	}
	lp, err := raead.Open(nil, rnonce, encLen, nil)
	if err != nil {
		t.Fatalf("decrypt resp len: %v", err)
	}
	incNonceT(rnonce)
	plen := int(binary.BigEndian.Uint16(lp))
	encPay := make([]byte, plen+raead.Overhead())
	if _, err := io.ReadFull(conn, encPay); err != nil {
		t.Fatalf("read resp payload: %v", err)
	}
	got, err := raead.Open(nil, rnonce, encPay, nil)
	if err != nil {
		t.Fatalf("decrypt resp payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("ss relay mismatch: %q", got)
	}
	conn.Close()
	expectReport(t, reported, 1)
}

func incNonceT(n []byte) {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

func itoaN(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

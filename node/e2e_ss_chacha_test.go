package node

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"heki/server/proto/ss"
)

// TestEndToEndSSChaCha20 proves the newly-wired chacha20-ietf-poly1305 SS cipher
// works end-to-end through the node (panel pull -> auth -> relay -> report),
// using a real chacha20-poly1305 client on both directions.
func TestEndToEndSSChaCha20(t *testing.T) {
	const password = "ss-chacha-pass"
	panelURL, reported, closePanel := fakePanel(t, 21,
		`[{"id":1,"email":"c@x","passwd":"`+password+`"}]`)
	defer closePanel()
	echoLn, echoHost, echoPort := startEcho(t)
	defer echoLn.Close()

	n, err := New(Config{
		Protocol: "ss", Method: "chacha20-ietf-poly1305", PanelType: "sspanel", PanelURL: panelURL, PanelKey: "k", NodeID: 21,
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

	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 7)
	}
	subkey, _ := hkdf.Key(sha1.New, master, salt, "ss-subkey", 32)
	aead, err := chacha20poly1305.New(subkey)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 12)

	payload := []byte("ss-chacha-roundtrip")
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

	respSalt := make([]byte, 32)
	if _, err := io.ReadFull(conn, respSalt); err != nil {
		t.Fatalf("read resp salt: %v", err)
	}
	rsub, _ := hkdf.Key(sha1.New, master, respSalt, "ss-subkey", 32)
	raead, err := chacha20poly1305.New(rsub)
	if err != nil {
		t.Fatal(err)
	}
	rnonce := make([]byte, 12)
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

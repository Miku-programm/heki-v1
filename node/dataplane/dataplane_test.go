package dataplane

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMatchRule(t *testing.T) {
	ip := net.ParseIP("1.2.3.4")
	cases := []struct {
		rule string
		tgt  Target
		want bool
	}{
		{"*", Target{Host: "x"}, true},
		{"domain:google.com", Target{Host: "www.google.com"}, true},
		{"domain:google.com", Target{Host: "google.com"}, true},
		{"domain:google.com", Target{Host: "notgoogle.com"}, false},
		{"full:google.com", Target{Host: "www.google.com"}, false},
		{"domain-keyword:tele", Target{Host: "api.telegram.org"}, true},
		{"ip:1.2.3.0/24", Target{IP: ip}, true},
		{"ip:1.2.3.4", Target{IP: ip}, true},
		{"cidr:1.2.0.0/16", Target{IP: ip}, true},
		{"port:443", Target{Port: 443}, true},
		{"port:1000-2000", Target{Port: 1500}, true},
		{"port:80,443", Target{Port: 443}, true},
		{"node_id:1,2,3", Target{NodeID: 2}, true},
		{"node_id:1,2,3", Target{NodeID: 5}, false},
		{"geosite:netflix", Target{Host: "netflix.com"}, false}, // no data file
		{"regexp:.*\\.facebook\\.com", Target{Host: "a.facebook.com"}, true},
		{"glob:check-*.example.com", Target{Host: "check-1.example.com"}, true},
		{"sina.com", Target{Host: "www.sina.com.cn"}, true}, // bare substring
		{"1.2.3.4", Target{IP: ip}, true},                   // bare IP
		{"1.2.3.4:443", Target{IP: ip, Port: 443}, true},    // bare ip:port
		{"1.2.3.4:443", Target{IP: ip, Port: 80}, false},
		{"api.ip.sb:443", Target{Host: "api.ip.sb", Port: 443}, true},
	}
	for _, c := range cases {
		if got := matchRule(c.rule, c.tgt); got != c.want {
			t.Errorf("matchRule(%q, %+v) = %v, want %v", c.rule, c.tgt, got, c.want)
		}
	}
}

func TestRouterMatch(t *testing.T) {
	r := NewRouter(true, []Route{
		{Rules: []string{"domain:block.me"}, Outs: []Outbound{{Type: "block"}}},
		{Rules: []string{"domain:redir.me"}, Outs: []Outbound{{Type: "redirect", Server: "1.1.1.1", Port: 53}}},
		{Rules: []string{"*"}, Outs: []Outbound{{Type: "direct", Listen: "9.9.9.9"}}},
	})
	if o, ok := r.Match(Target{Host: "x.block.me"}); !ok || o.normalizedType() != "block" {
		t.Fatalf("block route: %+v ok=%v", o, ok)
	}
	if o, ok := r.Match(Target{Host: "redir.me"}); !ok || o.Server != "1.1.1.1" {
		t.Fatalf("redirect route: %+v", o)
	}
	if o, ok := r.Match(Target{Host: "other.com"}); !ok || o.Listen != "9.9.9.9" {
		t.Fatalf("catch-all route: %+v", o)
	}

	// no catch-all -> no match -> connection closed
	r2 := NewRouter(true, []Route{{Rules: []string{"domain:only.me"}, Outs: []Outbound{{Type: "direct"}}}})
	if _, ok := r2.Match(Target{Host: "nope.com"}); ok {
		t.Fatal("expected no match (closed)")
	}
	// disabled -> always direct
	if o, ok := NewRouter(false, nil).Match(Target{Host: "x"}); !ok || o.normalizedType() != "direct" {
		t.Fatalf("disabled router should be direct: %+v", o)
	}
}

func TestDialerDirectAndBlock(t *testing.T) {
	// echo upstream
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
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
	port := atoiT(portStr)

	dir, _ := os.MkdirTemp("", "audit")
	aud := NewAuditor(dir, []string{"*"}, 0)
	aud.nowFn = func() time.Time { return time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC) }

	d := &Dialer{
		Router: NewRouter(true, []Route{
			{Rules: []string{"port:" + portStr}, Outs: []Outbound{{Type: "direct"}}},
			{Rules: []string{"*"}, Outs: []Outbound{{Type: "block"}}},
		}),
		Auditor: aud,
	}

	// direct to the echo port works
	conn, err := d.DialContext(context.Background(), Meta{NodeID: 1, UserID: 7, Protocol: "trojan", Network: "tcp"}, host, port)
	if err != nil {
		t.Fatalf("direct dial: %v", err)
	}
	conn.Write([]byte("ping"))
	buf := make([]byte, 4)
	io.ReadFull(conn, buf)
	if string(buf) != "ping" {
		t.Fatalf("echo mismatch: %q", buf)
	}
	conn.Close()

	// a different port hits the block route
	if _, err := d.DialContext(context.Background(), Meta{NodeID: 1}, "example.com", 9999); err != ErrBlocked {
		t.Fatalf("expected ErrBlocked, got %v", err)
	}

	aud.Close() // flush
	// audit file should contain the connected record for user 7
	data, _ := os.ReadFile(filepath.Join(dir, "domain-audit-node-1-2026-08-09.jsonl"))
	var rec Record
	first := strings.SplitN(strings.TrimSpace(string(data)), "\n", 2)[0]
	if err := json.Unmarshal([]byte(first), &rec); err != nil {
		t.Fatalf("audit json: %v (%s)", err, data)
	}
	if rec.UserID != 7 || rec.Status != "connected" || rec.TargetPort != port {
		t.Fatalf("unexpected audit record: %+v", rec)
	}
}

func TestProxyProtocolV1(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		c2.Write([]byte("PROXY TCP4 203.0.113.7 198.51.100.1 56324 443\r\n"))
		c2.Write([]byte("hello"))
	}()
	pc, err := ReadProxyHeader(c1, true)
	if err != nil {
		t.Fatalf("v1 parse: %v", err)
	}
	if ta, ok := pc.RemoteAddr().(*net.TCPAddr); !ok || ta.IP.String() != "203.0.113.7" || ta.Port != 56324 {
		t.Fatalf("v1 real addr: %v", pc.RemoteAddr())
	}
	got := make([]byte, 5)
	io.ReadFull(pc, got)
	if string(got) != "hello" {
		t.Fatalf("v1 body: %q", got)
	}
}

func TestProxyProtocolV2(t *testing.T) {
	var hdr bytes.Buffer
	hdr.Write(proxyV2Sig)
	hdr.WriteByte(0x21) // v2, PROXY
	hdr.WriteByte(0x11) // AF_INET, STREAM
	addr := make([]byte, 12)
	copy(addr[0:4], net.ParseIP("203.0.113.9").To4())
	copy(addr[4:8], net.ParseIP("198.51.100.1").To4())
	binary.BigEndian.PutUint16(addr[8:10], 50000)
	binary.BigEndian.PutUint16(addr[10:12], 443)
	binary.Write(&hdr, binary.BigEndian, uint16(len(addr)))
	hdr.Write(addr)
	hdr.WriteString("DATA")

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() { c2.Write(hdr.Bytes()) }()
	pc, err := ReadProxyHeader(c1, true)
	if err != nil {
		t.Fatalf("v2 parse: %v", err)
	}
	if ta, ok := pc.RemoteAddr().(*net.TCPAddr); !ok || ta.IP.String() != "203.0.113.9" || ta.Port != 50000 {
		t.Fatalf("v2 real addr: %v", pc.RemoteAddr())
	}
	got := make([]byte, 4)
	io.ReadFull(pc, got)
	if string(got) != "DATA" {
		t.Fatalf("v2 body: %q", got)
	}
}

func TestResolverStrategyOrder(t *testing.T) {
	ips := []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("1.2.3.4")}
	if got := orderByStrategy(ips, "ipv4_first"); got[0].To4() == nil {
		t.Fatal("ipv4_first should put v4 first")
	}
	if got := orderByStrategy(ips, "ipv6_first"); got[0].To4() != nil {
		t.Fatal("ipv6_first should put v6 first")
	}
	if got := orderByStrategy(ips, "ipv4_only"); len(got) != 1 || got[0].To4() == nil {
		t.Fatal("ipv4_only should keep only v4")
	}
}

func atoiT(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

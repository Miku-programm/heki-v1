// Package naive is a RECONSTRUCTION of heki v1.2.8's heki/server/proto/naive
// package, rebuilt from static analysis (IDA/Hex-Rays) of the shipped binary.
// It is behavior-equivalent Go, NOT the original source.
//
// NaiveProxy follows Caddy's forwardproxy semantics: it is an ordinary HTTPS
// server that, for authenticated clients, honors HTTP CONNECT (and GET-tunnel)
// requests and relays to the target; everything else looks like a normal web
// server. Auth is HTTP Proxy-Authorization: Basic. This is heki's own code
// (not a thin wrapper), so the reconstruction is close to complete.
//
// Faithful (observed): the Proxy-Authorization Basic auth (authenticate), the
// CONNECT handling in ServeHTTP, and the bidirectional flushingCopy relay.
// Reconstructed/scoped: identifier names; the outer TLS/HTTP2 server is wired by
// the transport layer.
//
// Built and vet-checked with go1.26.3. Still a reconstruction, not the original.
package naive

import (
	"crypto/subtle"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"heki/node/dataplane"
)

// User is a configured NaiveProxy account (HTTP Basic credentials).
type User struct {
	Email    string
	Username string
	Password string
}

// ServerCallbacks are the runtime hooks (traffic/online-IP/limits).
type ServerCallbacks struct {
	ReportTraffic func(email string, up, down int64)
	ReportAliveIP func(email string, ip net.IP)
	CheckIPLimit  func(email string, ip net.IP) bool
	SpeedLimit    func(email string) int64
}

// Handler is the NaiveProxy server handler; it is an http.Handler.
type Handler struct {
	mu       sync.RWMutex
	users    map[string]*User // username -> user
	callback ServerCallbacks
	dialer   *dataplane.Dialer
}

// SetDialer sets the optional data-plane egress dialer (routing/DNS/audit).
func (h *Handler) SetDialer(d *dataplane.Dialer) { h.dialer = d }

// NewHandler builds a NaiveProxy handler.
func NewHandler(users []*User) *Handler {
	h := &Handler{}
	h.UpdateUsers(users)
	return h
}

func (h *Handler) SetServerCallbacks(cb ServerCallbacks) {
	h.mu.Lock()
	h.callback = cb
	h.mu.Unlock()
}

func (h *Handler) UpdateUsers(users []*User) {
	m := make(map[string]*User, len(users))
	for _, u := range users {
		m[u.Username] = u
	}
	h.mu.Lock()
	h.users = m
	h.mu.Unlock()
}

func (h *Handler) userLimiter(email string) int64 {
	h.mu.RLock()
	cb := h.callback.SpeedLimit
	h.mu.RUnlock()
	if cb == nil {
		return 0
	}
	return cb(email)
}

// authenticate validates the Proxy-Authorization: Basic header, returning the
// user or nil. Constant-time password comparison. Mirrors authenticate.
func (h *Handler) authenticate(r *http.Request) *User {
	const prefix = "Basic "
	authz := r.Header.Get("Proxy-Authorization")
	if authz == "" {
		authz = r.Header.Get("Authorization")
	}
	if !strings.HasPrefix(authz, prefix) {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(authz[len(prefix):])
	if err != nil {
		return nil
	}
	username, password, ok := strings.Cut(string(raw), ":")
	if !ok {
		return nil
	}
	h.mu.RLock()
	u := h.users[username]
	h.mu.RUnlock()
	if u == nil {
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(password), []byte(u.Password)) != 1 {
		return nil
	}
	return u
}

// ServeHTTP handles proxied requests. Authenticated CONNECT requests are relayed
// to the target; anything unauthenticated or non-proxy gets a plain 404 so the
// server is indistinguishable from an ordinary HTTPS site.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user := h.authenticate(r)
	if user == nil {
		// Look like a normal web server (no Proxy-Authenticate challenge).
		http.NotFound(w, r)
		return
	}
	if ip := clientIP(r); ip != nil {
		h.mu.RLock()
		alive, check := h.callback.ReportAliveIP, h.callback.CheckIPLimit
		h.mu.RUnlock()
		if alive != nil {
			alive(user.Email, ip)
		}
		if check != nil && !check(user.Email, ip) {
			http.NotFound(w, r)
			return
		}
	}
	if r.Method == http.MethodConnect {
		h.handleConnect(w, r, user)
		return
	}
	// GET-tunnel / forwardproxy for absolute-URI requests could be handled here;
	// unsupported methods fall through to a 404.
	http.NotFound(w, r)
}

// handleConnect dials the CONNECT target, sends 200, and relays both directions.
func (h *Handler) handleConnect(w http.ResponseWriter, r *http.Request, user *User) {
	_ = h.userLimiter(user.Email)
	host, portStr, _ := net.SplitHostPort(r.Host)
	if host == "" {
		host = r.Host
	}
	port, _ := strconv.Atoi(portStr)
	clientIP := ""
	if ip := dataplane.HostIP(r.RemoteAddr); ip != nil {
		clientIP = ip.String()
	}
	upstream, err := dataplane.DialOrDirect(r.Context(), h.dialer, dataplane.Meta{
		UserEmail: user.Email, Protocol: "naive", Network: "tcp",
		ClientIP: clientIP,
	}, host, port)
	if err != nil {
		http.Error(w, "", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		// HTTP/2: use the Flusher + request body as the client stream.
		w.WriteHeader(http.StatusOK)
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		up, down := relayH2(r.Body, w, upstream)
		h.report(user.Email, up, down)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	up, down := relayConn(client, upstream)
	h.report(user.Email, up, down)
}

func (h *Handler) report(email string, up, down int64) {
	h.mu.RLock()
	report := h.callback.ReportTraffic
	h.mu.RUnlock()
	if report != nil {
		report(email, up, down)
	}
}

// flushingCopy copies src->dst, flushing dst after every write so tunneled data
// is not buffered. Mirrors flushingCopy.
func flushingCopy(dst io.Writer, src io.Reader, flush func()) int64 {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total
			}
			if flush != nil {
				flush()
			}
			total += int64(n)
		}
		if rerr != nil {
			return total
		}
	}
}

func relayH2(clientBody io.Reader, w http.ResponseWriter, upstream net.Conn) (up, down int64) {
	flush := func() {
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
	}
	done := make(chan struct{})
	go func() { up = flushingCopy(upstream, clientBody, nil); done <- struct{}{} }()
	down = flushingCopy(w, upstream, flush)
	<-done
	return
}

func relayConn(client, upstream net.Conn) (up, down int64) {
	done := make(chan struct{})
	go func() { up = copyAll(upstream, client); done <- struct{}{} }()
	down = copyAll(client, upstream)
	<-done
	return
}

func copyAll(dst io.Writer, src io.Reader) int64 {
	n, _ := io.Copy(dst, src)
	return n
}

// HandleConn adapts a raw connection into the HTTP server (HandleConn); in the
// node the outer TLS server calls ServeHTTP directly.
func (h *Handler) HandleConn(conn net.Conn) error {
	srv := &http.Server{Handler: h}
	return srv.Serve(newSingleConnListener(conn))
}

func clientIP(r *http.Request) net.IP {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return net.ParseIP(host)
	}
	return nil
}

// singleConnListener serves exactly one accepted connection, then blocks.
type singleConnListener struct {
	conn net.Conn
	ch   chan net.Conn
}

func newSingleConnListener(c net.Conn) *singleConnListener {
	ch := make(chan net.Conn, 1)
	ch <- c
	return &singleConnListener{conn: c, ch: ch}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	c, ok := <-l.ch
	if !ok {
		return nil, io.EOF
	}
	close(l.ch)
	return c, nil
}
func (l *singleConnListener) Close() error   { return l.conn.Close() }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

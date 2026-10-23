package vless

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// RealityConfig holds the REALITY parameters pulled from the panel. REALITY
// borrows a real site's TLS certificate: authorized clients complete a normal
// TLS 1.3 handshake, while unauthorized / probing connections are transparently
// forwarded to the real site so the server is indistinguishable from it.
//
// Fields recovered from buildRealityConfig.
type RealityConfig struct {
	Dest        string   // the real site to steal certs from / fall back to, host:port
	ServerNames []string // allowed SNIs
	PrivateKey  [32]byte // server x25519 private key
	ShortIDs    []string // allowed short_id values (hex)
	Fingerprint string   // client TLS fingerprint to emulate (chrome, firefox, ...)
	SpiderX     string   // spider path
	Xver        int      // proxy-protocol version to the dest
}

// knownFingerprints are the uTLS fingerprints REALITY accepts.
var knownFingerprints = map[string]struct{}{
	"chrome": {}, "firefox": {}, "safari": {}, "ios": {}, "android": {},
	"edge": {}, "360": {}, "qq": {}, "random": {}, "randomized": {},
}

// BuildRealityConfig validates raw REALITY settings into a RealityConfig.
// Mirrors buildRealityConfig's checks (error strings recovered from the binary).
func BuildRealityConfig(dest string, serverNames []string, privateKey []byte, shortIDs []string, fingerprint, spiderX string, xver int) (*RealityConfig, error) {
	if len(privateKey) != 32 {
		return nil, fmt.Errorf("reality private key must be 32 bytes, got %d", len(privateKey))
	}
	if fingerprint == "" {
		return nil, fmt.Errorf("vless reality config: empty public_key")
	}
	fp := strings.ToLower(strings.TrimSpace(fingerprint))
	if _, ok := knownFingerprints[fp]; !ok {
		return nil, fmt.Errorf("vless reality config: unknown fingerprint %q", fingerprint)
	}
	c := &RealityConfig{
		Dest:        dest,
		ServerNames: serverNames,
		ShortIDs:    shortIDs,
		Fingerprint: fp,
		SpiderX:     spiderX,
		Xver:        xver,
	}
	copy(c.PrivateKey[:], privateKey)
	return c, nil
}

// FallbackTarget is a real site to forward unauthorized connections to. When a
// RealityConfig is present, its Dest is the natural fallback.
type FallbackTarget struct {
	Host string
	Port int
}

// doFallback transparently forwards a connection (with whatever bytes were
// already read) to the real site, so an unauthorized / probing client sees the
// genuine upstream. Mirrors (*Handler).doFallback.
func (h *Handler) doFallback(conn net.Conn, consumedHeader *RequestHeader) error {
	h.mu.RLock()
	fb := h.fallback
	reality := h.reality
	h.mu.RUnlock()

	target := ""
	switch {
	case fb != nil:
		target = net.JoinHostPort(fb.Host, strconv.Itoa(fb.Port))
	case reality != nil && reality.Dest != "":
		target = reality.Dest
	default:
		return fmt.Errorf("vless: no fallback configured")
	}

	upstream, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return err
	}
	defer upstream.Close()

	go io.Copy(upstream, conn)
	io.Copy(conn, upstream)
	return nil
}

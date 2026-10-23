// Package realityx is a REAL REALITY server layer: it drives the upstream
// github.com/sagernet/reality library (the same code sing-box uses) to
// terminate REALITY handshakes, then hands the authenticated connection to a
// normal handler (heki's VLESS handler). REALITY "borrows" a real TLS site's
// certificate: the server relays the handshake to Dest and, for an authorized
// client, completes a REALITY TLS 1.3 session; unauthorized clients are
// transparently proxied to Dest (steal-oneself), so they only ever see the
// real site.
//
// Note on testing: an authorized-client round trip requires a uTLS-based
// REALITY client (as in xray/sing-box), which is out of scope here. The
// realityx test validates the genuine library behavior that IS reachable
// in-process: the handshake relay to Dest for a non-authorized client.
package realityx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"

	reality "github.com/sagernet/reality"
	"golang.org/x/crypto/curve25519"
)

// Options configures a REALITY server.
type Options struct {
	PrivateKey  []byte   // 32-byte x25519 private key
	ServerNames []string // allowed SNI (must include Dest's cert name)
	ShortIDs    []string // allowed short IDs, hex (<=16 hex chars -> 8 bytes)
	Dest        string   // the borrowed real TLS 1.3 site, host:port
}

// GenerateKeyPair returns a fresh x25519 private/public key pair. The public
// key (base of the client's "public_key") pairs with the server's PrivateKey.
func GenerateKeyPair() (priv, pub []byte, err error) {
	priv = make([]byte, 32)
	if _, err = rand.Read(priv); err != nil {
		return nil, nil, err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

func buildConfig(opt Options) (*reality.Config, error) {
	if len(opt.PrivateKey) != 32 {
		return nil, errors.New("realityx: private key must be 32 bytes")
	}
	if opt.Dest == "" {
		return nil, errors.New("realityx: Dest is required")
	}
	names := make(map[string]bool, len(opt.ServerNames))
	for _, n := range opt.ServerNames {
		names[n] = true
	}
	shortIDs := make(map[[8]byte]bool, len(opt.ShortIDs)+1)
	for _, s := range opt.ShortIDs {
		var id [8]byte
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, errors.New("realityx: invalid short id " + s)
		}
		copy(id[:], b)
		shortIDs[id] = true
	}
	if len(shortIDs) == 0 {
		shortIDs[[8]byte{}] = true // allow the empty short id by default
	}
	return &reality.Config{
		DialContext: (&net.Dialer{}).DialContext,
		Type:        "tcp",
		Dest:        opt.Dest,
		ServerNames: names,
		PrivateKey:  opt.PrivateKey,
		ShortIds:    shortIDs,
	}, nil
}

// Listener wraps an inner net.Listener and terminates REALITY on each
// connection. Accept returns only authorized REALITY connections; unauthorized
// ones are consumed by the library (proxied to Dest).
type Listener struct {
	inner  net.Listener
	cfg    *reality.Config
	conns  chan net.Conn
	closed chan struct{}
}

// NewListener builds a REALITY-terminating listener over inner.
func NewListener(inner net.Listener, opt Options) (*Listener, error) {
	cfg, err := buildConfig(opt)
	if err != nil {
		return nil, err
	}
	l := &Listener{inner: inner, cfg: cfg, conns: make(chan net.Conn), closed: make(chan struct{})}
	go l.loop()
	return l, nil
}

func (l *Listener) loop() {
	for {
		c, err := l.inner.Accept()
		if err != nil {
			return
		}
		go func() {
			rc, err := reality.Server(context.Background(), c, l.cfg)
			if err != nil {
				return // unauthorized/invalid: already handled (relayed to Dest)
			}
			select {
			case l.conns <- rc:
			case <-l.closed:
				_ = rc.Close()
			}
		}()
	}
}

// Accept returns the next authorized REALITY connection.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

// Close stops the listener.
func (l *Listener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return l.inner.Close()
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

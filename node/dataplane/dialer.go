package dataplane

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"
)

// Meta carries per-connection context used for routing, source binding, and
// auditing.
type Meta struct {
	NodeID         int
	UserID         int
	UserEmail      string // resolved to UserID via Dialer.ResolveUserID when set
	Protocol       string
	Network        string // "tcp" / "udp"
	ClientIP       string // real client IP (after PROXY protocol, if any)
	IngressLocalIP net.IP // local IP the client connected to (for auto_out_ip)
}

// ErrBlocked is returned when routing blocks or does not match a connection.
var ErrBlocked = fmt.Errorf("dataplane: connection closed by routing")

// Dialer ties routing, DNS resolution, source-IP binding (auto_out_ip), and
// auditing into one egress dial used by the protocol handlers.
type Dialer struct {
	Router        *Router
	Resolver      *Resolver // nil => system resolver
	Auditor       *Auditor  // nil => no audit
	AutoOutIP     bool      // bind egress source to the ingress local IP
	NodeID        int       // default node id for audit records
	ResolveUserID func(email string) int
	Timeout       time.Duration
}

// DialOrDirect dials host:port through d when it is non-nil, otherwise with a
// plain net dial. It lets handlers stay dialer-agnostic.
func DialOrDirect(ctx context.Context, d *Dialer, meta Meta, host string, port int) (net.Conn, error) {
	if d != nil {
		return d.DialContext(ctx, meta, host, port)
	}
	nd := net.Dialer{Timeout: 10 * time.Second}
	return nd.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
}

// DialContext resolves, routes, binds the egress source, dials, and audits.
func (d *Dialer) DialContext(ctx context.Context, meta Meta, host string, port int) (net.Conn, error) {
	// Resolve the host (for IP-based routing and the dial target).
	var ip net.IP
	if parsed := net.ParseIP(host); parsed != nil {
		ip = parsed
	} else if d.Resolver != nil {
		if ips, err := d.Resolver.Resolve(ctx, host); err == nil && len(ips) > 0 {
			ip = ips[0]
		}
	}

	out, matched := d.Router.Match(Target{Host: hostForRules(host), IP: ip, Port: port, NodeID: meta.NodeID})
	if !matched {
		d.audit(meta, host, ip, port, host, "", "rejected")
		return nil, ErrBlocked
	}

	target := host
	targetPort := port
	switch out.normalizedType() {
	case "block":
		d.audit(meta, host, ip, port, host, "block", "blocked")
		return nil, ErrBlocked
	case "redirect":
		if out.Server != "" {
			target = out.Server
		}
		if out.Port != 0 {
			targetPort = out.Port
		}
	}

	// Source IP: routes Out.Listen > auto_out_ip (ingress local IP) > system.
	var localAddr net.Addr
	if bindIP := d.sourceBind(out, meta); bindIP != nil {
		localAddr = &net.TCPAddr{IP: bindIP}
	}

	nd := net.Dialer{LocalAddr: localAddr, Timeout: d.timeout()}
	addr := net.JoinHostPort(target, strconv.Itoa(targetPort))

	var (
		conn net.Conn
		err  error
	)
	switch out.normalizedType() {
	case "direct", "redirect":
		conn, err = nd.DialContext(ctx, "tcp", addr)
	case "socks":
		conn, err = dialViaSOCKS(ctx, nd, out, target, targetPort)
	case "http":
		conn, err = dialViaHTTP(ctx, nd, out, target, targetPort)
	case "trojan":
		conn, err = dialViaTrojan(ctx, nd, out, target, targetPort)
	case "vless":
		conn, err = dialViaVLESS(ctx, nd, out, target, targetPort)
	case "ss", "shadowsocks":
		conn, err = dialViaSS(ctx, nd, out, target, targetPort)
	case "anytls":
		conn, err = dialViaAnyTLS(ctx, out, target, targetPort)
	case "vmess":
		conn, err = dialViaVMess(ctx, nd, out, target, targetPort)
	default:
		d.audit(meta, host, ip, port, addr, out.Type, "unsupported")
		return nil, fmt.Errorf("dataplane: unsupported outbound type %q", out.Type)
	}
	if err != nil {
		d.audit(meta, host, ip, port, addr, out.normalizedType(), "failed")
		return nil, err
	}
	d.audit(meta, host, ip, port, addr, out.normalizedType(), "connected")
	return conn, nil
}

func (d *Dialer) sourceBind(out Outbound, meta Meta) net.IP {
	switch out.Listen {
	case "":
		// no explicit bind: fall through to auto_out_ip
	case "auto":
		return meta.IngressLocalIP
	default:
		if ip := net.ParseIP(out.Listen); ip != nil {
			return ip
		}
	}
	if d.AutoOutIP && meta.IngressLocalIP != nil && !meta.IngressLocalIP.IsUnspecified() {
		return meta.IngressLocalIP
	}
	return nil
}

func (d *Dialer) timeout() time.Duration {
	if d.Timeout > 0 {
		return d.Timeout
	}
	return 15 * time.Second
}

func (d *Dialer) audit(meta Meta, host string, ip net.IP, port int, outAddr, outbound, status string) {
	if d.Auditor == nil {
		return
	}
	targetIP := ""
	if ip != nil {
		targetIP = ip.String()
	}
	nodeID := meta.NodeID
	if nodeID == 0 {
		nodeID = d.NodeID
	}
	userID := meta.UserID
	if userID == 0 && d.ResolveUserID != nil {
		userID = d.ResolveUserID(meta.UserEmail)
	}
	d.Auditor.Record(Record{
		NodeID:     nodeID,
		UserID:     userID,
		Protocol:   meta.Protocol,
		Network:    meta.Network,
		ClientIP:   meta.ClientIP,
		Target:     net.JoinHostPort(host, strconv.Itoa(port)),
		TargetHost: host,
		TargetIP:   targetIP,
		TargetPort: port,
		Outbound:   outbound,
		Status:     status,
	})
}

// hostForRules returns the host used for rule matching (empty when host is a
// literal IP, so domain rules don't accidentally match an IP string).
func hostForRules(host string) string {
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}

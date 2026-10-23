package dataplane

import (
	"context"
	"net"
)

type ingressIPKey struct{}

// WithIngressIP attaches the ingress local IP (the address the client connected
// to) to ctx, for auto_out_ip source binding downstream.
func WithIngressIP(ctx context.Context, ip net.IP) context.Context {
	if ip == nil {
		return ctx
	}
	return context.WithValue(ctx, ingressIPKey{}, ip)
}

// IngressIP returns the ingress local IP from ctx, or nil.
func IngressIP(ctx context.Context) net.IP {
	ip, _ := ctx.Value(ingressIPKey{}).(net.IP)
	return ip
}

// HostIP extracts the IP from a "host:port" or "host" address string.
func HostIP(addr string) net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return net.ParseIP(host)
}

// RemoteIP returns the IP string of a net.Addr (empty when not an IP address).
func RemoteIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	if ip := HostIP(addr.String()); ip != nil {
		return ip.String()
	}
	return ""
}

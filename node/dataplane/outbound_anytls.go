package dataplane

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"

	anytls "github.com/anytls/sing-anytls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

// dialViaAnyTLS chains the destination through an AnyTLS outbound, reusing the
// upstream sing-anytls client over a TLS connection to the proxy.
func dialViaAnyTLS(ctx context.Context, out Outbound, host string, port int) (net.Conn, error) {
	sni := out.SNI
	if sni == "" {
		sni = out.Server
	}
	cli, err := anytls.NewClient(ctx, anytls.ClientConfig{
		Password: out.Password,
		Logger:   logger.NOP(),
		DialOut: func(ctx context.Context) (net.Conn, error) {
			raw, err := net.Dial("tcp", net.JoinHostPort(out.Server, strconv.Itoa(out.Port)))
			if err != nil {
				return nil, err
			}
			tc := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: out.SkipCertVerify})
			if err := tc.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return tc, nil
		},
	})
	if err != nil {
		return nil, err
	}
	return cli.CreateProxy(ctx, M.ParseSocksaddrHostPort(host, uint16(port)))
}

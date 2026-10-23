module heki

go 1.26.0

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/anytls/sing-anytls v0.0.13
	github.com/apernet/hysteria/core/v2 v2.12.2
	github.com/apernet/hysteria/extras/v2 v2.12.2
	github.com/enfein/mieru/v3 v3.38.0
	github.com/refraction-networking/utls v1.8.3-0.20260301010127-aa6edf4b11af
	github.com/sagernet/sing v0.9.0
	github.com/sagernet/sing-quic v0.7.0
	github.com/sagernet/sing-vmess v0.2.8
	github.com/xtls/reality v0.0.0-20260322125925-9234c772ba8f
	github.com/xtls/xray-core v1.260327.0
	golang.org/x/crypto v0.58.0
	google.golang.org/protobuf v1.36.12
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/apernet/quic-go v0.61.1-0.20260806010916-184d081eef3e // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/gofrs/uuid/v5 v5.5.1 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/juju/ratelimit v1.0.2 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/metacubex/utls v1.8.7 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/pires/go-proxyproto v0.11.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/sagernet/quic-go v0.61.0-sing-box-mod.6 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	golang.org/x/exp v0.0.0-20250911091902-df9299821621 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/tools v0.51.0 // indirect
	google.golang.org/grpc v1.79.3 // indirect
)

replace github.com/anytls/sing-anytls => ./patches/sing-anytls

# 跑一个节点(对接面板)

`cmd/node` 是在重建库之上打通的**可运行节点**:从面板拉用户 → 监听 → 鉴权 → relay → 定时上报流量。

## 可运行的协议(已端到端验证)
| 协议 | 传输 | 端到端测试 |
|---|---|---|
| **trojan** | TCP+TLS | ✅ `go test ./node -run Trojan` |
| **vless**(非 REALITY) | TCP+TLS | ✅ `go test ./node -run VLESS` |
| **ss**(aes-128/256-gcm) | TCP(自带加密) | ✅ `go test ./node -run SS` |
| **hysteria2** | QUIC/UDP | ✅ `go test ./node -run Hysteria2`(接 apernet 真库) |
| **tuic** | QUIC/UDP | ✅ `go test ./node -run TUIC`(接 sing-quic 真库,TCP 中继) |
| **anytls** | TCP+TLS(会话复用+padding) | ✅ `go test ./node -run AnyTLS`(接 sing-anytls 真库) |
| **mieru** | 私有混淆传输(TCP) | ✅ `go test ./node -run Mieru`(接 enfein/mieru 真库) |
| **vless-reality** | REALITY(偷 TLS 握手) | ✅ `go test ./node -run VLESSReality`(真 uTLS 授权客户端,完整 vless-over-REALITY 往返) |
| **vmess** | TCP+TLS | 已接线(handler 完整,未单独 e2e) |
| **naive** | TCP+TLS(HTTP/1.1 CONNECT) | 已接线 |

> 五个特殊传输全部接上游真库:`hysteria2`(apernet)、`tuic`(sing-quic)、`anytls`(sing-anytls)、`mieru`(enfein/mieru)、`vless-reality`(sagernet/reality)。
>
> **REALITY 说明**:服务端用的是 sing-box 同款 `sagernet/reality` 真库。授权往返已用**自带的真 uTLS REALITY 客户端**(`transport/realityx/realityc`,refraction-networking/utls)跑通完整 e2e:session_id 鉴权(x25519 共享密钥 + AES-GCM 封装 version/time/shortID)→ 服务端 HMAC-SHA512 证书验证 → VLESS 往返 → 回报面板。未授权连接仍会透明中继到 `dest`(偷自己证书)。生产用 xray/sing-box 的 REALITY 客户端对接即可。

## 编译
```bash
git clone https://github.com/Miku-programm/heki-v1.git && cd heki-v1
go build -o heki-node ./cmd/node
```

## 配置 `config.json`
```json
{
  "protocol":   "trojan",
  "method":     "aes-256-gcm",
  "panel_type": "sspanel",
  "panel_url":  "https://your-panel.com",
  "panel_key":  "你的通信密钥",
  "node_id":    1,
  "listen":     ":443",
  "tls_cert":   "/etc/heki/certs/fullchain.pem",
  "tls_key":    "/etc/heki/certs/privkey.pem",
  "fallback_host": "www.bing.com",
  "fallback_port": 443,
  "sync_interval_sec":   60,
  "report_interval_sec": 30
}
```
- `protocol`:`trojan`/`vmess`/`vless`/`vless-reality`/`ss`/`naive`/`anytls`/`hysteria2`/`tuic`/`mieru`。
- `method`:仅 `ss` 用(`aes-128-gcm` / `aes-256-gcm` / `chacha20-ietf-poly1305`)。
- `ss`/`mieru`/`vless-reality` 不需要 TLS 证书(各自自带加密/握手);`hysteria2`/`tuic` 用证书但走 QUIC/UDP;其余走 TLS,填 `tls_cert`/`tls_key`。
- `panel_*`/`node_id`:与 XrayR/V2bX 的 ApiHost/ApiKey/NodeID 同义。
- `panel_type`:`heki-v1`(heki 自有协议,推荐)/ `sspanel` / `xboard`(含 v2board/xiaov2board)/ `ppanel` / `metron`。

### 对接 heki 自有面板(`panel_type: heki-v1`)
`heki-v1` 是 heki 对外公开的版本化控制面 WebAPI([官方文档](https://hekicore.github.io/heki-docs/#/panel/heki-v1-webapi))。本重建已按规范实现:

- 五个接口(`panel_url` 为基址,自动拼 `/api/v1/nodes/{node_id}`):
  - `GET  /api/v1/nodes/{id}`、`GET /api/v1/nodes/{id}/users`
  - `POST /api/v1/nodes/{id}/traffic`、`/alive-ips`、`/status`
- Bearer 鉴权(`Authorization: Bearer <panel_key>`),请求头带 `User-Agent: heki`、`X-Heki-Node-Id`、`Accept: application/json, application/problem+json`;
- 响应用 `{"data": …}` 外层包装(也兼容裸对象/数组),GET 走 `ETag`/`If-None-Match`(304 复用缓存),错误用 RFC 7807(`application/problem+json`);
- 上报体:`traffic` = `{"records":[{"user_id","u","d"}]}`,`alive-ips` = `{"records":[{"user_id","ips":[…]}]}`;
- Node 对象的 `protocol` 会解析并归一(别名 `v2ray/shadowsocks/shadowsocksr/hysteria` 自动映射到规范名),连同 `listen/limits/scheduler/security.reality` 一起暴露在 `NodeInfo` 上;用户 `banned/disabled/enabled=false` 会自动过滤。当前节点仍以 `config.json` 的 `protocol` 启动(请与面板下发保持一致)。

```json
{
  "protocol":   "vless",
  "panel_type": "heki-v1",
  "panel_url":  "https://api.example.com/heki",
  "panel_key":  "your-api-key",
  "node_id":    1,
  "listen":     ":443"
}
```
> 已验证:`go test ./panel -run HekiV1`(线协议一致性)+ `go test ./node -run HekiV1`(节点对接 heki-v1 后端跑通 trojan 全链路并按 `{"records":[…]}` 回报)。

### REALITY(`protocol: vless-reality`)
先生成密钥对:
```bash
./heki-node -genkey
# private_key (server): <hex>   放进 config
# public_key  (client): <hex>   给客户端
```
再在 `config.json` 加 `reality` 段(不需要 `tls_cert`):
```json
{
  "protocol": "vless-reality",
  "panel_type": "sspanel", "panel_url": "...", "panel_key": "...", "node_id": 1,
  "listen": ":443",
  "reality": {
    "private_key":  "<hex 32 字节>",
    "dest":         "www.microsoft.com:443",
    "server_names": ["www.microsoft.com"],
    "short_ids":    ["", "0123abcd"]
  }
}
```
用 xray/sing-box 的 REALITY 客户端对接(public_key / server_name / short_id 与上面一致)。

### Hysteria2 混淆与带宽(`protocol: hysteria2`)
按文档,`obfs=salamander` + `obfs_password` 才启用 Salamander 混淆(真库 `apernet/hysteria/extras` 实现);客户端需用相同 PSK。可选带宽上限 `up_mbps/down_mbps`:
```json
{
  "protocol": "hysteria2",
  "panel_type": "sspanel", "panel_url": "...", "panel_key": "...", "node_id": 1,
  "listen": ":443", "tls_cert": "...", "tls_key": "...",
  "hysteria2": { "obfs_password": "你的混淆密码", "up_mbps": 100, "down_mbps": 100 }
}
```
> 已验证:`go test ./node -run Hysteria2Obfs`(两端真 Salamander 混淆跑通 QUIC 往返)。SS `chacha20-ietf-poly1305` 也补齐:`go test ./node -run SSChaCha20`。

### 更多协议细节(按文档补齐)
- **TUIC 参数**:`config.json` 加 `tuic` 段可配 `congestion_control`(默认 `cubic`,可选 `bbr`/`new_reno`)、`zero_rtt_handshake`、`auth_timeout_sec`、`heartbeat_sec`、`udp_timeout_sec`。验证 `go test ./node -run TUICZeroRTT`(0-RTT + bbr 路径跑通)。
- **AnyTLS UoT(UDP over TCP)**:`anytls` 现支持 UDP——客户端按 sing UoT(magic 地址 `sp.v2.udp-over-tcp.arpa` + `uot.Request`)发包,节点中继到真实 UDP 目标并计流量。验证 `go test ./node -run AnyTLSUoT`(真数据报往返)。
- **VMess alterId**:`alterId==0` 走 VMessAEAD;保留 `alterId>0` 则按 heki 行为锁定到 **VMessMD5-only**(该用户从 AEAD 匹配中排除,避免 AEAD/MD5 混跑),遗留认证为 `HMAC-MD5(id, 时间戳)`(主 UUID + AlterID 链,带时钟窗口)。验证 `go test ./server/proto/vmess -run AlterIDModeLock`。遗留 AES-CFB 请求体已废弃、未接线——按文档建议订阅里直接删掉 alterId 走 AEAD。

## 节点运维/网络面(routes / DNS / 源进源出 / 真实 IP / 审计)
节点内置一个数据面(`node/dataplane`),按文档实现了常用运维能力,均有测试。

### 多路由多出口(`routes.toml`)
`-r routes.toml` 或 config 里 `routes_file`;按顺序匹配规则,命中后随机选一个出口;启用后未命中则关闭连接。
```toml
enable=true
[[routes]]
rules=["geosite:netflix","domain:google.com","ip:1.2.3.4/24","port:1000-2000","node_id:1"]
[[routes.Outs]]
type="socks"      # direct / block(reject) / redirect / socks / http
server="proxy.example.com"
port=1080
[[routes]]
rules=["*"]
[[routes.Outs]]
type="direct"
listen=""          # 出口网卡 IP(源绑定);留空由系统决定
```
> 规则匹配支持 `domain:`/`domain-keyword:`/`full:`/`ip:`/`cidr:`/`port:`/`node_id:`/`regexp:`/`glob:`/裸串/`*`(`geosite:`/`geoip:` 需 .dat 文件,未内置→不命中)。出口已实现 `direct`/`block`/`redirect`/`socks`/`http`,以及**链式代理出站 `trojan`/`vless`**(TLS,`password`/`uuid`/`sni`/`skip_cert_verify`)。链式出站示例:
> ```toml
> [[routes.Outs]]
> type="trojan"      # 或 vless
> server="exit.example.com"
> port=443
> password="落地密码"  # vless 用 uuid="..."
> sni="exit.example.com"
> skip_cert_verify=false
> ```

### 源进源出(`auto_out_ip`)
config 里 `auto_out_ip=true`:按用户连入的入口本地 IP 绑定出口源 IP。优先级 `routes.toml 的 listen` > `auto_out_ip` > 系统默认。

### DNS 规则(`dns.yml`)
`-d dns.yml` 或 `dns_rules_file`;按域名规则选 DNS 服务器与策略;`default_dns`/`dns_strategy` 兜底。优先级 dns.yml > default_dns > 系统。
```yaml
8.8.8.8:53,1.1.1.1:
  strategy: ipv4_first     # ipv4_first/ipv4_only/ipv6_first/ipv6_only
  rules:
    - domain:google.com
1.1.1.1:
  - domain:youtube.com     # 省略 strategy/rules,直接列规则
```
> DNS 地址支持裸 `8.8.8.8[:port]`、`tcp://`、`tcp-tls://`(当前按 TCP/UDP 解析;DoH 回退 UDP)。

### 中转获取真实 IP(PROXY protocol)
config 里 `proxy_protocol=true`(可加 `force_proxy_protocol=true`):TCP/TLS 入站先读 PROXY protocol v1/v2 头,拿到真实源 IP(TLS 在读头之后终结)。真实 IP 会进入审计与路由匹配。

### 域名访问审计(JSONL)
config 里 `domain_audit_enable=true`、`domain_audit_domains=api.ip.sb,cidr:198.51.100.0/24,glob:check-*.example.com`、`domain_audit_log_dir`、`domain_audit_retention_days`。命中规则的连接按节点+日期写 JSONL(字段同 heki:`time/node_id/user_id/protocol/network/client_ip/target/target_host/target_ip/target_port/status`),非阻塞队列 + 短窗去重 + 按保留天清理。

> 验证:`go test ./node/dataplane`(规则/路由/PROXY v1+v2/审计/策略单测)+ `go test ./node -run Dataplane`(AnyTLS 全链路:PROXY 真实 IP → 路由 direct → 审计落盘,断言 client_ip)+ `go test ./node -run Chained`(两节点链:client→anytls(A)→trojan/vless 出站→落地(B)→echo)。数据面已接入**全部 TCP/QUIC 协议**出站(trojan/vless/ss/vmess/naive/anytls/tuic/mieru;hysteria2 由 apernet 内部直连,未接)。

## 运行
```bash
./heki-node -c config.json
```
用对应协议的**标准客户端**连(trojan/vmess/vless/ss/naive),密码/UUID 取面板里该用户的字段。

## 已验证
`go test ./...` 全过,其中 `./node` 跑了 **trojan/vless/ss 三条真实端到端闭环**(假面板 + 真客户端 + echo 上游):拉用户 → 鉴权 → 数据往返 → 流量回报面板。

## 范围声明
行为重建,非原始 heki 源码。QUIC/REALITY 系需上游库,生产使用请自行评估。

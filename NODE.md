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
- `method`:仅 `ss` 用(aes-128-gcm / aes-256-gcm)。
- `ss`/`mieru`/`vless-reality` 不需要 TLS 证书(各自自带加密/握手);`hysteria2`/`tuic` 用证书但走 QUIC/UDP;其余走 TLS,填 `tls_cert`/`tls_key`。
- `panel_*`/`node_id`:与 XrayR/V2bX 的 ApiHost/ApiKey/NodeID 同义。

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

## 运行
```bash
./heki-node -c config.json
```
用对应协议的**标准客户端**连(trojan/vmess/vless/ss/naive),密码/UUID 取面板里该用户的字段。

## 已验证
`go test ./...` 全过,其中 `./node` 跑了 **trojan/vless/ss 三条真实端到端闭环**(假面板 + 真客户端 + echo 上游):拉用户 → 鉴权 → 数据往返 → 流量回报面板。

## 范围声明
行为重建,非原始 heki 源码。QUIC/REALITY 系需上游库,生产使用请自行评估。

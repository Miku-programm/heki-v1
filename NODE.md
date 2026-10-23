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
| **vmess** | TCP+TLS | 已接线(handler 完整,未单独 e2e) |
| **naive** | TCP+TLS(HTTP/1.1 CONNECT) | 已接线 |

> `hysteria2`(apernet)、`tuic`(sing-quic)、`anytls`(sing-anytls)、`mieru`(enfein/mieru)已接上游真库跑通端到端。`vless-REALITY` 需 xtls/reality,handler 已把传输抽象成接口。

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
- `protocol`:`trojan`/`vmess`/`vless`/`ss`/`naive`。
- `method`:仅 `ss` 用(aes-128-gcm / aes-256-gcm)。
- `ss` 不需要 TLS 证书(自带加密);其余走 TLS,填 `tls_cert`/`tls_key`(你域名的证书)。
- `panel_*`/`node_id`:与 XrayR/V2bX 的 ApiHost/ApiKey/NodeID 同义。

## 运行
```bash
./heki-node -c config.json
```
用对应协议的**标准客户端**连(trojan/vmess/vless/ss/naive),密码/UUID 取面板里该用户的字段。

## 已验证
`go test ./...` 全过,其中 `./node` 跑了 **trojan/vless/ss 三条真实端到端闭环**(假面板 + 真客户端 + echo 上游):拉用户 → 鉴权 → 数据往返 → 流量回报面板。

## 范围声明
行为重建,非原始 heki 源码。QUIC/REALITY 系需上游库,生产使用请自行评估。

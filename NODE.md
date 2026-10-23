# 跑一个节点(trojan over TLS,对接面板)

`cmd/node` 是在重建库之上打通的**最小可运行节点**:从面板拉用户 → TLS 监听 → trojan 鉴权 → relay → 定时上报流量。目前支持 **trojan / TCP+TLS**,面板支持 **sspanel / xboard / ppanel / metron / hekiv1**(端点见 `panel/`)。

## 编译
```bash
git clone https://github.com/Miku-programm/heki-v1.git && cd heki-v1
go build -o heki-node ./cmd/node
```

## 配置 `config.json`
```json
{
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
- `panel_type`:面板类型。`panel_url`/`panel_key`/`node_id`:对接参数(和 XrayR/V2bX 的 ApiHost/ApiKey/NodeID 同义)。
- `tls_cert`/`tls_key`:节点的 TLS 证书(用你域名的证书;可用 acme.sh/Caddy 签发)。
- `fallback_*`:鉴权失败时透明回落的真站(抗主动探测)。

## 运行
```bash
./heki-node -c config.json
```
启动后它会:拉取用户、在 `:443` 起 TLS 监听、接受 trojan 客户端、鉴权通过就 relay、按 `report_interval_sec` 把流量上报回面板。客户端用标准 **Trojan** 客户端(密码=面板里该用户的密码/UUID,取决于面板字段)。

## 已验证
`go test ./node/` 跑了一个**真实端到端闭环**(假面板 + 真 TLS trojan 客户端 + echo 上游):拉到用户、鉴权通过、数据往返、流量回报面板,`PASS`。

## 范围与后续
- 现在只打通了 **trojan/TCP+TLS** 这一条。vmess/vless(非 REALITY)over TCP+TLS 可按同样方式接(handler 已在,缺监听+accounting 接线);REALITY/QUIC 系(vless-reality/hysteria2/tuic/mieru)还需补被抽象的传输层。
- 在线 IP 上报(aliveip)、限速(speedlimit)回调已在 handler 预留,node 里按需接 `ReportAliveIP`/`CheckIPLimit`/`SpeedLimit` 即可。
- 这是行为重建,非原始 heki;生产使用请自行评估。

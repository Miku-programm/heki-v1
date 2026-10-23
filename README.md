# heki v1.2.8 —— 作者自有内核的重建工程(单一 go module)

> ⚠️ **这不是 heki 的原始源代码。** heki 为闭源,原始源码不公开。本仓库是**行为等价的重建/重实现**:协议栈从剥离符号的二进制逆向重建;`heki-v1 WebAPI`、`routes.toml`/`dns.yml`、审计等照**官方公开文档**实现;特殊传输(hysteria2/tuic/anytls/mieru/reality)接**真实上游库**;链式出站等照协议**公开线格式**实现。可编译、可对接面板、有端到端测试,但**不等于** heki 内部源码,生产使用请自行评估。

这是对 heki v1.2.8 **作者自有内核(`heki/*`)** 的人工重建,基于对其二进制的静态反编译(IDA/Hex-Rays),合并为一个可整体编译的 Go module。

- 目标:`heki-v1.2.8`,SHA-256 `0ed51b5357dda79b02fcd0ac463b5ccf1ff9653d68a27334efa54904fa81450d`
- module:`heki`,Go 1.26,**仅标准库**。
- ✅ **整体 `go build ./...` 与 `go vet ./...` 通过**(go1.26.3)。
- 规模:62 个 `.go`,约 7800 行,12 个包。

## 这是什么
heki 的内核由作者自写:授权系统、面板对接/调度、服务端编排,以及十种代理协议的服务端 handler(鉴权、用户体系、门控、计费限速、relay)。本工程把这些 `heki/*` 包全部重建并放回真实导入路径:

```
heki/
├── license/                      授权(Ed25519 验签 + 机器指纹 + 在线/离线 + 缓存 HMAC)
├── panel/                        5 种面板客户端(sspanel/xboard/ppanel/metron/hekiv1)+ Scheduler 三循环门控
└── server/proto/
    ├── vmess/                    AEAD/legacy 鉴权、kdf、AES-GCM、SessionHistory 防重放、数据面 relay/mux/UDP/IP缓存
    ├── ssr/                      cipher/protocol(auth_chain)/obfs 三层 + 暴力兜底 + UDP NAT
    ├── anytls/                   padding scheme(crypto/rand)+ 空闲会话看门狗 + tag 鉴权/宽限
    ├── vless/                    UUID/flow + Vision + REALITY + 后量子 X25519+ML-KEM-768
    ├── trojan/                   hex(SHA-224) 鉴权 + 回落真站
    ├── ss/                       SS-AEAD(HKDF-SHA1)+ SS-2022 EIH + UDP NAT
    ├── hysteria2/                鉴权器 + Brutal/Salamander 配置 + 三回调 + 在线 IP 记账
    ├── tuic/                     UUID+密码 + 宽限 + ECH + UDP-over-QUIC 处理面
    ├── mieru/                    rebuild 生命周期 + 签名鉴权 + 内层 SOCKS5 + PROXY protocol
    └── naive/                    HTTP/2 CONNECT + Basic 鉴权 + flushingCopy
```

## 编译验证
```
cd heki-reconstructed-full
go build ./...   # OK
go vet  ./...    # 无警告
go list ./...    # 12 个包,import path 为 heki/license、heki/server/proto/vmess ...
```

## 重要声明
- **这是 Hex-Rays 行为重建,不是原始源码。** 原始 `.go`(注释、变量名、精确结构)随编译+strip 永久丢失,不可还原;本工程是**等价、可编译、行为对齐**的重写,标识符/注释为重建。
- **范围**:关键算法尽量照搬并用标准库实现;依赖作者私有补丁库(sing-vmess/sing-anytls/mieru/sing-quic)或大型 QUIC/REALITY 库的底层传输,抽象为接口并注明;少数需第三方的密码学(chacha20、blake3)标为可注入/unsupported;各包数据面 relay 视情况为完整实现或带注释骨架(见各包内 README/doc.go)。
- 依赖库的**原始真源码**是公开的,不在此工程(见 `heki_真源码_依赖清单` / `heki-deps-src/`)。

*基于用户自有二进制的静态分析重建。未运行原程序。*

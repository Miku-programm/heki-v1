# heki 内核用了哪些库 —— 二进制实锤 + 本工程对齐情况

> 结论先行:heki "独立后端,不基于任何 core" 指的是**不套 Xray/sing-box 整框架**,但它**大量 vendor 并打补丁**地链接了 apernet / sagernet(sing)/ anytls / enfein(mieru)/ xtls 这些**单协议库**。本工程的特殊传输同样接这些库,架构是忠实的。

## 实锤来源
`go version -m heki-v1.2.8` 的嵌入 buildinfo + gopclntab 符号表(`heki-symbols-name2addr.tsv`)。符号表里每个库的函数数量(都是真正编译进去并调用的,非死代码):

| 库 | heki 二进制里的函数数 |
|---|---|
| apernet/hysteria | 239 |
| sagernet/sing-quic/tuic | 115 |
| anytls/sing-anytls | 120 |
| enfein/mieru | 769 |
| xtls/reality | 546 |
| xtls/xray-core | 1137 |
| sagernet/sing-vmess | 286 |
| apernet/quic-go | 1485 |
| sagernet/quic-go | 1254 |

## heki 实际链接版本 vs 本工程

| 协议 | heki buildinfo | 本工程 | 对齐 |
|---|---|---|---|
| hysteria2 | `apernet/hysteria/core/v2 v2.12.2` + `apernet/quic-go` | 同 `v2.12.2` | ✅ 完全一致 |
| tuic | `sagernet/sing-quic v0.7.0`(`./patches/`)+ `sagernet/quic-go` | `v0.7.0`(原版) | ✅ 同库同版(未打私有补丁) |
| anytls | `anytls/sing-anytls v0.0.13`(`./patches/`) | `v0.0.13`(原版) | ✅ 同库同版 |
| mieru | `enfein/mieru/v3 v3.38.0`(`./patches/`) | `v3.38.0`(原版) | ✅ 同库同版 |
| vmess | `sagernet/sing-vmess v0.2.8`(`./patches/`) | `v0.2.8`(原版,`transport/vmessx`) | ✅ 同库同版 |
| 底层 sing | `sagernet/sing v0.9.0` | `v0.9.0` | ✅ 一致 |
| vless-reality | `xtls/reality` + `xtls/xray-core` | `xtls/reality`(heki build-info 确切版本 `v0.0.0-20260322125925`) | ✅ 同库同版 |

## 两点说明(诚实)

1. **私有补丁 `./patches/*` 无法逐行复刻**:heki 对 sing-quic / sing-anytls / mieru / sing-vmess 都打了本地补丁(buildinfo 里是 `=> ./patches/... (devel)`,无 module hash,源码不公开)。补丁**改动面**能从二进制符号 diff 出来(例:sing-anytls 的补丁是把 Stream 收包改成 pipe + recv-pump,并重构了帧/握手),但**函数体逐行复刻**需从剥离符号的 Go 二进制反编译,输出粗糙、且无源码可验证,不保证一致——本工程用**原版未打补丁的同版本库**,线协议一致、内部实现非 heki 那份补丁。

2. **REALITY 已对齐 `xtls/reality`(heki 的确切库+版本)**:用 `xtls/reality@v0.0.0-20260322125925`(只需 Go 1.24)。自带的 uTLS 授权客户端(`transport/realityx/realityc`)**无需改动**即与它互通——授权往返 e2e 通过(`go test ./node -run VLESSReality`)。关键点:xtls/reality 授权路径会**模仿 Dest 的握手后记录长度**,这些长度由 `reality.DetectPostHandshakeRecordsLens`(xray 启动时也调)探测 Dest 得到;`realityx` 在建监听器时调用它,否则授权连接会一直等这个"学习结果"而卡住(首连有一次探测等待,约 5s)。

## 本工程的协议栈构成(和 heki 同路子)
- trojan / vless / ss / naive:标准库自写服务端(逆向重建,heki 这部分也是自有实现)。
- vmess:`sagernet/sing-vmess`(= heki 的库)。
- hysteria2 / tuic / anytls / mieru:各自上游库(= heki 的库,原版未打补丁)。
- vless-reality:`xtls/reality`(= heki 的库,确切版本)+ 自带 uTLS 授权客户端(互通已验证)。
- 数据面(路由/DNS/审计/PROXY protocol/链式出站):标准库自写。

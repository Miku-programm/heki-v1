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
| vless-reality | `xtls/reality` + `xtls/xray-core v1.260327.0` | 经 `xtls/xray-core v1.260327.0` 的 `transport/internet/reality.Server` 驱动 `xtls/reality v0.0.0-20260322125925` | ✅ 同库同版+同集成层 |
| utls(reality 依赖) | `refraction-networking/utls v1.8.3-0.20260301010127` + `metacubex/utls v1.8.7` | 同(接入 xray-core 后由 MVS 自动对齐) | ✅ 完全一致 |

## 两点说明(诚实)

1. **私有补丁 `./patches/*`(无 module hash、源码不公开)**:heki 对 sing-quic / sing-anytls / mieru / sing-vmess 都打了本地补丁(buildinfo 里是 `=> ./patches/... (devel)`)。

   **已恢复并落地:`patches/sing-anytls`。** 用 IDA/Hex-Rays 反编译了二进制里的 `(*Stream).Read` / `runRecvPump` / `enqueueRecvItem` / `newStream`,确认 heki 的补丁是:在 `Session.recvLoop` 和 Stream 的 pipe 之间插入一条**异步接收队列 + 每流 `runRecvPump` goroutine**(慢读的流不再阻塞整个会话的 recvLoop——消除队头阻塞),并把 die-error 改成**原子存取**(消除竞态)。本工程按此在 `patches/sing-anytls/session/stream.go`+`session.go` 重建了该补丁,并像 heki 一样用 `replace github.com/anytls/sing-anytls => ./patches/sing-anytls` 挂上。验证:`go build`/`-race` 通过、**该库自带的 `session` 测试通过**(含 64KiB 大包/分帧测试)、节点 anytls e2e(含 UoT/链式)通过。这是**对该补丁行为的重建**,非 heki 逐字节源码。

   **sing-vmess:IDA 核查后未见可复现补丁。** 反编译核心 `(*AEADChunkReader).Read` 与原版 v0.2.8 一致(标准 VMess 分块读);符号层也无新增函数——先前的"heki-only"是方法提升 + 死代码消除(未用的 mux / DialEarly / ClientWith* 被裁)造成的噪声。结论:**没有可验证的语义补丁可重建,原版 v0.2.8 已忠实**(vmess 链路 e2e 对着它跑通)。不凭空捏造补丁。

   **mieru:IDA 深挖后未见确认的行为补丁。** 顺着文档提到的"空 TCP 回收 / ~6 分 30 秒会话复用宽限",定位到 `ScheduleController.Idle`/`TryDisableIdle`(对比全局 `scheduleIdleTime`)和 replay 缓存窗口。反编译 `protocol.init` 确认 heki 的 replay 缓存 = `NewCache(4MB, 360s)`,而原版 v3.38.0 就是 `KeyRefreshInterval(120s)*3 = 360s`——**完全一致**。文档里的空闲宽限是 mieru 原版的本地资源策略(非线协议),heki 直接继承。`scheduleIdleTime` 的赋值在 Go 拆分出的多段 init 里、经间接存储,难以干净定位,但它是本地资源常量,不影响线协议/代理行为。结论:**未发现可确认的行为补丁,原版 v3.38.0 忠实。**

   **sing-quic:IDA 挖到唯一的库补丁,但影响很小。** 去掉泛型/congestion 噪声后,`tuic` 子包里唯一 heki 新增、原版没有的函数是 **`tuic.releaseCongestion`**(原版全库无此函数)。反编译它:`newCubicSender(DefaultClock{timeFunc}, reno=false, packetSize, 32*packetSize, 20000*packetSize)` 再 `SetCongestionControl`,由 `serverSession.closeWithError` 调用——即**在 TUIC 会话拆除前后重装一个 cubic 拥塞控制器**。但那两个窗口参数 `32 / 20000` 和**原版默认常量 `initialCongestionWindow=32` / `MaxCongestionWindowPackets=20000` 完全一致**——所以不是窗口调参,只是"重置拥塞控制器"这个动作;收益存疑(连接级 close 时重置近乎无效),且调用点语义从反编译看不够确切,**故不重建**(低置信、边际收益、还可能有害)。`serverConn.Peek/SetDeadline/handle*Frame` 等"heki-only"是 `serverConn` 内嵌 `*quic.Stream` 的**方法提升**产物,非补丁。

   文档提到的 TUIC "**2/6/3/15 MB 流/连接窗口**"不是 sing-quic 补丁,而是 heki 在 TUIC 胶水层设的 quic.Config/QUICOptions 值。**本工程已在 `transport/tuicx` 对齐该意图**:默认设宽松接收窗(6 MiB 流 / 15 MiB 连接,可配 `Options.StreamReceiveWindow`/`ConnectionReceiveWindow`),`go test ./node -run TUIC` 通过。

   **小结**:heki 四个私有 `./patches/` 里,只有 **sing-anytls** 有清晰、可复原、可验证的**行为补丁**(已重建应用);sing-vmess / mieru 经 IDA 核查**未见可确认的行为补丁**(核心函数/关键常量与原版一致);sing-quic 无可下手信号。私有 fork 的补丁未必都是行为改动——有的是编译裁剪、构建/兼容微调或本地资源常量。

2. **REALITY 已对齐到 heki 的确切集成层(xray-core 的 reality transport + xtls/reality)**:服务端握手**经 `github.com/xtls/xray-core v1.260327.0` 的 `transport/internet/reality.Server` 驱动**(该函数是个薄封装:内部调 `github.com/xtls/reality.Server(context.Background(), c, cfg)` 并返回其认证后的连接),而不是直接调底层库——这正是 heki 链接的同一条 REALITY 胶水路径(heki buildinfo 同时链接 `xtls/reality` 与 `xtls/xray-core v1.260327.0`,二者本工程均用其确切版本)。

   **附带收益:utls 自动对齐。** 接入 xray-core 后,Go 的 MVS 把 `refraction-networking/utls` 从本工程先前的 `v1.8.2` 升到 heki buildinfo 的**确切版本 `v1.8.3-0.20260301010127-aa6edf4b11af`**,并带入 `metacubex/utls v1.8.7`(indirect)——与 heki buildinfo **逐版本一致**。

   自带的 uTLS 授权客户端(`transport/realityx/realityc`)**无需改动**即与之互通——授权往返 e2e 通过(`go test ./node -run VLESSReality`)。关键点:xtls/reality 授权路径会**模仿 Dest 的握手后记录长度**,这些长度由 `reality.DetectPostHandshakeRecordsLens`(xray 启动时也调)探测 Dest 得到;`realityx` 在建监听器时调用它,否则授权连接会一直等这个"学习结果"而卡住(首连有一次探测等待,约 5s)。

## 本工程的协议栈构成(和 heki 同路子)
- trojan / vless / ss / naive:标准库自写服务端(逆向重建,heki 这部分也是自有实现)。
- vmess:`sagernet/sing-vmess`(= heki 的库)。
- hysteria2 / tuic / anytls / mieru:各自上游库(= heki 的库,原版未打补丁)。
- vless-reality:经 `xtls/xray-core` 的 `transport/internet/reality.Server` 驱动 `xtls/reality`(= heki 的同一集成层+确切版本)+ 自带 uTLS 授权客户端(互通已验证)。
- 数据面(路由/DNS/审计/PROXY protocol/链式出站):标准库自写。

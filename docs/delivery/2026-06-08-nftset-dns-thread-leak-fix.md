# 技术交付文档：修复 nftset-dns 线程泄漏

Feature: 修复 nftset-dns 长时间运行线程泄漏耗尽容器 PID 配额的问题
Type: T3 — 行为变更（与既有同步语义冲突）；Secondary: T6 — 直接依赖 libnftables 共享库
Date: 2026-06-08
Status: Implemented（改动已落地于本地仓库，未部署至现网容器）
基线 commit: `18042c7`（performance optimize）
改动范围: `dnserver/main.py`（+136 / −21）

---

## 1. 背景与动机（Background & Motivation）

### 现象
nftset-dns 长时间运行后线程数持续增长且不回收，最终占满容器 PID 配额（`pids.max = 3908`），导致：
- 容器内任何命令报 `can't fork: Resource temporarily unavailable`；
- 同容器内 dnsmasq 无法响应 DNS，整个局域网 DNS 瘫痪；
- 依赖该 DNS 的下游（v2ray、OpenVPN 隧道等）全部断连。

发现问题时（2026-06-07）两个实例线程数分别约 2521 / 1359，合计逼近 cgroup 上限 3908；kill 后容器立即恢复。

### 运行环境
- Raspberry Pi (aarch64)，Linux 6.6.51+rpt-rpi-v8；
- OpenWrt 24.10 docker 容器（`openwrt/rootfs:aarch64_generic-openwrt-24.10`），由 procd 的 ipset-dns 服务拉起；
- 上游 DNS：218.2.2.2；容器内 `nftables v1.0.9`，`libnftables.so.1`（1.1.0）存在。

### 根因（Root Cause）
旧实现中，每个 A/AAAA 查询线程执行：

```python
self.nft_executor.submit(self.nft_add, result).result()   # 同步阻塞
```

其中 `nft_executor = ThreadPoolExecutor(max_workers=1)`，worker 内部用 **无超时的 `os.system('nft add ...')`** fork 一个 shell 再 fork `nft`。问题叠加：

1. **单 worker + 同步阻塞**：所有 A/AAAA 请求线程串行排队挤进唯一 worker，并阻塞在 `.result()`。
2. **`os.system` 无超时**：一旦某次 `nft` 卡住（nf_tables 内核锁竞争，或系统已临近 PID 耗尽导致 `fork` 受阻），唯一 worker **永久卡死**，其后**所有** A/AAAA 请求线程永久堵在 `.result()` 不退出。
3. **dnslib `ThreadingMixIn` 无并发上限**：每请求一线程，被 (1)(2) 卡住时无法回收 → 线程只增不减 → PID 耗尽。
4. **次要放大**：每查询 `os.system` 还多 fork 一个 `/bin/sh`，PID 紧张时雪上加霜，并带 shell 注入面；每查询一条 INFO 日志在高 QPS 下刷爆日志。

> 注：dnslib 的请求线程是 daemon 线程，正常跑完会回收；因此单纯上游慢只造成可恢复的瞬时堆积。真正「不回收」的是 (2) 描述的 nft worker 永久卡死。

---

## 2. 提案变更（Proposed Change）

> **解决方案（一句话）**：把「写 nftset」从「单 worker 线程池 + 同步阻塞 + 无超时 `os.system`」改为「请求线程非阻塞入队 → 单后台 worker 进程内调用 libnftables 执行」，使请求线程的生命周期与 nft 写入彻底解耦，从根上消除线程堆积；并加去重缓存、有界队列、启动自检与线程数监控。

### What changes（变更点）
1. **进程内 nft 后端 `_NftBackend`**：用 `ctypes` 绑定 `libnftables.so.1`，在本进程内执行 `add element ...`，**零 fork、无 shell**。
2. **fail-fast 自检**：启动时加载 `.so` + 创建 ctx + 跑只读 `list tables` 自检；任一步失败即抛异常，服务**启动失败退出**，而非静默降级。
3. **异步解耦 + 有界队列**：请求线程仅 `put_nowait` 入队后立即返回退出；队列满（`NFT_QUEUE_MAXSIZE=2048`）则丢弃并限频告警，**永不阻塞 DNS 应答**。
4. **单后台 worker 消费**：独占 nft ctx（保证线程安全）；即使 worker 卡住，最坏只是丢弃 nft 更新，不再泄漏请求线程。
5. **去重缓存（LRU + TTL）**：`(set, ip)` 在 `NFT_CACHE_TTL=600s` 内命中即跳过；缓存上限 `NFT_CACHE_MAXSIZE=65536`。TTL 让 set 被外部 flush 后能自愈重加。
6. **线程数监控**：后台每 `THREAD_MONITOR_INTERVAL=60s` 输出 `active threads: N`。
7. **降日志噪声**：每查询的 `proxying` 日志从 INFO 降为 DEBUG。
8. **`stop()` 守卫**：start 在自检失败时中途退出的情况下，`stop()` 不再因 server 为 `None` 抛 `AttributeError` 掩盖真实错误。

### What does NOT change（范围边界）
- 对外 DNS 协议、端口、上游代理逻辑、命令行参数（`ipv4_set ipv6_set port upstream`）均不变；
- nftset 目标仍是 `inet fw4` 下的具名 set；元素内容与格式不变；
- 非 NFT 的 `DNSServer` / `ProxyResolver` 主流程不变（仅 proxying 日志降级影响到它）。

### New behavior（新行为）
- nft 写入变为**异步**：客户端可能在 IP 进入 nftset 前极短时间（毫秒级）拿到应答；
- 过载时**丢弃** nft 更新（有界队列）而非阻塞或泄漏；
- libnftables 不可用或无权限时**启动即失败**。

### Implementation Details（实现维度覆盖）

| Dimension | Changes | Notes |
|-----------|---------|-------|
| DB changes | N/A — 本项目无数据库 | |
| Environment variables | N/A — 未新增/变更环境变量 | 调优项以模块常量形式提供：`NFT_QUEUE_MAXSIZE` / `NFT_CACHE_MAXSIZE` / `NFT_CACHE_TTL` / `THREAD_MONITOR_INTERVAL` |
| Business logic flow | DNS 查询 → `ProxyResolverWithNFT.resolve` → 上游解析得到 `result` → 若 A/AAAA 则 `nft_add` 把 (set, ips) **非阻塞入队** → 立即返回应答、请求线程退出。后台 `nft-writer` worker：`queue.get` → `_dedup`（按 TTL 过滤）→ `_NftBackend.run('add element inet fw4 <set> { ips }')` | 请求线程不再等待 nft 完成 |
| API changes | N/A — 无对外 API | DNS 报文行为不变 |
| Async / background tasks | 新增 2 个 daemon 线程：`nft-writer`（消费有界队列写 nft）、`thread-monitor`（周期打印线程数）；移除原 `ThreadPoolExecutor(max_workers=1)` | 队列 `maxsize=2048`，满则丢弃 |
| Configuration | 无 feature flag；调优常量见上 | |
| External service calls | 新增：通过 `ctypes` 直接调用 `libnftables.so.1`（进程内，零 fork）；移除：`os.system('nft ...')` | 启动自检 `list tables` 验证可达 + 权限 |

---

## 3. 影响范围（Impact Scope）

- **Files**：`dnserver/main.py`（唯一改动文件）。
- **Modules affected**：
  - `ProxyResolverWithNFT`（重写：去重+有界队列+异步 worker）；
  - 新增 `_NftBackend`、`_start_thread_monitor`；
  - `ProxyResolver.resolve`（一行日志降级）；
  - `DNSServer.stop`（None 守卫）；
  - `DNSServerWithNFT.start`（启动线程监控）。
- **APIs / contracts**：无（CLI 参数、DNS 协议不变）。
- **Data structures**：进程内新增 `_queue: queue.Queue`、`_seen: OrderedDict`（均为运行时状态，不持久化）。
- **Critical paths**：DNS 解析热路径（每查询都经过 `ProxyResolverWithNFT.resolve`）—— YES。
- **External dependencies**：新增对 `libnftables.so.1` ABI 的直接依赖（`nft_ctx_new` / `nft_ctx_buffer_output` / `nft_ctx_buffer_error` / `nft_run_cmd_from_buffer` / `nft_ctx_get_error_buffer` / `nft_ctx_free`）。
- **Features that depend on changed behavior**：依赖 nftset 被及时填充来做按域名分流/防火墙的下游（v2ray / OpenVPN 路由）—— 受异步时序的极小窗口影响（见风险）。

---

## 4. 分类（Feature Classification）

**Type: T3 — 行为变更**（异步 nft 写入与「先写后回」的旧同步语义冲突；过载丢弃语义为新增）。
**Secondary: T6 — 外部依赖**（从 `os.system` 调 `nft` 二进制改为直接绑定 `libnftables.so.1` ABI）。

Reason：核心风险来自语义变化（写入时序由同步改异步、过载丢弃、启动 fail-fast），符合 T3「新行为与既有假设冲突」；同时引入对共享库 ABI 的直接依赖，带 T6 特征。

Impact summary：
- Files affected: 1
- Modules affected: `ProxyResolverWithNFT` / `_NftBackend` / `_start_thread_monitor` / `DNSServer.stop` / `DNSServerWithNFT.start`
- Critical paths: YES（DNS 解析热路径）
- External dependencies: YES（libnftables.so.1）

### Conflict Map（T3）

| 位置 | 旧假设 | 必须处理 | 处理方式 |
|------|--------|----------|----------|
| `ProxyResolverWithNFT.resolve` | 「nftset 写入完成后才返回应答」（同步） | YES | 改为异步入队；接受首包可能未命中规则的极小窗口（见 §5） |
| nft 写入失败处理 | `os.system` 返回码被忽略 | YES | worker 读取 libnftables 错误缓冲并 `logger.warning` |
| 过载时的行为 | 无界排队（线程堆积直至 PID 耗尽） | YES | 有界队列 + 满则丢弃 + 限频告警 |
| libnftables 缺失/无权限 | （旧路径走二进制，PATH 决定） | YES | 启动自检 fail-fast 抛错退出 |

### Breaking Change Analysis（T6 — libnftables）

| 变更 | 是否影响我们 | 说明 |
|------|--------------|------|
| 由 `nft` CLI 二进制改为 `libnftables.so.1` | YES（受控） | 二者同源；`.so.1` SONAME ABI 稳定，所用符号为公开稳定 API |
| 重复 `add element` 已存在元素 | NO | 实测该版本 `add` 幂等返回 rc=0、无报错；去重缓存仅为省开销 |
| 输出缓冲未开启时执行 `list` | YES（已规避） | 实测会段错误；故 ctx 创建后**立即**开启 output+error 缓冲再执行任何命令 |
| 上游 set/table flush 后元素丢失 | YES（已缓解） | 缓存 TTL=600s，过期后自动重加，自愈 |

---

## 5. 副作用与风险（Side Effects & Risks）

明确列出（“无副作用”不可接受）：

1. **异步时序窗口**：nft 写入异步化后，客户端可能在 IP 进 nftset 前的毫秒级窗口内拿到应答，导致**首包**未命中按域名的防火墙/路由规则。权衡：相较「整 LAN DNS 瘫痪」，偶发首包未命中可接受；多数客户端会复用后续连接而命中。
2. **过载丢弃**：队列满（>2048 待写）时丢弃 nft 更新并限频告警。极端突发下个别新域名 IP 可能漏写；可通过调大 `NFT_QUEUE_MAXSIZE` 缓解。被丢弃次数在日志中可见。
3. **fail-fast 启动失败**：libnftables 不可用/无权限时服务**直接退出**（经与需求方确认，接受此行为，后续再针对该场景修复）。需确保容器具备相应权限（现状已能写 nft）。
4. **ctypes/ABI 脆弱性**：误用（如未开输出缓冲执行 `list`）可能导致段错误使进程崩溃。已通过「创建即开缓冲、仅单 worker 线程持有 ctx、参数签名显式声明」规避，并在容器内实测稳定。
5. **缓存内存占用**：`_seen` 上限 65536 条 `(set, ip)→expiry`，内存占用可忽略（~数 MB 量级上限）。
6. **TCP 无超时未处理**：dnslib `DNSHandler` 对 TCP 连接 `recv` 无超时，半开 TCP 连接仍可能永久占用 handler 线程。**本次按需求方意见未修**，作为遗留次要隐患记录。

**Reversible**: YES
**Rollback approach**: 该改动仅涉及 `dnserver/main.py`，`git revert` 或回退到基线 commit `18042c7` 即可完全恢复旧行为；无数据迁移、无持久化状态变更。

---

## 6. 类比排查（Analogical Investigation）

- **本次解决的模式**：「每请求开线程 + 同步等待一个无超时外部操作」导致的线程/资源堆积。
- **已排查的相似位置**：
  - `ProxyResolver`（基类）/ `BaseResolver`：仅做上游代理，上游查询已有 dnslib 的 5s 超时，无 `os.system` / 无线程池阻塞 —— 无同类问题。
  - 全仓 `os.system` / `subprocess` / `ThreadPoolExecutor` 调用点：经检索仅 `ProxyResolverWithNFT` 一处，已修复。
- **后续任务**：
  - （建议）为 dnslib TCP handler 增加读取超时，消除半开连接泄漏（本次未做）。
  - （可选）引入上游响应缓存以降低上游往返与线程存活时长。
  - （可选）缓存 `resolve()` 中按查询重建的 `Record` 列表（nftset 场景 zones 为空，收益≈0，暂不做）。

---

## 7. 验证情况（Verification）

在 OpenWrt 容器内用**一次性测试表 `inet __dnstest__`**（不触碰 fw4 / 现网规则，用完即删）实测，均通过：

- `libnftables.so.1` 加载、`nft_ctx_new`、开启 output/error 缓冲、`list tables` 自检 → rc=0，无段错误；
- `add element inet __dnstest__ s4 { 1.1.1.1, 8.8.8.8 }` 写入 → `list set` 确认两个 IP 均在；
- 重复 `add` 已存在元素 → rc=0，无报错（确认 `add` 幂等）；
- 错误缓冲不跨命令累积（读取后无需手动重置）；
- `delete table inet __dnstest__` 清理 → rc=0，无残留；
- 本地 `python3 -m py_compile dnserver/main.py` 通过。

> 现网容器仍运行旧代码，本次**未重启/替换线上服务**；部署时更新包至容器即可。

---

## Decision Log

### Step: nft 写入时序 — Decision Discussion
**Decision point (option comparison)**：
- 方案 A：异步、解耦——请求线程拿到应答即返回，nft 写入丢进有界后台队列；
- 方案 B：保持同步——仍先写 nftset 再返回，但全程加超时、去单 worker 瓶颈。

**Additional context**：需求方关注单 worker 下「每任务执行时间能否控制」，以及「能否不 fork 进程完成 nft add」。

**Rationale**：方案 A 把线程数与 nft 速率彻底解耦，最不易再泄漏；其代价（首包可能未命中规则的毫秒级窗口）相较「整 LAN DNS 瘫痪」可接受。方案 B 仍保留单 worker 串行瓶颈，高 QPS 下线程仍可能短时堆积。

**Decision**：采用方案 A（异步解耦）。

### Step: nft 执行机制（避免 fork）— Decision Discussion
**Decision point (option comparison)**：
- A 现成 `nftables` Python 模块（进程内，零 fork）——容器内 `ModuleNotFoundError`，不可用；
- A' 自写极小 `ctypes` 绑定直调 `libnftables.so.1`（进程内，零 fork）——`.so` 存在且实测可用；
- B 常驻 `nft -i` 子进程（仅启动 fork 一次）；
- C `subprocess.run(['nft','-f','-'], timeout=...)`（每次仍 fork，但有超时、无 shell）。

**Additional context**：自写 ctypes 绑定初次测试出现段错误（exit 139）；定位为「未开输出缓冲即执行 `list`」误用，开启缓冲后稳定。

**Rationale**：A 不可用；A' 经容器实测稳定且彻底零 fork，从根上消除 PID 压力，优于 B/C。

**Decision**：采用 A'（ctypes 直调 libnftables），B/C 作为概念兜底但不实现。

### Step: 绑定不可用时的处理 — Decision Discussion
**Decision point (option comparison)**：
- 静默回退到 subprocess（保证可用性，但掩盖问题）；
- fail-fast：绑定/自检失败即启动报错退出（显式、安全）。

**Additional context**：需求方明确「可以接受 ctypes 绑定不成功时启动失败，后续再针对该场景修复」。

**Rationale**：nftset-dns 的全部意义即写 nftset，写不了仍在跑等于掩盖故障；显式失败更安全。

**Decision**：采用 fail-fast，移除静默 subprocess 回退；并增加只读 `list tables` 自检验证库+权限+内核可达。

### Step: TCP 无超时 — Decision Discussion
**Decision point**：是否在本次一并修复 dnslib TCP handler 无读取超时导致的半开连接线程泄漏。
**Rationale**：UDP 为主路径，TCP 为次要隐患；需求方选择本次不处理。
**Decision**：本次不修，作为遗留隐患记录于 §5 / §6。

---

## 设计完成（Design Complete）

Feature: 修复 nftset-dns 线程泄漏
Type: T3（Secondary T6）
交付文档: `docs/delivery/2026-06-08-nftset-dns-thread-leak-fix.md`
状态: 已实现，待部署验证

下一步：将改动打包更新至容器灰度，观察 `active threads` 日志与 nftset 填充情况后再全量。

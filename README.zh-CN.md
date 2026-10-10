# WVmp（中文）

一个自研的 PE 虚拟机保护壳。将 x86/x64 Windows 可执行文件中的标记区域翻译为自研的寄存器式虚拟机（169 ops，跳表调度），通过 stub-link 派发回原 native 代码。

![x64 direct](https://img.shields.io/badge/x64_direct-99.26%25-brightgreen)
![x86 direct](https://img.shields.io/badge/x86_direct-95.15%25-green)
![wvmpTest x86](https://img.shields.io/badge/wvmpTest_x86-96.3%25-yellowgreen)
![baseline](https://img.shields.io/badge/baseline-390%2F390-brightgreen)

> **语言**： [English](README.md) | **简体中文**

## 支持目标

| 架构 | Machine | 状态 |
|---|---|---|
| **x64 (PE32+)** | 0x8664 | **生产可用** |
| **x86 (PE32)** | 0x14C | **生产可用**（WOW64 已验证）|

Native 客户端代码路径不变。被标记的区域（两段连续 8 字节 magic）翻译为自研寄存器式虚拟机（169 ops，跳表 256 项）。输出在 `byte-exact` 校验下保持行为字节级一致——完整支持矩阵见 [docs/GAPS.md](docs/GAPS.md) 的**「指令族支持矩阵（当前口径，2026-09-19 实测 · 单一真源）」节**：该节是本文所有量化读数（`kVmOpMax` 169 / 跳表 256 / baseline 390 / x87 与 ymm 的 arch 归属 / gate 分档）的**单一真源**。两处不一致时以 GAPS 为准，本文件的这一格即为待修错误。

指令面亮点（2026-09 ~ 10）：**AVX/VEX.256**——x64 侧完整 ymm 数据通路（`vmov*` + 18 条 packed 算术、`vzeroupper`/`vzeroall`、按需 stub ymm 同步）及 `vextractf128`/`vinsertf128` 桥（MIT-533）；**x87 FPU**——x86 侧虚拟化（L0–L4：load/store、比较、fcmov、超越函数）；**VEX-GP BMI2**——`mulx`/`pdep`/`pext` 寄存器形在 x64 侧 native 直发（MIT-534，最低机器契约已接受，`[bmi2] require` 开关）。各指令族在另一侧架构均按架构 gate 处理——见下方 Gate 边界。

## Gate 边界（已文档化，非缺陷）

含被 gate 指令的区域保持 native 执行、输出字节级一致，但不做虚拟化。Gate 分三类（分档定义与各族当前判定以 [docs/GAPS.md](docs/GAPS.md) §「gate 分档（三档…）」为准，下表是其镜像）：

**架构 gate**（该架构的代码生成不产生该指令族）：

| 指令族 | 范围 | 说明 |
|---|---|---|
| x87 FPU (D8-DF) | x64 区域 | MSVC x64 浮点默认走 SSE；x87 在 x86 侧已虚拟化（MIT-509/510）。|
| ymm / VEX.256 | x86 区域 | MSVC x86 无 VEX 发射面（MIT-511）。|
| EVEX（0x62 前缀）| 双架构 | 尚未 lift。|

**频率 gate**（证据驱动翻面；挂账追踪 MIT-521）：

| 指令族 | 重审触发条件 |
|---|---|
| legacy SSE 与 ymm 同函数混排 | 整函数保持 native；出现真实保护样本需要混排协议时翻面（MIT-514）。|
| VEX-GP BMI2 **mem 形**（`mulx`/`pdep`/`pext` 带内存操作数）| `/Od` intrinsic 代码生成恒为 mem 形，此类函数当前保持 native；寄存器形已入面（MIT-534）。支持路径沿用 SSE mem 源通路（MIT-408 同款）。|

**永久**：

| 指令族 | 为何永久 |
|---|---|
| 间接 jmp（`jmp [mem]`/`jmp reg`）| 静态可分析的"表形"在 System32 / SysWOW64 全语料中占比 < 0.001%；主导形态需要 L 级运行时分析。（MIT-455 §3.2、MIT-494x。）|
| SEH（`fs:[...]`）/段覆盖 | 需要与 Windows 异常派发器协作，超出当前研究线范围。|

历史注记：x87 与 mul64hi 栈深边界曾是永久 gate——两者均已翻案（x87 → 分架构虚拟化，MIT-509/510；mul64hi → esp-resync 前瞻 + callee `ret N` 扫描，MIT-497/500，x86 22/22 区域全虚拟化）。两条原频率 gate 项也已落地：`vextractf128`/`vinsertf128` 桥（+2 VmOp，MIT-533）与 BMI2 最低机器契约及寄存器形直发（+3 VmOp，MIT-534，2026-09-28 用户接受）。当前状态表见 [docs/GAPS.md](docs/GAPS.md)。

## 配置（TOML）

打包行为经 TOML 配置：每函数保护档位（`default_level` + `[[functions]]` 规则，MIT-457）、每函数 crypt 豁免（`[[functions]] crypt = false`）、机器契约开关 `[avx] require` / `[bmi2] require`（默认 `true`；置 `false` 时含 AVX/BMI2 词的函数保持 native，使打包产物可在老机器上运行，MIT-518/534），以及泄露溯源用的 `[watermark]`（见下一节）。

## 水印溯源（泄露副本反查发行对象）

2026-10-10 交付（MIT-541 v1 + M2 + MIT-542）。每个保护副本可携带唯一水印；副本泄露后用 `wvmp scan` 反查出自哪次发行。

**保护时嵌入**——`[watermark]` 三种 `mode`（`padding` / `junk` / `both`，默认 `padding`；值为十六进制 + `?` 半字节通配，16-64 字符、固定位 ≥12）：

```toml
[watermark]
id     = "Customer_A"        # 缺省 = value 前 8 字符
value  = "4D5A90??1A2B3C4D"
copies = 3                   # 冗余份数（1-8）
mode   = "padding"           # padding | junk | both
fragments = 2                # padding 面：切 2-4 片分散嵌入
issue_log = "watermark_issues.tsv"  # 发行台账（TSV）
```

- **padding**——模式（或分散碎片）落在产出节表尾垫内；扫描端按碎片多数票识别。
- **junk**——水印 4 字节块骑在 **crypt 豁免函数**（`[[functions]] crypt = false`）的 junk-Mov `imm32` 里，即明文 blob 的 VM 词流内部。要求管道含 `mutate` 且值字节为 4 的倍数；任一块未能在明文 blob 面核实可见即打包失败（MIT-542 结果级核对——覆盖 x86 白名单 gate 把载体函数保持原生的情形）。
- **both**——两面都嵌；junk 面失效降级为警告，padding 面仍携带水印。

`--watermark <value>` 按次覆盖配置值。

**泄露副本反查**：

```bat
wvmp scan --in leaked.exe --registry watermarks.toml
```

登记表列已知水印（`[[watermarks]]` id/value/mode/fragments）；过相似对在解析期拒绝（通配感知的包含关系，VMProtect `AreSimilar` 移植）。命中退出码 0、全未命中 1——可脚本化批量筛查。发行台账（时间/id/值/seed/sha256 前 16/输出路径）把 ID 回答到"这份副本发给了谁"；台账含全部水印明文，已入 .gitignore，须与源码分开保管。

fail-closed 契约：配置了水印但无法嵌全（无载体/预算不足/块不可见）**直接构建失败**——绝不静默产出不可溯源副本。如实披露的局限：静态水印不抗双副本差分攻击（与 VMProtect 同级，"抗移除=中"）；碎片 + 词流面抬高攻击成本但不根除。明确不做运行时自校验（会给抹除者提供 oracle）。

## 构建（Windows / MSVC / Ninja，需 VS 18 Insiders）

```bat
scripts\build.bat
```

首次运行通过 CMake FetchContent 拉取第三方依赖（googletest、capstone、keystone、tomlplusplus）到 `.deps/`，其中 keystone 编译较久。

## 测试

```bat
scripts\test.bat
```

## 端到端烟测（GitHub 复跑入口）

烟测脚本走完整流水线：构建 wvmpTest 靶 → 跑 native → 用 WVmp CLI 打壳 → 跑 packed → diff 输出。

```bat
:: tests/wvmpTest/ 已在主仓内（与 WVmp 同源）——干净克隆不需要仓外任何东西:
cd tests\wvmpTest
call build.bat x64
cd ..\..
tests\wvmpTest\smoke_test.bat
```

两个架构同一入口：`smoke_test.bat` 默认跑 x64，`smoke_test.bat x86` 走 PE32 一侧（配置 `kernels_x86.toml`）。期望结果：

- native 与 packed 返回码均为 0
- 两侧 `SUMMARY` 行一致，且 packed 侧报告的是全量语料
- diff 数为 0（`image   :` 这一行被排除——它嵌入了绝对路径）
- native 的 SUMMARY 显示 `passed=106`（x64）/ `passed=105`（x86）
- protect 日志显示标记区域为真虚拟化：`已生成 29 个入口 stub`（x64）/ `26`（x86）

`run_compare.cmd build\x64\test_target.exe build\x64\packed.exe` 走文件日志通道
（`out\base_*.log`）复跑同一比对，diff 数非 0 即判 FAIL。

靶源码与构建脚本见 [tests/wvmpTest/](tests/wvmpTest/)。

## 覆盖率（X7 重扫，2026-09-03）

*2026-09-03 全量重扫快照。此后指令面继续扩展（x86 侧 x87、x64 侧 ymm/AVX——见 Gate 边界），本重扫先于该扩展。*

| 指标 | 数值 |
|---|---|
| **x64 助记符级 direct 覆盖率**（System32 103 文件 / 17.6M clean 指令）| **99.26%** |
| **x86 助记符级 direct 覆盖率**（SysWOW64 100 文件 + 第三方 + 扩展 / 27.4M clean 指令）| **95.15%** |
| **x64 函数级无 gate**（.pdata 函数域，240,277 函数）| **94.74%** |
| **wvmpTest 标记区域真虚拟化（x86）**（106 用例靶内 27 个区域）| **26/27 = 96.3%** |

上表 215 行是 2026-09-03 重扫产物；wvmpTest 这一行是 2026-09-19 对仓内 27 区语料的重测（MIT-492）——`wvmp_cli protect --config tests\wvmpTest\kernels_x86.toml`，口径 = stub 数 / marker 函数数。x64 侧为 **29/30 = 96.7%**（多出的 3 区是 x64 专属 AVX 语料）。两侧唯一未虚拟化的都是 `wv_lcg_next`：它的 `PROTECT_BEGIN`/`PROTECT_END` 之间没有指令。

重扫脚本：[`scripts/verifier/mit_x7_rescan.py`](scripts/verifier/mit_x7_rescan.py)，产物在 [`scripts/verifier/mit_x7_rescan_out/`](scripts/verifier/mit_x7_rescan_out/)（215 行 jsonl + summary.json）。约 4 分钟可复跑：

```bat
python scripts\verifier\mit_x7_rescan.py
```

关于方法论的深度说明（x86 上无法严格函数级覆盖率的三层替代口径、双通道一致性断言）见 [docs/GAPS.md](docs/GAPS.md) §X7 收口节。

## Multica 工程化工作流

WVmp 自 2026-08-29 起通过 [multica](https://github.com/multica-ai/multica) 驱动开发——每一次能力扩展都是一条带项目主验证的派活单。

**同一派单纪律自 MIT-419 起连续执行至 MIT-521：**
- **M2.5-G（指令虚拟化阶段，x64）**——MIT-419 至 MIT-435，基线 240/240
- **M2.5-X（多目标平台阶段，x86 生产可用）**——MIT-436 至 MIT-455，基线 330/330
- **M3 保护表面（工作流 1-5）**——自 MIT-456 起：五个保护 pass 全部交付 v1 及一波加固（配置系统、TLS-hook 初始化、dr*/RDTSC 检查、导入引用重写）
- **指令面扩展（x86 侧 x87 / x64 侧 ymm+AVX）**——MIT-509 至 MIT-521，含两波自主离线批次（2026-09-14）

[docs/MULTICA_ISSUES.md](docs/MULTICA_ISSUES.md) 收录 M2.5 时期的工单目录与纪律沉淀；之后的批次记录在 [docs/STATUS.md](docs/STATUS.md)。

**原始 multica 工件**（155 文件 /451KB）单独打包供下载：`docs/multica-archive.tar.gz`。**此文件不入 git**，**（保持仓轻量）**。日常运营以 multica 面板为权威源。

## 项目状态

| 阶段 | 状态 |
|---|---|
| M2.5-G 指令虚拟化（x64） | 已完成（2026-08-31）|
| M2.5-X 多目标平台（x86 生产可用）| 已完成（2026-09-03）|
| M3 保护表面（工作流 1–5）| **v1 已交付**（2026-09，MIT-456 波次）——见后续开发计划 |
| 指令面扩展（x86 x87 / x64 ymm+AVX / BMI2 备忘录）| 已完成（2026-09-14，MIT-509–521）|
| BMI2 寄存器形 + `vextractf128`/`vinsertf128` 桥 | 已完成（2026-09-28，MIT-534/533；kVmOpMax 164→169）|
| 水印溯源（泄露副本反查）| 已完成（2026-10-10，MIT-541 + M2 + 542）|
| 频率 gate 指令积压 | 开放，样本驱动（SSE+ymm 混排、BMI2 mem 形——MIT-521/534）|
| 产品表面（工作流 6 GUI）| 未开始，已被工作流 1–5 解锁 |
| 扩展表面（工作流 7–9）| park，等触发 |

## 后续开发计划

九条能力工作流规划于 M2.5-G + M2.5-X 收官之后，是 WVmp 的**独立产品**。**工作流 1–5 已于 2026 年 9 月交付 v1**（MIT-456 波次）：五个保护 pass 全部实体化、接入流水线、可按函数配置。工作流 6（GUI）与工作流 7–9 维持后续工作。原频率 gate 挂账中，`vextractf128`/`vinsertf128` 桥与 BMI2 最低机器契约（寄存器形）已落地（MIT-533/534）；剩余积压 = SSE+ymm 混排协议与 BMI2 mem 形——全部证据驱动（MIT-521）。水印溯源（2026-10，MIT-541/542）在工作流图谱之外作为泄露识别能力交付，构建在工作流 1–5 之上。

### 工作流 1：字节码密码学混淆 —— v1 已交付（MIT-458）

xor-chain codec 在虚拟化后对 VM 字节码 blob 加密；stub 入口一次性解密，marker magic 与 VM 程序和运行时解码器不可分割。MIT-462 回归加固；工作流 5 在其上收尾防篡改环。

### 工作流 2：指令级代码变异 —— v1 已交付（MIT-459）

字节码产出前的种子确定性 IR 级变异。v1 落地 Nop 插入；junk-Mov 替换在 flags 活性 gate 下跟进（MIT-474、MIT-478/479），变异词流语义钉死。

### 工作流 3：反调试 / 反插桩加固 —— v1 已交付（MIT-463）

PEB.BeingDebugged + NtGlobalFlag 检查 + FailFast 响应（MIT-463），经 TLS hook 初始化（MIT-465/467）；硬件断点（dr*）与 RDTSC 时序检查于 MIT-470/471 补齐。

### 工作流 4：导入保护（IAT 加固）—— v1 已交付（MIT-466）

导入调用经保护 stub 路由，含导入引用重写（MIT-477）。

### 工作流 5：运行时完整性校验 —— v1 已交付（MIT-464）

对每条密文流算 IEEE CRC32 存入尾区保留槽；stub 解密前校验，不匹配即 FailFast（篡改实验：翻转 1 字节密文 → 确定性崩溃 rc=139）。

五个 pass 均接入 TOML 配置系统（MIT-457）：每函数保护档位与 pass 专属开关。

### 工作流 6：独立 GUI

全新顶层交付物。当前 CLI（`cli/src/main.cpp`）是唯一接口。工作流 6 在 CLI 子进程基础上增加独立 GUI。

- **做什么**：项目管理（加载/保存 WVmp 项目文件）、保护区域选择可视化、按 pass 配置面板、实时编译日志、带 marker 高亮的代码预览。
- **为何现在**：工作流 1–5 已交付真实可配置选项（MIT-456+），GUI 有实料可暴露。没有它们，GUI 只是 CLI 的 chrome 壳。
- **派单前需锁定的范围决策**：
  - **GUI 框架**——Qt（工业标准，商业用途付费许可）/ wxWidgets（宽松许可、生态较小）/ Dear ImGui + 原生窗口（开发者友好、不够精致）。每种选择需检查与 WVmp MIT 许可的兼容性。
  - **OS 目标**——先 Windows-only，跨平台延后（与当前 WVmp 范围匹配）。
  - **进程模型**——GUI 是薄壳层，spawn `wvmp_cli.exe` 子进程并解析其输出。**不**与 passes/ 直接进程内链接。
- **工作量**：设计 + 骨架 2-3 天，功能完整 5-7 天。这是**单张大派活单**（或两张——GUI 骨架 + 功能接线），而非多工作流。

### 工作流 7：Windows 内核驱动保护

独立代码路径，有自己的 SYS 运行时。当前 WVmp 严格只做用户态 PE 可执行文件。

- **做什么**：保护 `.sys` 驱动二进制——独立的 VM 运行时，在 IRQL ≥ DISPATCH_LEVEL 运行，针对内核调试器附加（KdDebuggerEnabled / KdTransportMaxPacketSize）硬化，DriverUnload hook 透明化。
- **当前状态**：park，未派。
- **为何 park**：
  - 需要**独立 SYS 运行时**（现有用户态运行时依赖用户态 API 表）。
  - **测试基础设施不同**（内核验证器、WinDbg 内核模式、驱动加载测试工具）。
  - **威胁模型不同**（内核态对手：内核补丁保护、PatchGuard、签名驱动旁路）。
  - **当前无客户拉动**内核驱动保护。
- **解 park 触发条件**（任一）：
  - 客户明确请求 `.sys` 驱动保护场景。
  - 内部决定进入驱动保护产品线（商业决策）。
  - 相邻研究需求（例如某项新技术只在内核态有意义）。
- **工作量**：5-10 天设计 + 2-3 派活单循环（与工作流 1-5 独立）。

### 工作流 8：反 VM / 反沙箱检测

检测保护程序是否在分析环境（hypervisor、沙箱、DBI 框架）内运行。

- **做什么**：产出分析环境检测例程——CPUID hypervisor-present 位、固件表厂商扫描、沙箱 API 痕迹、时序检测变体。挂接在现有 `passes/anti_debug/` 基础设施上但作用于不同轴。
- **当前状态**：部分覆盖（部分保护工具中已有 CPUID 厂商扫描），未作为聚焦工作量派发。
- **为何未作为早期独立工作流**：
  - **相邻工作流已有部分覆盖**（反调试检查、完整性校验）；提升为独立是增量而非绿地。
  - **启发式维护代价**：VM/沙箱检测签名比 VM 加固的 churn 快得多（分析厂商持续增加规避策略）。需要持续维护，不是一次性派单。
  - **误报风险**：激进 VM 检测会破坏合法用户（如在 Hyper-V、WSL2、杀毒沙箱下运行的用户）。
- **解 park 触发条件**（任一）：
  - 客户明确请求"挫败大规模扫描器管线"（工作流 1 威胁模型变种）。
  - 真实世界规避事件（某主要分析厂商成功绕过当前保护）。
  - 内部决定针对特定对手类硬化。
- **工作量**：1-2 次设计会话 + 1-2 派活单，**外加**后续维护预算。

### 工作流 9：虚拟文件系统 / 虚拟注册表

基于 hook 的主机 OS 文件与注册表 I/O 重定向——模拟资源加密内嵌在保护镜像内。

- **做什么**：改写 Win32 文件/注册表 API 调用（`CreateFile`、`RegOpenKeyEx` 等）让其路由到自定义派发器。资源看似来自"虚拟"位置，实际是按需解密自内嵌 bundle。
- **当前状态**：park，未派。**无占位基础设施**。
- **为何 park**：
  - **主机 OS 表层，非 VM 保护层**——保护原语的价值在 IR → VM 字节码层；OS 表层保护是不同产品层。
  - **需要 inline API hook 框架**——ntdll/kernel32 hook 链、hook 安全性验证、WoW64 分割。基础设施成本巨大。
  - **维护负担高**——Windows API 表跨版本变化；hook 点位置漂移。
- **解 park 触发条件**（任一）：
  - 客户请求"加密内嵌资源"（商业产品特性）。
  - 相邻需求（例如工作流 1 密钥包可自然延伸为虚拟文件系统密钥）。
  - 内部决定硬化 OS 表层（产品线决策）。
- **工作量**：2-3 周设计 + 3-4 派活单循环。**注意**：与工作流 1-5 全部加起来量级相当——是重大承诺。

### 排序

**当前顺序**：

1. **频率 gate 指令积压**——样本驱动（MIT-521）：SSE+ymm 混排协议翻面与 BMI2 mem 形支持（桥与寄存器形已落地，MIT-533/534）。
2. **工作流 6（GUI）**——已被交付的工作流 1–5 解锁。
3. **工作流 7–9**——park，等各自外部触发，不变。

工作流 1–5 交付时的内部排序（crypt → mutate → anti_debug → import_protect → integrity_crc）遵循前置链；加固跟进按波次落地。**工作流 6**是 **M3 产品表面**；**工作流 7–9**组成**扩展表面**，park 等外部触发。

## 架构

```
[PE file]
   ↓ pe_loader
[Parsed image]（PE sections、imports、.pdata/.xdata）
   ↓ marker_scan            ← 检测两段连续 8 字节 magic
[Marked regions]
   ↓ lifter                 ← capstone 解码 → IR
[IR]                       ← 冻结载体域（ir::Op）
   ↓ virtualize             ← IR → VmOp 表（kVmOpMax=169）
[VmOp sequence]
   ↓ stub_link              ← 生成 stub 派发入口
[Protected PE]
```

实现位于 `vm/regvm/{backend,lifter,translator,runtime}/`，核心 passes 注册在 `passes/{pe_loader,marker_scan,lifter,mutate,virtualize,stub_link,pe_writer}/`，M3 保护 passes 在 `passes/{crypt,anti_debug,integrity_crc,import_protect,tls_hook}/`，水印核心库在 `common/src/wm/`，CLI（protect / scan / version）在 `cli/`。

## 仓库结构

```
WVmp/
├── cli/                       # WVmp CLI（protect / scan 子命令）
├── passes/                    # 流水线 passes（pe_loader、marker_scan、…）
├── vm/regvm/                  # VM 实现（lifter、translator、runtime、backend）
├── sdk/include/wvmp/          # 公共 SDK 头文件
├── docs/
│   ├── STATUS.md              # 当前权威阶段状态
│   ├── GAPS.md                # 完整支持矩阵 + X7 收口节
│   ├── MULTICA_ISSUES.md      # multica 工单目录（M2.5 时期；之后的批次见 STATUS.md）
│   └── multica-archive.tar.gz # 原始 multica 工件（不入 git）
├── scripts/
│   ├── build.bat              # MSVC + Ninja 构建
│   ├── test.bat               # ctest
│   ├── multiseed_e2e.sh       # 5 seed × 78 样本回归池
│   ├── watermark_e2e.sh       # 水印 E2E（嵌入/反查/多态/台账）
│   ├── watermark_e2e_m2.sh    # 水印 E2E（碎片/junk/both/负例）
│   └── verifier/
│       ├── mit_x7_rescan.py       # 客户态覆盖率扫描器
│       ├── mit_515_bmi_probe/     # BMI2（mulx/pdep/pext）硬件探针
│       ├── mit_517_avx_profile/   # AVX/VEX codegen 频率画像
│       └── dump_handler_xmm_check.py # handler 形状 dump 门
├── tests/wvmpTest/            # 106 用例功能测试靶（30 个标记区域）
│   ├── src/                   # test kernels 源码
│   ├── build.bat              # 构建 test_target.exe
│   ├── kernels.toml           # x64 靶的 WVmp CLI 配置
│   ├── kernels_x86.toml       # 同一管道，PE32 靶
│   └── smoke_test.bat         # 端到端烟测入口
└── LICENSE                    # MIT
```

## 许可证

MIT。详见 [LICENSE](LICENSE)。

## 致谢

作为 CMake FetchContent 依赖的 capstone、keystone、googletest、tomlplusplus 项目以各自许可证包含。
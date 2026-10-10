# WVmp 水印溯源功能实现方案

> 版本 v1（2026-10-09）。目标：每个保护副本嵌入唯一可反查的水印，泄露后凭副本文件定位发行对象。
> 参考蓝本：`vmprotect-3.5.1-master/14_WATERMARK_SYSTEM.md`（dump/mask 编译 + 流式匹配 + 分散嵌入）。
> 本方案所有代码锚点均已在当前 main（a62c09d）核实。

---

## 0. 设计原则（对齐项目既有纪律）

1. **缺省零扰动**：不配置水印时，pe_writer 输出必须与现状 byte-exact 一致（全池 390/390 的既有 E2E 契约不能破）。
2. **确定性可复现**：通配符填充一律走 `ctx.rng`（由 `config.seed` 播种），同 seed + 同水印值 → 逐字节可复现；不同客户副本靠水印值本身区分。
3. **fail-closed**：schema 未知键显式拒绝（沿用 config.cpp:118 起的严格 schema 纪律）；嵌入预算不足硬失败，不静默丢水印。
4. **如实披露**：水印是静态对抗手段，方案末节如实列明局限，不做虚假安全承诺。

## 1. 总体架构：四件套

```
配置/CLI                    保护管道                       事后
┌──────────────┐   ┌───────────────────────────┐   ┌────────────────┐
│ [watermark]  │   │ pe_writer 末尾新增          │   │ wvmp scan 子命令│
│ TOML 节      ├──►│ EmbedWatermark 步骤        │──►│ 全文件流式匹配  │
│ --watermark  │   │ （新节对齐尾垫内分散嵌入）  │   │ 反查发行台账    │
│ CLI 覆盖     │   └────────────┬──────────────┘   └───────▲────────┘
└──────────────┘                │                           │
                        发行台账 tsv 追加一条 ───────────────┘
                        (时间/水印ID/seed/输出sha256)
```

核心库放在 `common`（编译 dump/mask + 流式匹配器），CLI、pe_writer、scan 三方共用，杜绝两处实现漂移。

## 2. 数据模型与核心算法（common 层）

新文件：`common/include/wvmp/wm/watermark.hpp` + `common/src/wm/watermark.cpp`

```cpp
namespace wvmp::wm {

// 水印值：十六进制字符串，'?' 为半字节(nibble)通配符。
// 例："4D5A90??0300" → dump={4D,5A,90,??,03,00}, mask={FF,FF,FF,00,FF,FF}
// （?? 两个字符通配一个整字节；奇偶位各自独立通配也允许，如 "4?5A"）
struct Watermark {
    std::string id;     // 如 "Customer_A_2026Q4"
    std::string value;  // 十六进制 + '?'
    std::vector<uint8_t> dump;  // 编译产物：含随机填充的通配位
    std::vector<uint8_t> mask;  // 编译产物：FF=固定位, 00=通配位

    void compile();     // 移植 VMProtect Watermark::Compile（nibble 级打包）
};

// 流式单字节匹配器（移植 VMProtect Watermark::SearchByte, core/core.cc:216）：
// 多活跃匹配位置、掩码比较 (dump&mask)==(value&mask)、完整匹配返回 true。
class StreamMatcher {
public:
    explicit StreamMatcher(const Watermark& wm);
    bool feed(uint8_t b);          // 完整命中一次返回 true（可多次）
    void reset();
};

// 校验与切分
bool validate(const std::string& value, std::string* why);  // 见 §2.1
std::vector<Fragment> split_fragments(const Watermark& wm, size_t min_hex);

} // namespace wvmp::wm
```

### 2.1 值域校验规则（parse 期，fail-closed）

- 只允许 `[0-9A-Fa-f?]`，长度为偶数，总长 16–64 个十六进制字符（8–32 字节）；
- **固定位熵下限**：非 `?` 字符数 ≥ 12（即 ≥ 48 bit 固定模式，扫描误匹配概率 < 2^-48 量级，按 10MB 文件 ~10^8 字节窗口计算仍可忽略）；切分后**每个片段**固定位 ≥ 8 个十六进制字符，否则拒绝切分并退回整段嵌入；
- 拒绝全 `?`、拒绝空 id。

### 2.2 匹配语义（与 VMProtect 对齐）

逐字节流式匹配、掩码比较、命中计数。扫描端对每个已登记水印各持一个 `StreamMatcher`，对整个文件（从 offset 0 到 EOF，**含 overlay**，不按节遍历——泄露副本可能被重打包，节表不可信）逐字节喂入；输出每枚水印的命中次数与命中偏移。

## 3. 配置面（CLI + TOML）

### 3.1 TOML：新增 `[watermark]` 节（`cli/src/config.cpp`，镜像 `[mutate]`/`[anti_debug]` 的白名单登记与未知子键拒绝）

```toml
[watermark]
id     = "Customer_A_2026Q4"     # 必填（与 value 至少其一见 §3.3）
value  = "4D5A90??0300..."       # 必填，hex + '?'
copies = 3                        # 可选，默认 3：嵌入份数（抗局部篡改）
fragments = 2                     # 可选，默认 1：v1 建议 1（见 §5 分期）
issue_log = "watermark_issues.tsv" # 可选：发行台账追加路径
```

`WvmpConfig`（`cli/include/wvmp/cli/config.hpp`）新增 `WatermarkConfig` 子结构 + `has_watermark` 标志（沿用 `has_mutate_density` 的 Optional 模式）。

### 3.2 CLI：`--watermark <value>` 覆盖（`cli/src/args.cpp` / `args.hpp`）

- `wvmp protect --config c.toml --watermark 4D5A...`：命令行值覆盖 TOML 的 `value`（镜像 `-o` 对 `output` 的覆盖语义）；`id` 取 TOML 或缺省为值本身前 8 字符。
- 摘要打印追加一行：`[wvmp] 水印 : id=Customer_A... 固定位=52bit copies=3`（main.cpp 的参数披露块）。

### 3.3 退出码与诊断

- 配置校验失败 → 退出码 1（既有"参数/配置错误"档）；
- 嵌入预算不足（§5.2）→ pe_writer 记 Error 并抛出，CLI 退出码 2（"管道运行期失败"档）；
- pass 层保持"正常路径零诊断"，水印成功嵌入由 CLI 打印 Note（沿用区域清单的披露位置，main.cpp:183 附近）。

## 4. Context 槽与管道接线

- `framework/keys.hpp` 新增 `kWatermark`；`cmd_protect` 在装配后写入 `ctx.slot<wvmp::wm::WatermarkConfig>(kWatermark)`（仅在 has_watermark 时写入——**槽缺席 = 不嵌入**，保证缺省零扰动，镜像 kProtectRules 的写法）。
- 不新增 pass、不动 `Pipeline::from_names` 白名单：嵌入作为 **pe_writer 内部步骤**，在 `add_sections` 落位新节之后（`pe_writer_pass.cpp:383-393` 之后、最终 `ByteWriter` 收尾之前）执行。理由：水印是"写出期修饰"，无独立 Phase 语义，避免管道面扩容。

## 5. 嵌入策略

### 5.1 v1：新节 FileAlignment 尾垫分散嵌入（默认）

- 载体：pe_writer 已落位的新节（`.wvmp` 等，`kNewSections`）的**尾垫**——`raw size` 按 `file_align` 上取整产生的零填充区（位于节虚拟范围尾部、映射为无功能零页，不与 stub/reloc/emit 区重叠）；
- `copies` 份水印依次顺排或按 `ctx.rng` 取偏移（同 seed 可复现）；通配 nibble 用 `ctx.rng` 填充——**同一水印在不同 seed/不同副本产出物里物理字节不同，但 dump/mask 身份相同**（VMProtect "多态水印"语义）；
- 若尾垫总预算 < `copies × pattern_len`，先尝试把最后一个新节 raw size 向上多取整一档对齐（raw > virtual 合法且多出的文件字节不映射进内存），仍不足则**硬失败**（fail-closed，见 §3.3）。

### 5.2 v2（增强，另立任务）：抗摘除强化

- **碎片分散**：`split_fragments` 把 dump/mask 切成 2–4 片，散布到多个新节尾垫与节间隙，扫描端任一片段命中即计入，按片段多数票定 ID；
- **mutate 立即数嵌入**：把水印字节作为垃圾指令立即数混入 mutate 位面（`config.rules.mutate_density` 已有基建），对齐 VMProtect `AddWatermark` 分散进指令流的策略——隐蔽性最高，但触及 virtualize/mutate 输出面，需独立回归。

### 5.3 定位与预算的测试钉子

- 嵌入完成后 pe_writer 在 diag 里记 Note（仅 CLI 展示）：嵌入的 (节名, 节内偏移, 份数)——供白盒测试与人工核账，不进输出文件。

## 6. 发行台账（溯源闭环的关键，VMProtect 没做的一步）

`protect` 成功且水印生效后，CLI 追加一行 TSV（`issue_log` 路径，默认不写）：

```
2026-10-09T14:22:31+08:00	Customer_A_2026Q4	4D5A90??…	12345	9f3ab1…(输出文件sha256前16)	target_protected.exe
```

追溯流程：泄露副本 → `wvmp scan` 得水印 id → 查台账得该 id 发给谁、何时、哪次构建。台账属用户本地资产，不入 git（.gitignore 建议追加 `watermark_issues.tsv`）。

## 7. 扫描工具：`wvmp scan` 子命令

`cli/src/main.cpp` 子命令扩展（`args.cpp` 解析；独立纯读实现，不装配管道）：

```
wvmp scan --in leaked.exe --registry watermarks.toml [--quiet]
```

- `watermarks.toml`：`[[watermarks]]` 数组（id/value，与 §3.1 同 schema，独立小解析器复用 common 校验）；
- 输出：每枚水印 `命中=2 次 @ file_off 0x40f3,0x52a1 → Customer_A_2026Q4`；`--quiet` 仅打印命中的 id；
- 退出码：命中 0；全部未命中 1（可直接脚本化批量筛查）。

## 8. 文件改动清单（锚点均已核实）

| 动作 | 文件 |
|---|---|
| 新增 | `common/include/wvmp/wm/watermark.hpp`、`common/src/wm/watermark.cpp`（compile/StreamMatcher/validate/split） |
| 新增 | `common/tests/wm/test_watermark.cpp`（gtest，注册 ctest） |
| 修改 | `cli/include/wvmp/cli/config.hpp`、`cli/src/config.cpp`（[watermark] 节 + 白名单 + 校验） |
| 修改 | `cli/include/wvmp/cli/args.hpp`、`cli/src/args.cpp`（--watermark 覆盖 + scan 子命令解析） |
| 修改 | `cli/src/main.cpp`（槽写入 / 摘要披露 / 台账追加 / cmd_scan） |
| 修改 | `framework/include/wvmp/framework/keys.hpp`（kWatermark） |
| 修改 | `passes/pe_writer/src/pe_writer_pass.cpp`（add_sections 后嵌入步骤 + 预算硬失败 + Note） |
| 修改 | `passes/pe_writer/tests/test_pe_writer.cpp`（缺席 byte-exact / 在场可扫回 两类） |
| 新增 | `cli/tests/test_scan.cpp`（scan 端到端：合成字节流喂匹配器） |
| 修改 | `cli/configs/default.toml`（注释示例，默认注释掉——缺省不启用水印） |

## 9. 测试与验收计划（按项目三验收纪律）

1. **单测（common）**：compile 的 dump/mask 用参考文档 §2 示例钉板（"4D5A90??0300"）；StreamMatcher 用文档 §3.2 的双命中序列钉板；validate 的 6 条拒绝路径（奇长/非法字符/固定位不足/全通配/空 id/超长）；
2. **配置**：合法 [watermark] 全键/最简键通过；未知子键拒绝（fail("config [watermark] 未知子键 …")）；--watermark 覆盖优先级；
3. **pe_writer**：槽缺席 → 输出与基线 byte-exact（复用既有 byte-exact 比较测试基建）；槽在场 → 输出与无水印版本**仅尾垫区间不同**（差异区间断言）；预算不足负例 → 退出码 2 且诊断含 Error；
4. **E2E（池门扩容 390 → 39N）**：`protect(带水印) → scan` 回环命中正确 id；同水印不同 seed 两副本 → scan 同 id 但物理字节差异 ≥ 通配位数；无水印副本 scan → 全未命中退出码 1；10MB 随机文件 × 100 枚水印 → 零误命中（误匹配实证）；
5. **验收口径**：负例注入（故意改坏一个字节的水印仍应命中——掩码容错位验证）+ 独立子代理验收复跑（沿用 T18/T64 纪律）。

## 10. 分期与工作量

| 期 | 内容 | 估算 |
|---|---|---|
| M1 | common 核心库 + [watermark]/--watermark + pe_writer 尾垫嵌入 + 台账 + scan 子命令 + 全部单测/E2E | 2–3 个工作日（改动面小、锚点清晰；主要成本在验收负例族） |
| M2 | 碎片分散 + mutate 立即数嵌入 + 相似水印防碰撞校验（AreSimilar 移植） | 1–2 个工作日（触及 mutate 输出面，回归成本为主） |

## 11. 风险与安全边界（如实披露）

- **差分攻击**：攻击者持有两个不同客户副本做 diff 可定位水印区并抹除——VMProtect 同款局限（其文档 §9 亦如实标注"抗移除=中"）；M2 的碎片+立即数嵌入显著抬高成本但不根除。水印定位的是**文件级泄露源**，不是防逆向手段；
- **台账即靶心**：发行台账本身含全部水印明文，必须与源码分开保管（不入 git 已在 §6 处理）；
- **内存 dump 不可溯**：v1 嵌入区在映射态节内，内存 dump 理论可扫到；raw>virtual 备用区则只在文件态存在——两态取舍见 §5.1，默认选映射态（覆盖面更广）；
- **Defender 误报**：packed PE 本就有被秒杀前科（项目实录），新增的尾垫随机字节理论上不改变现有检出面，但 M1 验收必须含 Defender 实测一项；
- **不承诺运行时校验**：loader 里做水印自校验（发现被抹就拒绝运行）属反调试对抗面，超出"溯源"范围，且会给静态抹除者提供 oracle，明确不做。

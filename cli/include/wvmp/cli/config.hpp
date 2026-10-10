// WVmp CLI 配置模型（P8 泳道）。
//
// 保护任务用 TOML 描述（见 cli/configs/default.toml）：
//   input  / output : 输入与输出 PE 路径（必填）
//   seed            : 保护随机种子，0 = 默认（可省略）
//   [[passes]]      : 要装配的 pass 名单，按配置顺序书写；Pipeline 会
//                     按 Phase 稳定排序，同 Phase 内保持此处的顺序。
#pragma once

#include "wvmp/cli/scan.hpp"
#include "wvmp/common/types.hpp"
#include "wvmp/wm/watermark.hpp"

#include "wvmp/framework/protect_levels.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace wvmp::cli {

// v1 无 pass 级参数，结构预留（后续 pass options 平铺进该结构）。
struct PassConfig {
    std::string name;
};

// MIT-438 (X1b) B.5: 目标架构声明（TOML `arch` 字段，可省略 = auto）。
// 值域与 passes/pe_loader/include/wvmp/passes/pe_loader/target_arch.hpp 的
// 槽常量 (kTargetArch*) 逐一对账（CLI 经穷举 switch 映射，防漂移）：
//   auto = machine 推导；x64 = 与 0x8664 不符 → rc=2 显式拒；
//   x86  = 匹配 0x014C → 通行（MIT-446 (X4) D1 解禁），不符 → rc=2 拒。
enum class ArchOpt : wvmp::u8 { Auto = 0, X64 = 1, X86 = 2 };

// MIT-541 水印溯源 v1：[watermark] 节模型（值域校验在 parse_config 内
// 做，fail-closed；编译成 dump/mask 发生在 main 落槽时）。缺省不配置 =
// 无水印（输出与现状 byte-exact）。M2 起 mode/fragments 扩展。
struct WatermarkConfig {
    std::string id;      // 发行对象标识；缺省 = value 前 8 字符
    std::string value;   // 十六进制 + '?'（16-64 字符，固定位 >= 12）
    wvmp::u32 copies = 3;   // 嵌入份数（1-8；junk 面 = 每块份数上限尽力值）
    wm::WatermarkMode mode = wm::WatermarkMode::Padding;  // padding/junk/both
    wvmp::u32 fragments = 1;  // padding 面碎片数（1-4；仅 padding/both 模式）
    bool has_issue_log = false;
    std::string issue_log;  // 发行台账追加路径（TSV；空 = 不落台账）
};

struct WvmpConfig {
    std::string input, output;
    wvmp::u64 seed = 0;
    ArchOpt arch = ArchOpt::Auto;   // B.5: 缺省 auto = 现状行为不变
    std::vector<PassConfig> passes; // 配置顺序（Pipeline 会按 Phase 稳定排序）

    // MIT-457 配置系统 v1：保护档位（default_level 可省略 = virtualize；
    // [[functions]] 每函数规则，选择器 rva/index 恰一）。
    ProtectRules rules;

    // MIT-541 水印溯源 v1：has_watermark = [watermark] 在场。
    bool has_watermark = false;
    WatermarkConfig watermark;
};

// 轻量 Result<T>：ok=false 时 error 给出用户可读的失败描述（文件不存在 /
// 语法错（带行号）/ 字段缺失或类型不对）。
struct ConfigResult {
    bool ok = false;
    WvmpConfig value;
    std::string error;
};

ConfigResult parse_config(const std::filesystem::path& file);

// MIT-541 水印溯源 v1 + M2：scan 用 registry 解析。格式（与 [watermark]
// 同值域，独立文件；mode/fragments 告诉扫描端按哪个嵌入方案分片）：
//   [[watermarks]]
//   id    = "Customer_A"
//   value = "4D5A90??03001122"
//   mode  = "junk"        # 可选：padding(默认)/junk/both
//   fragments = 2         # 可选：padding 面碎片数 1-4（默认 1）
// 登记表内两枚过相似（wm::are_similar：'?' 通配 + 大小写不敏感的包含
// 关系）→ 拒绝（误归因防线，M2）。
struct WatermarkRegistryResult {
    bool ok = false;
    std::string error;
    std::vector<ScanItem> items;  // 已 compile 的水印 + 嵌入方案
};
WatermarkRegistryResult parse_watermark_registry(const std::filesystem::path& file);

} // namespace wvmp::cli

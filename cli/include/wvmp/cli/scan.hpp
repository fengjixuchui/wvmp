// MIT-541 水印溯源 v1 + M2：scan 子命令核心（泄露副本 → 水印 ID 反查）。
//
// 与 protect 完全解耦：纯读文件 + 流式匹配，不装配管道。registry 解析
// 复用 config.cpp 的 TOML/路径基建（见 parse_watermark_registry）。
// M2 起条目携带 mode/fragments——扫描端按嵌入方案镜像分片（padding 面
// N 等分 / junk 面 4 字节块 / both 两案并试），多数票定 ID。
#pragma once

#include "wvmp/wm/watermark.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace wvmp::cli {

// registry 条目（已 compile 的水印 + 嵌入方案描述）。
struct ScanItem {
    wm::Watermark watermark;
    wm::WatermarkMode mode = wm::WatermarkMode::Padding;
    u32 fragments = 1;
};

struct ScanReport {
    bool ok = false;         // 文件可读且 registry 合法（执行面成功）
    std::string error;       // 失败描述
    bool any_hit = false;    // 是否有任一水印命中（决定退出码 0/1）
    // 命中面（按 registry 顺序）：id / 命中次数 / 命中偏移（截断）。
    struct Hit {
        std::string id;
        size_t count;
        std::vector<size_t> offsets;
    };
    std::vector<Hit> hits;
};

// 对 input 全文件（含 overlay；泄露副本可能被重打包，节表不可信，不做
// 节感知扫描）逐字节匹配 items 里的每枚水印。执行面失败（文件打不开
// 等）置 ok=false + error；匹配面零命中 ok=true + any_hit=false。
// 每条目按其 mode/fragments 构造碎片方案（与嵌入端同一切分规则），
// 多数票（wm::scan_fragments）通过才计入命中。
ScanReport scan_file(const std::filesystem::path& input,
                     const std::vector<ScanItem>& items);

} // namespace wvmp::cli

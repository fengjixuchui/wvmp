// MIT-541 水印溯源 v1：scan 子命令核心（泄露副本 → 水印 ID 反查）。
//
// 与 protect 完全解耦：纯读文件 + 流式匹配，不装配管道。registry 解析
// 复用 config.cpp 的 TOML/路径基建（见 parse_watermark_registry）。
#pragma once

#include "wvmp/wm/watermark.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace wvmp::cli {

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
ScanReport scan_file(const std::filesystem::path& input,
                     const std::vector<wm::Watermark>& items);

} // namespace wvmp::cli

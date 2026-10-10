#include "wvmp/cli/scan.hpp"

#include <array>
#include <cstdio>
#include <fstream>
#include <vector>

namespace wvmp::cli {

ScanReport scan_file(const std::filesystem::path& input,
                     const std::vector<wm::Watermark>& items) {
    ScanReport rep;
    std::ifstream in(input, std::ios::binary);
    if (!in) {
        rep.error = "无法打开待扫描文件: " + input.string();
        return rep;
    }
    // 每枚水印一个 matcher；64KB 块流式喂入（对齐参考实现的 4096 分块
    // 思路，块大小只影响 IO 次数不影响语义）。
    std::vector<wm::StreamMatcher> matchers;
    matchers.reserve(items.size());
    for (const auto& wm : items) matchers.emplace_back(wm);
    std::vector<size_t> counts(items.size(), 0);
    std::vector<std::vector<size_t>> offsets(items.size());
    std::array<u8, 65536> buf;
    size_t base = 0;
    while (in) {
        in.read(reinterpret_cast<char*>(buf.data()),
                static_cast<std::streamsize>(buf.size()));
        const size_t n = static_cast<size_t>(in.gcount());
        for (size_t i = 0; i < n; ++i) {
            for (size_t k = 0; k < items.size(); ++k) {
                if (matchers[k].feed(buf[i])) {
                    ++counts[k];
                    if (offsets[k].size() < wm::kMaxReportOffsets)
                        offsets[k].push_back(base + i);
                }
            }
        }
        base += n;
    }
    for (size_t k = 0; k < items.size(); ++k) {
        if (counts[k] == 0) continue;
        rep.any_hit = true;
        rep.hits.push_back({items[k].id, counts[k], std::move(offsets[k])});
    }
    rep.ok = true;
    return rep;
}

} // namespace wvmp::cli

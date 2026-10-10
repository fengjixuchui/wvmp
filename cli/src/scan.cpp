#include "wvmp/cli/scan.hpp"

#include <array>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <utility>
#include <vector>

namespace wvmp::cli {
namespace {

// 与嵌入端同一切分规则（pe_writer padding 面 / mutate junk 面）：
//   padding/both + fragments>1 → N 等分（split_fragments 语义）；
//   junk/both → dump.size()/4 个 4 字节块；
//   padding + fragments=1 → 整段单片。
// both = 两案并试（任一案多数票过即命中）。
std::vector<std::vector<wm::Fragment>> schemes_of(const ScanItem& item) {
    std::vector<std::vector<wm::Fragment>> out;
    const auto& w = item.watermark;
    if (item.mode != wm::WatermarkMode::Junk && item.fragments > 1) {
        auto frags = wm::split_fragments(w, item.fragments, 4);
        if (!frags.empty()) out.push_back(std::move(frags));
    } else if (item.mode != wm::WatermarkMode::Junk) {
        auto whole = wm::split_fragments(w, 1, 4);
        if (!whole.empty()) out.push_back(std::move(whole));
    }
    if (item.mode != wm::WatermarkMode::Padding && w.dump.size() % 4 == 0) {
        auto chunks = wm::split_fragments(w, w.dump.size() / 4, 4);
        if (!chunks.empty()) out.push_back(std::move(chunks));
    }
    return out;
}

} // namespace

ScanReport scan_file(const std::filesystem::path& input,
                     const std::vector<ScanItem>& items) {
    ScanReport rep;
    std::ifstream in(input, std::ios::binary);
    if (!in) {
        rep.error = "无法打开待扫描文件: " + input.string();
        return rep;
    }
    // 一次性读入（E2E 实测的样本量 MB 级；流式分块对匹配语义无增益，
    // 文件级缓存一次读尽再跑 K 个 matcher 更简单且可复跑 offsets）。
    // ifstream 的 char_traits 是 char，逐块 read 后拷贝进 u8 向量。
    std::vector<u8> data;
    {
        char buf[65536];
        while (in.read(buf, sizeof buf) || in.gcount() > 0)
            data.insert(data.end(), buf, buf + in.gcount());
        if (in.bad()) {
            rep.error = "读取待扫描文件失败: " + input.string();
            return rep;
        }
    }
    for (const ScanItem& item : items) {
        size_t best_count = 0;
        std::vector<size_t> best_offsets;
        bool identified = false;
        for (const auto& scheme : schemes_of(item)) {
            const auto r = wm::scan_fragments(scheme, data.data(), data.size());
            if (r.identified) {
                identified = true;
                if (r.count > best_count) {
                    best_count = r.count;
                    best_offsets = r.offsets;
                }
            }
        }
        if (!identified) continue;
        rep.any_hit = true;
        rep.hits.push_back({item.watermark.id, best_count, std::move(best_offsets)});
    }
    rep.ok = true;
    return rep;
}

} // namespace wvmp::cli

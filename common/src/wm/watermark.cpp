#include "wvmp/wm/watermark.hpp"

#include <stdexcept>

namespace wvmp::wm {
namespace {

int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 0x0a;
    if (c >= 'a' && c <= 'f') return c - 'a' + 0x0a;
    return -1;
}

} // namespace

bool validate(std::string_view id, std::string_view value, std::string* why) {
    const auto set_why = [why](std::string msg) {
        if (why != nullptr) *why = std::move(msg);
    };
    if (id.empty()) {
        set_why("水印 id 不能为空");
        return false;
    }
    if (id.size() > kIdMaxChars) {
        set_why("水印 id 超长（> " + std::to_string(kIdMaxChars) + " 字符）");
        return false;
    }
    for (const char c : id) {
        const bool printable = c >= 0x20 && static_cast<unsigned char>(c) < 0x7F;
        if (!printable) {
            set_why("水印 id 含不可打印/制表符字符（台账 TSV 与终端会被破坏）");
            return false;
        }
    }
    if (value.size() % 2 != 0) {
        set_why("水印值长度必须为偶数个十六进制字符（当前 " +
                std::to_string(value.size()) + "）");
        return false;
    }
    if (value.size() < kValueMinChars || value.size() > kValueMaxChars) {
        set_why("水印值长度必须在 " + std::to_string(kValueMinChars) + "-" +
                std::to_string(kValueMaxChars) + " 个十六进制字符（当前 " +
                std::to_string(value.size()) + "）");
        return false;
    }
    size_t fixed = 0;
    for (const char c : value) {
        if (c == '?') continue;
        if (hex_val(c) < 0) {
            set_why(std::string("水印值含非法字符 '") + c +
                    "'（只允许 0-9/A-F/a-f/?）");
            return false;
        }
        ++fixed;
    }
    if (fixed < kMinFixedChars) {
        set_why("水印值固定位不足（非 '?' 字符 " + std::to_string(fixed) +
                " < " + std::to_string(kMinFixedChars) +
                "，48bit 固定模式是扫描误匹配的兜底）");
        return false;
    }
    if (fixed == 0) {
        set_why("水印值不能全为通配符");
        return false;
    }
    return true;
}

void Watermark::compile() {
    std::string why;
    if (!validate(id, value, &why)) throw std::runtime_error("watermark: " + why);

    const size_t nbytes = value.size() / 2;
    dump.assign(nbytes, 0);
    mask.assign(nbytes, 0);
    for (size_t i = 0; i < value.size(); ++i) {
        // 与参考实现同构：固定 nibble → b=值/m=0xF；'?' → b=0（物理填充
        // 由嵌入方取 rng）/m=0。高半字节在偶数下标，低半字节在奇数下标。
        u8 b = 0, m = 0x0F;
        if (value[i] != '?') {
            b = static_cast<u8>(hex_val(value[i]));
        } else {
            m = 0;
        }
        const size_t p = i / 2;
        if ((i & 1) == 0) {
            dump[p] = static_cast<u8>((dump[p] & 0x0F) | (b << 4));
            mask[p] = static_cast<u8>((mask[p] & 0x0F) | (m << 4));
        } else {
            dump[p] = static_cast<u8>((dump[p] & 0xF0) | (b & 0x0F));
            mask[p] = static_cast<u8>((mask[p] & 0xF0) | (m & 0x0F));
        }
    }
}

StreamMatcher::StreamMatcher(const Watermark& wm)
    : dump_(wm.dump.data()), mask_(wm.mask.data()), len_(wm.dump.size()) {
    // 裸指针持有方保证 Watermark 生命周期覆盖 matcher（scan_bytes 内
    // 栈上使用；外部调用方同理——头注释已声明）。
}

bool StreamMatcher::feed(u8 v) {
    if (len_ == 0) return false;
    bool res = false;
    // 从后向前遍历活跃位置：erase(begin+i) 不失效更靠前的迭代器下标
    // （含 i==-1 的"新起点"试探，与参考实现逐语句对齐）。
    for (int i = static_cast<int>(pos_.size()) - 1; i >= -1; --i) {
        const size_t p = (i == -1) ? 0 : pos_[static_cast<size_t>(i)];
        if ((dump_[p] & mask_[p]) == (v & mask_[p])) {
            const size_t np = p + 1;
            if (np == len_) {
                res = true;
                if (i > -1) pos_.erase(pos_.begin() + i);
            } else if (i == -1) {
                pos_.push_back(np);
            } else {
                pos_[static_cast<size_t>(i)] = np;
            }
        } else if (i > -1) {
            pos_.erase(pos_.begin() + i);
        }
    }
    return res;
}

void StreamMatcher::reset() { pos_.clear(); }

ScanResult scan_bytes(const Watermark& wm, const u8* data, size_t size) {
    ScanResult r;
    StreamMatcher m(wm);
    for (size_t off = 0; off < size; ++off) {
        if (m.feed(data[off])) {
            // 命中完成于最后喂入的字节，模式末端即当前偏移。
            ++r.count;
            if (r.offsets.size() < kMaxReportOffsets) r.offsets.push_back(off);
        }
    }
    return r;
}

namespace {

size_t fixed_nibbles(const std::vector<u8>& mask) {
    size_t n = 0;
    for (const u8 m : mask) {
        if ((m & 0xF0) != 0) ++n;
        if ((m & 0x0F) != 0) ++n;
    }
    return n;
}

} // namespace

std::vector<Fragment> split_fragments(const Watermark& wm, size_t target_count,
                                      size_t min_bytes) {
    std::vector<Fragment> out;
    if (target_count <= 1) {
        if (wm.dump.empty() || wm.dump.size() < min_bytes ||
            fixed_nibbles(wm.mask) < kMinFragmentFixedChars)
            return {};
        out.push_back({wm.dump, wm.mask, 0});
        return out;
    }
    const size_t total = wm.dump.size();
    if (target_count > total / min_bytes) return {};  // 片数超出可均分上限
    // 字节对齐尽量均匀：前 r 片 each+1 字节。
    const size_t base = total / target_count;
    const size_t r = total % target_count;
    size_t off = 0;
    for (size_t k = 0; k < target_count; ++k) {
        const size_t len = base + (k < r ? 1 : 0);
        if (len < min_bytes) return {};
        Fragment f;
        f.dump.assign(wm.dump.begin() + std::ptrdiff_t(off),
                      wm.dump.begin() + std::ptrdiff_t(off + len));
        f.mask.assign(wm.mask.begin() + std::ptrdiff_t(off),
                      wm.mask.begin() + std::ptrdiff_t(off + len));
        if (fixed_nibbles(f.mask) < kMinFragmentFixedChars) return {};
        f.src_off = off;
        out.push_back(std::move(f));
        off += len;
    }
    return out;
}

FragmentScanResult scan_fragments(const std::vector<Fragment>& frags,
                                  const u8* data, size_t size) {    FragmentScanResult r;
    r.fragments_total = frags.size();
    if (frags.empty()) return r;
    for (const Fragment& f : frags) {
        // 片与整段同构：借 StreamMatcher 的裸构造（dump/mask 指针 + 长度
        // 由 Watermark 承载，这里临时拼一个轻量视图即可——直接手写掩码
        // 流式匹配与 Watermark 版同算法）。
        Watermark view;
        view.dump = f.dump;  // 拷贝一次（扫描频率低，正确性优先于零拷贝）
        view.mask = f.mask;
        StreamMatcher m(view);
        size_t hits = 0;
        for (size_t off = 0; off < size; ++off) {
            if (m.feed(data[off])) {
                ++hits;
                if (r.offsets.size() < kMaxReportOffsets) r.offsets.push_back(off);
            }
        }
        if (hits > 0) ++r.fragments_hit;
        r.count += hits;
    }
    // 多数票：K=1 退化为 v1 整段语义（count >= 1）；K>=2 需不同片命中数
    // >= ceil(K/2) 且 >= 2。K=2 时 ceil(2/2)=1，"且 >=2"收紧为两片全中
    //——两片水印只中一片 = 半数证据，归因不足以披露。
    if (r.fragments_total == 1)
        r.identified = r.count >= 1;
    else
        r.identified = r.fragments_hit >= (r.fragments_total + 1) / 2 &&
                       r.fragments_hit >= 2;
    return r;
}

std::vector<bool> fragments_present(const std::vector<Fragment>& frags,
                                    const u8* data, size_t size) {
    std::vector<bool> out(frags.size(), false);
    for (size_t k = 0; k < frags.size(); ++k) {
        Watermark view;
        view.dump = frags[k].dump;
        view.mask = frags[k].mask;
        StreamMatcher m(view);
        for (size_t off = 0; off < size && !out[k]; ++off)
            if (m.feed(data[off])) out[k] = true;  // 首中即停
    }
    return out;
}

bool are_similar(std::string_view v1, std::string_view v2) {
    // VMProtect SymbolsMatch 语义：'?' 匹配任意单字符；其余大小写不敏感。
    const auto match_at = [](std::string_view a, std::string_view b) {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); ++i) {
            const char x = a[i], y = b[i];
            if (x == '?' || y == '?') continue;
            char X = x >= 'a' ? char(x - 'a' + 'A') : x;
            char Y = y >= 'a' ? char(y - 'a' + 'A') : y;
            if (X != Y) return false;
        }
        return true;
    };
    if (v1.empty() || v2.empty()) return true;
    if (v1.size() == v2.size()) return match_at(v1, v2);
    // 短串在长串上滑窗找通配子串匹配（含全 '?' 段的包含关系）。
    const std::string_view& short_v = v1.size() < v2.size() ? v1 : v2;
    const std::string_view& long_v = v1.size() < v2.size() ? v2 : v1;
    if (long_v.size() < short_v.size()) return false;
    for (size_t off = 0; off + short_v.size() <= long_v.size(); ++off)
        if (match_at(long_v.substr(off, short_v.size()), short_v)) return true;
    return false;
}

bool check_layout(const Watermark& wm, WatermarkMode mode, u32 fragments,
                  std::string* why) {
    const auto set_why = [why](std::string msg) {
        if (why != nullptr) *why = std::move(msg);
    };
    if (mode != WatermarkMode::Junk && fragments > 1) {
        if (split_fragments(wm, fragments, 4).empty()) {
            set_why("fragments=" + std::to_string(fragments) +
                    " 切分不可行（每片需 >=4 字节且固定位 >= " +
                    std::to_string(kMinFragmentFixedChars) + " 个十六进制字符）");
            return false;
        }
    }
    if (mode == WatermarkMode::Junk || mode == WatermarkMode::Both) {
        if (wm.dump.size() % 4 != 0) {
            set_why("junk 模式要求水印值字节为 4 的倍数（每块占一条 junk-Mov "
                    "imm32；当前 " +
                    std::to_string(wm.dump.size()) + " 字节）");
            return false;
        }
        if (split_fragments(wm, wm.dump.size() / 4, 4).empty()) {
            set_why("junk 4 字节块存在固定位不足的块（每块需 >= " +
                    std::to_string(kMinFragmentFixedChars) +
                    " 个固定十六进制字符）");
            return false;
        }
    }
    return true;
}

} // namespace wvmp::wm

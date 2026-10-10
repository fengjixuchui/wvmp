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

} // namespace wvmp::wm

// MIT-541 水印溯源 v1：核心数据模型与匹配算法（common 层，三方共用）。
//
// 设计蓝本 = vmprotect-3.5.1 的 Watermark/WatermarkManager（深度拆解见
// vmprotect-3.5.1-master/14_WATERMARK_SYSTEM.md），实现口径以
// docs/WATERMARK_TRACING_DESIGN.md 为准：
//   - 水印值 = 十六进制字符串，'?' 为半字节(nibble)通配符；
//   - compile() 把值打包成 dump/mask 对（nibble 级，通配位 mask=0、
//     dump 填 0——通配位的物理填充由嵌入方(pe_writer)用 ctx.rng 现场取，
//     本库保持无 RNG、确定性）；
//   - StreamMatcher = VMProtect Watermark::SearchByte 逐字节流式匹配的
//     忠实移植（多活跃匹配位置 + 掩码比较），CLI 的 scan 子命令、
//     pe_writer 的单测、发行台账核对共用这一个实现，杜绝两处漂移。
//
// 使用方：cli（配置解析校验 + scan）、pe_writer（嵌入）、tests。
#pragma once

#include "wvmp/common/types.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace wvmp::wm {

// 值域常量（与设计文档 §2.1 对齐；改任一须同步 docs 与单测钉板）。
inline constexpr size_t kValueMinChars = 16;  // 8 字节下限
inline constexpr size_t kValueMaxChars = 64;  // 32 字节上限
// 固定位熵下限：非 '?' 字符数 >= 12（48 bit 固定模式）。10MB 文件
// ~10^8 字节扫描窗口下误匹配期望 < 10^-6，仍在可忽略量级。
inline constexpr size_t kMinFixedChars = 12;
// 台账/登记用途的 id 上限（防 TSV 行失控；非安全边界）。
inline constexpr size_t kIdMaxChars = 64;

struct Watermark {
    std::string id;     // 发行对象标识（如 "Customer_A_2026Q4"）
    std::string value;  // 十六进制 + '?'（原样保留，台账/复核用）
    std::vector<u8> dump;  // 编译产物：模式字节（通配位填 0）
    std::vector<u8> mask;  // 编译产物：0xFF=固定位，0x00=通配位（nibble 粒度）

    // 把 value 打包成 dump/mask。前置条件：validate() 已通过（否则
    // std::runtime_error）。幂等：重复调用覆盖旧产物。
    void compile();
};

// 配置期校验（fail-closed）：id 非空、无制表符/换行等 TSV 杀手字符、
// 长度 <= kIdMaxChars；value 满足值域（字符集/偶长/长度窗/固定位下限/
// 非全通配）。失败返回 false 并给出可直读的 why（不带 usage 前缀）。
bool validate(std::string_view id, std::string_view value, std::string* why);

// 嵌入计划（kWatermark 槽的载荷类型；槽缺席 = 不嵌入，pe_writer 输出
// 与无水印现状 byte-exact 一致——MIT-541 缺省零扰动契约）。
struct WatermarkPlan {
    Watermark watermark;  // 已 compile()（dump/mask 就绪）
    u32 copies = 1;       // 嵌入份数（>=1；抗局部篡改冗余）
    std::string issue_log;  // 发行台账路径（空 = 不落台账；由 CLI 填）
};

// 流式单字节匹配器（VMProtect core/core.cc:216 SearchByte 移植）。
// 语义钉板（与参考实现一致，单测按 14_WATERMARK_SYSTEM.md §3.2 序列钉）：
//   - feed() 返回 true 表示"当前字节完成了一次完整匹配"（可多次）；
//   - 掩码比较 (dump[p]&mask[p]) == (v&mask[p])，通配位任意值命中；
//   - 单字节长度模式在匹配字节上返回 true 且不驻留活跃位置。
class StreamMatcher {
public:
    explicit StreamMatcher(const Watermark& wm);

    // 逐字节喂入；返回该字节是否完成一次完整匹配。
    bool feed(u8 v);
    void reset();

private:
    const u8* dump_ = nullptr;
    const u8* mask_ = nullptr;
    size_t len_ = 0;
    std::vector<size_t> pos_;  // 活跃匹配位置（已匹配前缀的下一位置）
};

// 一次性扫描辅助：对 [data, data+size) 全区间跑 StreamMatcher，返回
// 命中次数与文件偏移（offsets 上限 kMaxReportOffsets，防恶意构造的
// 高频模式把终端刷爆）。
inline constexpr size_t kMaxReportOffsets = 64;
struct ScanResult {
    size_t count = 0;             // 总命中次数
    std::vector<size_t> offsets;  // 命中发生的字节偏移（截断至 kMaxReportOffsets）
};
ScanResult scan_bytes(const Watermark& wm, const u8* data, size_t size);

} // namespace wvmp::wm

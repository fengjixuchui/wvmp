// MIT-541 水印溯源 v1：CLI 面单测。
//
// 覆盖：[watermark] 配置解析（接受/拒绝路径）、--watermark 与 scan 的
// 参数解析、registry 解析、scan_file 端到端（合成文件含/不含水印）。
// pe_writer 嵌入面的测试在 passes/pe_writer/tests（需要落节基建）。

#include "wvmp/cli/args.hpp"
#include "wvmp/cli/config.hpp"
#include "wvmp/cli/scan.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace {

class TempFile {
public:
    TempFile(std::string_view name_suffix, std::string_view content) {
        static std::atomic<unsigned> counter{0};
        path_ = std::filesystem::temp_directory_path() /
                ("wvmp_cli_wm_" + std::to_string(counter++) +
                 std::string(name_suffix));
        std::ofstream out(path_, std::ios::binary | std::ios::trunc);
        out << content;
    }
    ~TempFile() {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }
    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;
    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

constexpr const char* kBaseToml =
    "input  = \"target.exe\"\n"
    "output = \"target_protected.exe\"\n";

} // namespace

// —— [watermark] 配置解析 ——
TEST(WatermarkConfig, AcceptsFullTable) {
    const TempFile toml(".toml",
        std::string(kBaseToml) +
        "[watermark]\n"
        "id     = \"Customer_A\"\n"
        "value  = \"4D5A90??11223344\"\n"
        "copies = 5\n"
        "issue_log = \"issues.tsv\"\n");
    const auto r = wvmp::cli::parse_config(toml.path());
    ASSERT_TRUE(r.ok) << r.error;
    ASSERT_TRUE(r.value.has_watermark);
    EXPECT_EQ(r.value.watermark.id, "Customer_A");
    EXPECT_EQ(r.value.watermark.value, "4D5A90??11223344");
    EXPECT_EQ(r.value.watermark.copies, 5u);
    EXPECT_TRUE(r.value.watermark.has_issue_log);
    EXPECT_EQ(r.value.watermark.issue_log, "issues.tsv");
}

TEST(WatermarkConfig, DefaultsIdFromValueAndCopies) {
    const TempFile toml(".toml",
        std::string(kBaseToml) +
        "[watermark]\n"
        "value = \"4D5A9011223344FF\"\n");
    const auto r = wvmp::cli::parse_config(toml.path());
    ASSERT_TRUE(r.ok) << r.error;
    ASSERT_TRUE(r.value.has_watermark);
    EXPECT_EQ(r.value.watermark.id, "4D5A9011");  // value 前 8 字符
    EXPECT_EQ(r.value.watermark.copies, 3u);      // 缺省 3 份
    EXPECT_FALSE(r.value.watermark.has_issue_log);
}

TEST(WatermarkConfig, AbsentTableMeansNoWatermark) {
    const TempFile toml(".toml", kBaseToml);
    const auto r = wvmp::cli::parse_config(toml.path());
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_FALSE(r.value.has_watermark);
}

TEST(WatermarkConfig, RejectsUnknownSubkey) {
    const TempFile toml(".toml",
        std::string(kBaseToml) +
        "[watermark]\n"
        "value = \"4D5A9011223344FF\"\n"
        "frag_cnt = 2\n");  // 真未知键（fragments 已在 M2 转正）
    const auto r = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(r.ok);
    EXPECT_TRUE(contains(r.error, "[watermark] 未知子键 'frag_cnt'"));
}

TEST(WatermarkConfig, RejectsMissingValue) {
    const TempFile toml(".toml",
        std::string(kBaseToml) +
        "[watermark]\n"
        "id = \"A\"\n");
    const auto r = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(r.ok);
    EXPECT_TRUE(contains(r.error, "缺少必填子键 'value'"));
}

TEST(WatermarkConfig, RejectsCopiesOutOfRange) {
    const TempFile toml(".toml",
        std::string(kBaseToml) +
        "[watermark]\n"
        "value = \"4D5A9011223344FF\"\n"
        "copies = 9\n");
    const auto r = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(r.ok);
    EXPECT_TRUE(contains(r.error, "copies"));
}

TEST(WatermarkConfig, RejectsBadValueViaWmValidate) {
    const TempFile toml(".toml",
        std::string(kBaseToml) +
        "[watermark]\n"
        "value = \"4D5A????????????\"\n");  // 固定位不足
    const auto r = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(r.ok);
    EXPECT_TRUE(contains(r.error, "固定位不足"));
}

// —— args：--watermark 覆盖与 scan 子命令 ——
TEST(WatermarkArgs, ProtectWatermarkOverride) {
    const char* argv[] = {"wvmp", "protect", "--config", "c.toml",
                          "--watermark", "4D5A90??11223344"};
    const auto r = wvmp::cli::parse_args(6, argv);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_FALSE(r.is_scan);
    EXPECT_EQ(r.watermark_override, "4D5A90??11223344");
}

TEST(WatermarkArgs, WatermarkNeedsValue) {
    const char* argv[] = {"wvmp", "protect", "--config", "c.toml", "--watermark"};
    const auto r = wvmp::cli::parse_args(5, argv);
    ASSERT_FALSE(r.ok);
    EXPECT_TRUE(contains(r.error, "--watermark 需要一个参数"));
}

TEST(WatermarkArgs, ScanSubcommandParsing) {
    const char* argv[] = {"wvmp", "scan", "--in", "leaked.exe",
                          "--registry", "wm.toml", "--quiet"};
    const auto r = wvmp::cli::parse_args(7, argv);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_TRUE(r.is_scan);
    EXPECT_EQ(r.scan_input, "leaked.exe");
    EXPECT_EQ(r.scan_registry, "wm.toml");
    EXPECT_TRUE(r.scan_quiet);
}

TEST(WatermarkArgs, ScanRequiresRegistry) {
    const char* argv[] = {"wvmp", "scan", "--in", "leaked.exe"};
    const auto r = wvmp::cli::parse_args(4, argv);
    ASSERT_FALSE(r.ok);
    EXPECT_TRUE(contains(r.error, "--registry"));
}

// —— registry 解析 ——
TEST(WatermarkRegistry, ParsesAndCompiles) {
    const TempFile reg(".toml",
        "[[watermarks]]\n"
        "id = \"Customer_A\"\n"
        "value = \"4D5A90??11223344\"\n"
        "[[watermarks]]\n"
        "id = \"Customer_B\"\n"
        "value = \"9F8E7D6C5B4A1122\"\n");
    const auto r = wvmp::cli::parse_watermark_registry(reg.path());
    ASSERT_TRUE(r.ok) << r.error;
    ASSERT_EQ(r.items.size(), 2u);
    EXPECT_EQ(r.items[0].watermark.id, "Customer_A");
    EXPECT_EQ(r.items[0].watermark.dump.size(), 8u);
    EXPECT_EQ(r.items[0].mode, wvmp::wm::WatermarkMode::Padding);
    EXPECT_EQ(r.items[1].watermark.id, "Customer_B");
}

TEST(WatermarkRegistry, RejectsUnknownField) {
    const TempFile reg(".toml",
        "[[watermarks]]\n"
        "id = \"A\"\n"
        "value = \"4D5A9011223344FF\"\n"
        "copies = 3\n");  // registry 面无 copies
    const auto r = wvmp::cli::parse_watermark_registry(reg.path());
    ASSERT_FALSE(r.ok);
    EXPECT_TRUE(contains(r.error, "未知字段 'copies'"));
}

TEST(WatermarkRegistry, RejectsEmpty) {
    // 只含注释 → 缺 [[watermarks]] 数组；显式空数组 → 为空。两条路径都拒。
    const TempFile reg(".toml", "# 空登记\n");
    const auto r = wvmp::cli::parse_watermark_registry(reg.path());
    ASSERT_FALSE(r.ok);
    EXPECT_TRUE(contains(r.error, "缺少 [[watermarks]]"));

    const TempFile reg2(".toml", "watermarks = []\n");
    const auto r2 = wvmp::cli::parse_watermark_registry(reg2.path());
    ASSERT_FALSE(r2.ok);
    EXPECT_TRUE(contains(r2.error, "为空"));
}

TEST(WatermarkRegistry, MissingFile) {
    const auto r = wvmp::cli::parse_watermark_registry(
        std::filesystem::temp_directory_path() / "wvmp_wm_no_such_9f3.toml");
    ASSERT_FALSE(r.ok);
    EXPECT_TRUE(contains(r.error, "不存在"));
}

// —— scan_file 端到端（合成字节流，不经 pe_writer）——
TEST(ScanFile, HitsEmbeddedWatermark) {
    wvmp::wm::Watermark wm;
    wm.id = "Customer_A";
    wm.value = "4D5A90??11223344";
    wm.compile();

    std::string content;
    content += std::string(64, '\0');
    const char pattern_bytes[8] = {'\x4D', '\x5A', '\x90', '\x77',
                                   '\x11', '\x22', '\x33', '\x44'};
    content.append(pattern_bytes, sizeof(pattern_bytes));
    content += std::string(64, '\xAA');
    const TempFile bin(".bin", content);

    const wvmp::cli::ScanItem item{wm, wvmp::wm::WatermarkMode::Padding, 1};
    const auto rep = wvmp::cli::scan_file(bin.path(), {item});
    ASSERT_TRUE(rep.ok) << rep.error;
    ASSERT_TRUE(rep.any_hit);
    ASSERT_EQ(rep.hits.size(), 1u);
    EXPECT_EQ(rep.hits[0].id, "Customer_A");
    EXPECT_EQ(rep.hits[0].count, 1u);
    ASSERT_EQ(rep.hits[0].offsets.size(), 1u);
    EXPECT_EQ(rep.hits[0].offsets[0], 71u);  // 64+8-1：命中完成于末字节
}

TEST(ScanFile, NoHitCleanFile) {
    wvmp::wm::Watermark wm;
    wm.id = "A";
    wm.value = "4D5A90??11223344";
    wm.compile();
    const TempFile bin(".bin", std::string(256, '\x00'));
    const wvmp::cli::ScanItem item{wm, wvmp::wm::WatermarkMode::Padding, 1};
    const auto rep = wvmp::cli::scan_file(bin.path(), {item});
    ASSERT_TRUE(rep.ok) << rep.error;
    EXPECT_FALSE(rep.any_hit);
    EXPECT_TRUE(rep.hits.empty());
}

TEST(ScanFile, MissingInputFails) {
    wvmp::wm::Watermark wm;
    wm.id = "A";
    wm.value = "4D5A9011223344FF";
    wm.compile();
    const wvmp::cli::ScanItem item{wm, wvmp::wm::WatermarkMode::Padding, 1};
    const auto rep = wvmp::cli::scan_file(
        std::filesystem::temp_directory_path() / "wvmp_wm_no_such_7a1.bin", {item});
    ASSERT_FALSE(rep.ok);
    EXPECT_TRUE(contains(rep.error, "无法打开"));
}

// —— M2：mode/fragments 配置面 ——
TEST(WatermarkConfigM2, AcceptsJunkModeWithCoherence) {
    const TempFile toml(".toml",
        std::string(kBaseToml) +
        "[[passes]]\nname = \"mutate\"\n"
        "[[functions]]\nname = \"wvmp_mark_foo\"\ncrypt = false\nlevel = \"virtualize\"\n"
        "[watermark]\nvalue = \"4D5A9011223344FF\"\nmode = \"junk\"\n");
    const auto r = wvmp::cli::parse_config(toml.path());
    ASSERT_TRUE(r.ok) << r.error;
    ASSERT_TRUE(r.value.has_watermark);
    EXPECT_EQ(r.value.watermark.mode, wvmp::wm::WatermarkMode::Junk);
}

TEST(WatermarkConfigM2, JunkModeWithoutCryptExemptionRejected) {
    const TempFile toml(".toml",
        std::string(kBaseToml) +
        "[[passes]]\nname = \"mutate\"\n"
        "[watermark]\nvalue = \"4D5A9011223344FF\"\nmode = \"junk\"\n");
    const auto r = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(r.ok);
    EXPECT_TRUE(contains(r.error, "crypt=false"));
}

TEST(WatermarkConfigM2, JunkModeWithoutMutatePassRejected) {
    const TempFile toml(".toml",
        std::string(kBaseToml) +
        "[[functions]]\nname = \"wvmp_mark_foo\"\ncrypt = false\n"
        "[watermark]\nvalue = \"4D5A9011223344FF\"\nmode = \"junk\"\n");
    const auto r = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(r.ok);
    EXPECT_TRUE(contains(r.error, "mutate"));
}

TEST(WatermarkConfigM2, JunkModeNonMultipleOf4BytesRejected) {
    // 20 hex = 10 字节，10 % 4 != 0。
    const TempFile toml(".toml",
        std::string(kBaseToml) +
        "[[passes]]\nname = \"mutate\"\n"
        "[[functions]]\nname = \"wvmp_mark_foo\"\ncrypt = false\n"
        "[watermark]\nvalue = \"4D5A9011223344FFAABB\"\nmode = \"junk\"\n");
    const auto r = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(r.ok);
    EXPECT_TRUE(contains(r.error, "4 的倍数"));
}

TEST(WatermarkConfigM2, JunkModeFragmentsRejected) {
    const TempFile toml(".toml",
        std::string(kBaseToml) +
        "[[passes]]\nname = \"mutate\"\n"
        "[[functions]]\nname = \"wvmp_mark_foo\"\ncrypt = false\n"
        "[watermark]\nvalue = \"4D5A9011223344FF\"\nmode = \"junk\"\nfragments = 2\n");
    const auto r = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(r.ok);
    EXPECT_TRUE(contains(r.error, "fragments"));
}

TEST(WatermarkConfigM2, PaddingFragmentsAccepted) {
    const TempFile toml(".toml",
        std::string(kBaseToml) +
        "[watermark]\nvalue = \"4D5A9011223344FF\"\nfragments = 2\n");
    const auto r = wvmp::cli::parse_config(toml.path());
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.value.watermark.fragments, 2u);
}

TEST(WatermarkConfigM2, PaddingFragmentsTooManyRejected) {
    // 8 字节 / 4 片 = 每片 2 字节 < 4B 下限。
    const TempFile toml(".toml",
        std::string(kBaseToml) +
        "[watermark]\nvalue = \"4D5A9011223344FF\"\nfragments = 4\n");
    const auto r = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(r.ok);
    EXPECT_TRUE(contains(r.error, "切分不可行"));
}

TEST(WatermarkConfigM2, BothModeAccepted) {
    const TempFile toml(".toml",
        std::string(kBaseToml) +
        "[[passes]]\nname = \"mutate\"\n"
        "[[functions]]\nname = \"wvmp_mark_foo\"\ncrypt = false\n"
        "[watermark]\nvalue = \"4D5A9011223344FF\"\nmode = \"both\"\nfragments = 2\n");
    const auto r = wvmp::cli::parse_config(toml.path());
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.value.watermark.mode, wvmp::wm::WatermarkMode::Both);
}

// —— M2：registry mode/fragments 与防碰撞 ——
TEST(WatermarkRegistryM2, ParsesModeAndFragments) {
    const TempFile reg(".toml",
        "[[watermarks]]\nid = \"A\"\nvalue = \"4D5A9011223344FF\"\nmode = \"junk\"\n"
        "[[watermarks]]\nid = \"B\"\nvalue = \"9F8E7D6C5B4A1122\"\nfragments = 2\n");
    const auto r = wvmp::cli::parse_watermark_registry(reg.path());
    ASSERT_TRUE(r.ok) << r.error;
    ASSERT_EQ(r.items.size(), 2u);
    EXPECT_EQ(r.items[0].mode, wvmp::wm::WatermarkMode::Junk);
    EXPECT_EQ(r.items[1].mode, wvmp::wm::WatermarkMode::Padding);
    EXPECT_EQ(r.items[1].fragments, 2u);
}

TEST(WatermarkRegistryM2, RejectsSimilarPair) {
    // 两枚都过值域（16-64 hex），且长值在偏移 2 处包含短值（滑窗子串）。
    const TempFile reg(".toml",
        "[[watermarks]]\nid = \"Long\"\nvalue = \"AB4D5A9011223344FFCD\"\n"
        "[[watermarks]]\nid = \"Inner\"\nvalue = \"4D5A9011223344FF\"\n");
    const auto r = wvmp::cli::parse_watermark_registry(reg.path());
    ASSERT_FALSE(r.ok);
    EXPECT_TRUE(contains(r.error, "过相似"));
    EXPECT_TRUE(contains(r.error, "Long"));
    EXPECT_TRUE(contains(r.error, "Inner"));
}

TEST(WatermarkRegistryM2, RejectsWildcardOverlapPair) {
    // 等长 16 hex，仅两个 '?' 抹平差异 → match_at 全配 = 相似。
    const TempFile reg(".toml",
        "[[watermarks]]\nid = \"A\"\nvalue = \"4D5A9011223344FF\"\n"
        "[[watermarks]]\nid = \"B\"\nvalue = \"4D5A9011??3344FF\"\n");
    const auto r = wvmp::cli::parse_watermark_registry(reg.path());
    ASSERT_FALSE(r.ok);
    EXPECT_TRUE(contains(r.error, "过相似"));
}

TEST(WatermarkRegistryM2, DisjointPairAccepted) {
    const TempFile reg(".toml",
        "[[watermarks]]\nid = \"A\"\nvalue = \"4D5A9011223344FF\"\n"
        "[[watermarks]]\nid = \"B\"\nvalue = \"9F8E7D6C5B4A1122\"\n");
    const auto r = wvmp::cli::parse_watermark_registry(reg.path());
    ASSERT_TRUE(r.ok) << r.error;
}

// —— M2：scan_file 碎片多数票 ——
namespace {
wvmp::cli::ScanItem make_item(const char* value, wvmp::wm::WatermarkMode mode,
                              wvmp::u32 fragments) {
    wvmp::cli::ScanItem it;
    it.watermark.id = "T";
    it.watermark.value = value;
    it.watermark.compile();
    it.mode = mode;
    it.fragments = fragments;
    return it;
}
} // namespace

TEST(ScanFileM2, FragmentedPaddingMajorityVote) {
    // fragments=2：两片 4D5A9011 / 223344FF 分散两处。
    const auto item = make_item("4D5A9011223344FF",
                                wvmp::wm::WatermarkMode::Padding, 2);
    std::string content;
    content += std::string(32, 'x');
    content += std::string("\x4D\x5A\x90\x11", 4);
    content += std::string(64, 'y');
    content += std::string("\x22\x33\x44\xFF", 4);
    const TempFile bin(".bin", content);
    const auto rep = wvmp::cli::scan_file(bin.path(), {item});
    ASSERT_TRUE(rep.ok) << rep.error;
    ASSERT_TRUE(rep.any_hit);
    ASSERT_EQ(rep.hits.size(), 1u);
    EXPECT_EQ(rep.hits[0].count, 2u);
}

TEST(ScanFileM2, FragmentSinglePieceNotIdentified) {
    const auto item = make_item("4D5A9011223344FF",
                                wvmp::wm::WatermarkMode::Padding, 2);
    std::string content(64, 'x');
    content += std::string("\x4D\x5A\x90\x11", 4);  // 只有一片
    const TempFile bin(".bin", content);
    const auto rep = wvmp::cli::scan_file(bin.path(), {item});
    ASSERT_TRUE(rep.ok) << rep.error;
    EXPECT_FALSE(rep.any_hit);
}

TEST(ScanFileM2, JunkChunksMajorityVote) {
    // junk 方案：8 字节 → 2 块 4B（模拟 VM 词 aux 面的分散 4 字节块）。
    const auto item = make_item("4D5A9011223344FF",
                                wvmp::wm::WatermarkMode::Junk, 1);
    std::string content;
    content += std::string(16, 'x');
    content += std::string("\x22\x33\x44\xFF", 4);  // 块 1（低地址块字节序 = dump 序）
    content += std::string(16, 'y');
    content += std::string("\x4D\x5A\x90\x11", 4);  // 块 0
    const TempFile bin(".bin", content);
    const auto rep = wvmp::cli::scan_file(bin.path(), {item});
    ASSERT_TRUE(rep.ok) << rep.error;
    ASSERT_TRUE(rep.any_hit);
}

TEST(ScanFileM2, WholePatternNoLongerRequiredForJunkItem) {
    // junk 条目：整段连续形态不识别（8 字节连排 = 整段匹配面，junk 条目
    // 按 4B 块投票——连排时两块恰好都中，仍识别；此用例钉"块分散"才是
    // junk 的目标形态且连排不劣化）。
    const auto item = make_item("4D5A9011223344FF",
                                wvmp::wm::WatermarkMode::Junk, 1);
    std::string content;
    content += std::string("\x4D\x5A\x90\x11\x22\x33\x44\xFF", 8);
    const TempFile bin(".bin", content);
    const auto rep = wvmp::cli::scan_file(bin.path(), {item});
    ASSERT_TRUE(rep.ok) << rep.error;
    EXPECT_TRUE(rep.any_hit)
;  // 连排覆盖两块 → 仍过票
}

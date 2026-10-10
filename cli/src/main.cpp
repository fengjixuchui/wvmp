// wvmp 命令行入口（P8 泳道）。
//
// 子命令：
//   wvmp protect --config <file> [-o <output>] [--watermark <hex>] [--dry-run]
//   wvmp scan --in <file> --registry <toml> [--quiet]   (MIT-541 水印溯源)
//   wvmp version
//
// 退出码约定：
//   0  成功（dry-run 打印管道后退出也走这里）
//   1  参数 / 配置 / 管道装配错误（含 from_names 抛错：未知 pass、依赖缺失；
//      scan 的全未命中也走这里——可直接脚本化批量筛查）
//   2  管道运行期失败（run 抛错；diag 尾部会打印到 stderr）

#include "wvmp/cli/args.hpp"
#include "wvmp/cli/config.hpp"
#include "wvmp/cli/scan.hpp"

#include "wvmp/common/sha256.hpp"
#include "wvmp/framework/context.hpp"
#include "wvmp/framework/diagnostics.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/pass.hpp"
#include "wvmp/framework/phase.hpp"
#include "wvmp/framework/pipeline.hpp"
#include "wvmp/passes/pe_loader/target_arch.hpp"
#include "wvmp/wm/watermark.hpp"

#include <chrono>
#include <cstdio>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
#include <vector>

namespace {

// 与根 CMakeLists 的 project(wvmp VERSION 0.1.0) 保持一致。
constexpr char kVersion[] = "wvmp 0.1.0";

const char* severity_tag(wvmp::Severity s) {
    switch (s) {
    case wvmp::Severity::Note: return "note";
    case wvmp::Severity::Warning: return "warning";
    case wvmp::Severity::Error: return "error";
    }
    return "?";
}

void print_diag_item(const wvmp::Diagnostic& d) {
    std::fprintf(stderr, "[wvmp] [%s] %s: %s\n", severity_tag(d.severity),
                 d.pass.c_str(), d.message.c_str());
}

// run 失败时打印诊断尾部（最后 5 条，含 pass 名，便于定位是谁抛的）。
void print_diag_tail(const wvmp::Diagnostics& diag) {
    const auto& items = diag.items();
    if (items.empty()) return;
    const size_t first = items.size() > 5 ? items.size() - 5 : 0;
    std::fprintf(stderr, "[wvmp] ---- 诊断尾部 ----\n");
    for (size_t i = first; i < items.size(); ++i) print_diag_item(items[i]);
}

// 成功时打印 pass 留下的 Note / Warning（Error 不该出现在这里）。
void print_diag_notes(const wvmp::Diagnostics& diag) {
    for (const auto& d : diag.items())
        if (d.severity != wvmp::Severity::Error) print_diag_item(d);
}

// 按 stages() 的实际顺序（已按 Phase 排好序）渲染：
//   Load: pe_loader → Analyze: marker_scan, lifter → Transform: virtualize → Write: pe_writer
std::string describe_pipeline(const wvmp::Pipeline& pipe) {
    const auto& stages = pipe.stages();
    std::string out = "将执行的管道：";
    for (size_t i = 0; i < stages.size(); ++i) {
        const bool new_phase = i == 0 || stages[i]->phase() != stages[i - 1]->phase();
        if (new_phase) {
            if (i != 0) out += " → ";
            out += std::string(wvmp::to_string(stages[i]->phase())) + ": ";
        } else {
            out += ", ";
        }
        out += std::string(stages[i]->name());
    }
    if (stages.empty()) out += "(空管道)";
    return out;
}

int cmd_version() {
    std::puts(kVersion);
    return 0;
}

// MIT-541：scan 子命令——泄露副本 → 水印 ID 反查。
// 退出码：0 = 至少一枚命中；1 = 全未命中或执行面失败（错误打到 stderr）。
int cmd_scan(const wvmp::cli::ArgsResult& args) {
    const wvmp::cli::WatermarkRegistryResult reg =
        wvmp::cli::parse_watermark_registry(args.scan_registry);
    if (!reg.ok) {
        std::fprintf(stderr, "[wvmp] %s\n", reg.error.c_str());
        return 1;
    }
    const wvmp::cli::ScanReport rep = wvmp::cli::scan_file(args.scan_input, reg.items);
    if (!rep.ok) {
        std::fprintf(stderr, "[wvmp] %s\n", rep.error.c_str());
        return 1;
    }
    if (!rep.any_hit) {
        if (!args.scan_quiet)
            std::printf("[wvmp] 未命中任何已登记水印（%zu 枚）\n", reg.items.size());
        return 1;
    }
    for (const auto& hit : rep.hits) {
        std::string offs;
        for (size_t i = 0; i < hit.offsets.size(); ++i) {
            char b[24];
            std::snprintf(b, sizeof(b), "%s0x%llX", i == 0 ? "" : ",",
                          static_cast<unsigned long long>(hit.offsets[i]));
            offs += b;
        }
        if (hit.offsets.size() == wvmp::wm::kMaxReportOffsets) offs += ",…";
        if (args.scan_quiet)
            std::printf("%s\n", hit.id.c_str());
        else
            std::printf("[wvmp] 命中=%zu 次 @ file_off %s → %s\n",
                        hit.count, offs.c_str(), hit.id.c_str());
    }
    return 0;
}

// MIT-541：发行台账追加（溯源闭环的关键一环——scan 只能给出水印 ID，
// "ID → 发给谁" 的答案在这本台账里）。列：时间/id/值/seed/sha256 前
// 16/输出路径。写入失败 = 溯源断链，按 fail-closed 报 rc=2（产物已
// 原子落盘不回滚，消息里明示需手工补记）。
bool append_issue_log(const std::string& path, const wvmp::wm::WatermarkPlan& plan,
                      wvmp::u64 seed, const std::string& output) {
    // 产物指纹：读回输出文件算 sha256（前 16 字符）。
    std::ifstream in(output, std::ios::binary);
    if (!in) return false;
    std::vector<wvmp::u8> bytes((std::istreambuf_iterator<char>(in)),
                                std::istreambuf_iterator<char>());
    if (!in.eof() && in.fail()) return false;
    const std::string sha16 = wvmp::sha256_hex(bytes.data(), bytes.size())
                                  .substr(0, 16);
    // 本地时区 ISO-8601（台账是给人查的，用本地时刻）。
    char ts[40];
    {
        const auto now = std::chrono::system_clock::now();
        const std::time_t t = std::chrono::system_clock::to_time_t(now);
        std::tm tmv{};
#ifdef _WIN32
        localtime_s(&tmv, &t);
#else
        localtime_r(&t, &tmv);
#endif
        std::snprintf(ts, sizeof(ts), "%04d-%02d-%02dT%02d:%02d:%02d",
                      tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
                      tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    }
    std::error_code ec;
    const bool fresh = !std::filesystem::exists(path, ec);
    std::ofstream out(path, std::ios::app);
    if (!out) return false;
    if (fresh)
        out << "# timestamp\tid\tvalue\tseed\tsha256_16\toutput\n";
    out << ts << '\t' << plan.watermark.id << '\t' << plan.watermark.value
        << '\t' << seed << '\t' << sha16 << '\t' << output << '\n';
    out.flush();
    return static_cast<bool>(out);
}

int cmd_protect(const wvmp::cli::ArgsResult& args) {
    // 1) 配置。
    const wvmp::cli::ConfigResult cfg = wvmp::cli::parse_config(args.config_path);
    if (!cfg.ok) {
        std::fprintf(stderr, "[wvmp] %s\n", cfg.error.c_str());
        return 1;
    }
    const wvmp::cli::WvmpConfig& config = cfg.value;

    std::string output = config.output;
    if (!args.output_override.empty()) output = args.output_override;

    // MIT-541 水印溯源 v1：解析生效水印（--watermark 覆盖 > [watermark]；
    // 两者皆缺 = 不嵌水印，缺省零扰动）。值域校验 + compile 在这里一次
    // 做完，pe_writer 只消费现成计划。
    bool wm_active = false;
    wvmp::wm::WatermarkPlan wm_plan;
    {
        const std::string wm_value = !args.watermark_override.empty()
                                         ? args.watermark_override
                                         : (config.has_watermark
                                                ? config.watermark.value
                                                : std::string());
        if (!wm_value.empty()) {
            wm_active = true;
            wm_plan.watermark.id = config.has_watermark && !config.watermark.id.empty()
                                       ? config.watermark.id
                                       : wm_value.substr(0, 8);
            wm_plan.watermark.value = wm_value;
            wm_plan.copies = config.has_watermark ? config.watermark.copies : 3;
            std::string why;
            if (!wvmp::wm::validate(wm_plan.watermark.id, wm_value, &why)) {
                std::fprintf(stderr, "[wvmp] 水印配置无效: %s\n", why.c_str());
                return 1;
            }
            try {
                wm_plan.watermark.compile();
            } catch (const std::exception& e) {
                std::fprintf(stderr, "[wvmp] 水印编译失败: %s\n", e.what());
                return 1;
            }
        }
    }

    // 2) 装配管道（未知名 / 依赖缺失在 from_names 里抛）。
    std::vector<std::string> names;
    names.reserve(config.passes.size());
    for (const auto& p : config.passes) names.push_back(p.name);

    wvmp::Pipeline pipeline;
    try {
        pipeline = wvmp::Pipeline::from_names(names);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[wvmp] %s\n", e.what());
        return 1;
    }

    // 3) 打印任务摘要（dry-run 与真实执行共用）。
    std::printf("[wvmp] input : %s\n", config.input.c_str());
    std::printf("[wvmp] output: %s%s\n", output.c_str(),
                output != config.output ? "（-o 覆盖）" : "");
    std::printf("[wvmp] seed  : %llu\n", static_cast<unsigned long long>(config.seed));
    if (!config.rules.functions.empty() ||
        config.rules.default_level != wvmp::ProtectLevel::Virtualize) {
        std::printf("[wvmp] 档位  : default=%.*s, %zu 条函数规则\n",
                    static_cast<int>(wvmp::to_string(config.rules.default_level).size()),
                    wvmp::to_string(config.rules.default_level).data(),
                    config.rules.functions.size());
    }
    const auto& pr = config.rules;
    if (pr.has_mutate_density || pr.has_anti_debug_techniques ||
        pr.has_anti_debug_init || pr.has_tls_enabled) {
        std::printf("[wvmp] 参数  :");
        if (pr.has_mutate_density)
            std::printf(" mutate 密度=%u%%", pr.mutate_density);
        if (pr.has_anti_debug_techniques)
            std::printf(" anti_debug 位面=%u", pr.anti_debug_techniques);
        if (pr.has_anti_debug_init)
            std::printf(" anti_debug init=%s", pr.anti_debug_init ? "on" : "off");
        if (pr.has_tls_enabled)
            std::printf(" tls=%s", pr.tls_enabled ? "on" : "off");
        std::printf("\n");
    }
    if (wm_active) {
        const size_t fixed = [&] {
            size_t n = 0;
            for (const char c : wm_plan.watermark.value)
                if (c != '?') ++n;
            return n;
        }();
        std::printf("[wvmp] 水印 : id=%s 固定位=%zub copies=%u%s\n",
                    wm_plan.watermark.id.c_str(), fixed, wm_plan.copies,
                    args.watermark_override.empty() ? "" : "（--watermark 覆盖）");
    }
    std::printf("[wvmp] %s\n", describe_pipeline(pipeline).c_str());

    if (args.dry_run) {
        std::puts("[wvmp] dry-run：仅装配，未执行。");
        return 0;
    }

    // 4) 真实执行。
    wvmp::ProtectionContext ctx;
    ctx.input_path = config.input;
    ctx.output_path = output;
    ctx.seed = config.seed;
    ctx.rng.reseed(config.seed);
    // MIT-438 (X1b) B.5: arch 声明 → pe_loader 校验挂点。穷举 switch 映射
    // 到 pe_loader target_arch.hpp 的槽常量（新增枚举值时编译期缺 case 警告，
    // 防两处定义面漂移）。
    ctx.slot<wvmp::u8>(wvmp::passes::kTargetArchDecl) = [](wvmp::cli::ArchOpt a) {
        switch (a) {
        case wvmp::cli::ArchOpt::Auto: return wvmp::passes::kTargetArchAuto;
        case wvmp::cli::ArchOpt::X64: return wvmp::passes::kTargetArchX64;
        case wvmp::cli::ArchOpt::X86: return wvmp::passes::kTargetArchX86;
        }
        return wvmp::passes::kTargetArchAuto;
    }(config.arch);
    // MIT-457 配置系统 v1：保护规则集入槽（kProtectRules）。空规则集也写入
    // ——对 pass 而言"缺省档位"语义与槽缺席等价，写入统一两条取值路径。
    ctx.slot<wvmp::ProtectRules>(wvmp::kProtectRules) = config.rules;
    // MIT-541 水印溯源 v1：计划入槽（kWatermark）。仅在生效时写入——
    // 槽缺席 = pe_writer 不嵌入（缺省零扰动契约）。
    if (wm_active) ctx.slot<wvmp::wm::WatermarkPlan>(wvmp::kWatermark) = wm_plan;

    try {
        pipeline.run(ctx);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[wvmp] 管道执行失败: %s\n", e.what());
        print_diag_tail(ctx.diag);
        return 2;
    }

    // M1 决策（P8 遗留项）：run 正常返回但 diag 含 Error 级条目时视为失败——
    // "没抛但报过错"的 pass 不应被静默放过。
    if (ctx.diag.has_errors()) {
        std::fprintf(stderr, "[wvmp] 管道完成但诊断含 %zu 条 Error：\n",
                     ctx.diag.items().size());
        print_diag_tail(ctx.diag);
        return 2;
    }

    print_diag_notes(ctx.diag);
    // MIT-457 配置系统 v1：区域清单单行披露（[[functions]] 规则的 rva/index
    // 选择器取此口径）。放 CLI 而非 marker_scan Note——pass 层保持"正常路径
    // 零诊断"的既有测试契约。
    if (!ctx.functions.empty()) {
        std::string list = "[wvmp] 区域清单:";
        for (size_t i = 0; i < ctx.functions.size(); ++i) {
            char buf[160];
            std::snprintf(buf, sizeof(buf), " [%zu] %s rva=0x%llX", i,
                          ctx.functions[i].name.c_str(),
                          static_cast<unsigned long long>(ctx.functions[i].begin_rva));
            list += buf;
        }
        std::printf("%s\n", list.c_str());
    }
    std::printf("[wvmp] 完成: %s -> %s\n", config.input.c_str(), output.c_str());

    // MIT-541：发行台账（仅配置了 issue_log 时落）。失败 = 溯源断链，
    // rc=2 明示（产物已落盘不回滚，消息点名手工补记）。
    if (wm_active && config.has_watermark && config.watermark.has_issue_log) {
        if (!append_issue_log(config.watermark.issue_log, wm_plan,
                              config.seed, output)) {
            std::fprintf(stderr,
                         "[wvmp] 发行台账写入失败: %s（产物已生成，请手工补记 "
                         "id=%s seed=%llu output=%s）\n",
                         config.watermark.issue_log.c_str(),
                         wm_plan.watermark.id.c_str(),
                         static_cast<unsigned long long>(config.seed),
                         output.c_str());
            return 2;
        }
        if (!args.dry_run)
            std::printf("[wvmp] 台账 : %s（id=%s）\n",
                        config.watermark.issue_log.c_str(),
                        wm_plan.watermark.id.c_str());
    }
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    const wvmp::cli::ArgsResult args = wvmp::cli::parse_args(argc, argv);
    if (!args.ok) {
        std::fprintf(stderr, "[wvmp] %s\n", args.error.c_str());
        return 1;
    }
    if (args.is_version) return cmd_version();
    if (args.is_scan) return cmd_scan(args);
    return cmd_protect(args);
}

#include "wvmp/cli/args.hpp"

#include <string_view>

namespace wvmp::cli {
namespace {

constexpr std::string_view kUsage =
    "usage:\n"
    "  wvmp protect --config <file> [-o <output>] [--watermark <hex>] [--dry-run]\n"
    "  wvmp scan --in <file> --registry <toml> [--quiet]\n"
    "  wvmp version";

ArgsResult fail(std::string error) {
    ArgsResult result;
    result.ok = false;
    result.error = std::move(error);
    result.error += "\n";
    result.error += kUsage;
    return result;
}

ArgsResult parse_protect(int argc, const char* const argv[], int first_flag) {
    ArgsResult result;
    for (int i = first_flag; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg == "--config") {
            if (i + 1 >= argc)
                return fail("--config 需要一个参数（TOML 配置文件路径）");
            result.config_path = argv[++i];
        } else if (arg == "-o") {
            if (i + 1 >= argc)
                return fail("-o 需要一个参数（输出路径，覆盖配置里的 output）");
            result.output_override = argv[++i];
        } else if (arg == "--watermark") {
            // MIT-541：水印值覆盖（十六进制 + '?'；值域校验在 main 落槽
            // 前做——解析层只管取值）。
            if (i + 1 >= argc)
                return fail("--watermark 需要一个参数（水印值：十六进制 + '?' "
                            "通配符，覆盖配置里的 [watermark].value）");
            result.watermark_override = argv[++i];
        } else if (arg == "--dry-run") {
            result.dry_run = true;
        } else if (arg.starts_with('-')) {
            return fail("未知选项 '" + std::string(arg) + "'");
        } else {
            return fail("多余的位置参数 '" + std::string(arg) + "'（protect 不接受）");
        }
    }
    if (result.config_path.empty())
        return fail("protect 需要 --config <file>");
    result.ok = true;
    return result;
}

ArgsResult parse_scan(int argc, const char* const argv[], int first_flag) {
    ArgsResult result;
    for (int i = first_flag; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg == "--in") {
            if (i + 1 >= argc)
                return fail("--in 需要一个参数（待扫描的 PE 文件路径）");
            result.scan_input = argv[++i];
        } else if (arg == "--registry") {
            if (i + 1 >= argc)
                return fail("--registry 需要一个参数（已登记水印 TOML 路径）");
            result.scan_registry = argv[++i];
        } else if (arg == "--quiet") {
            result.scan_quiet = true;
        } else if (arg.starts_with('-')) {
            return fail("未知选项 '" + std::string(arg) + "'");
        } else {
            return fail("多余的位置参数 '" + std::string(arg) + "'（scan 不接受）");
        }
    }
    if (result.scan_input.empty())
        return fail("scan 需要 --in <file>");
    if (result.scan_registry.empty())
        return fail("scan 需要 --registry <toml>");
    result.ok = true;
    result.is_scan = true;
    return result;
}

} // namespace

ArgsResult parse_args(int argc, const char* const argv[]) {
    if (argc < 2)
        return fail("缺少子命令");
    const std::string_view sub = argv[1];
    if (sub == "version") {
        if (argc > 2)
            return fail("version 不接受额外参数: '" + std::string(argv[2]) + "'");
        ArgsResult result;
        result.ok = true;
        result.is_version = true;
        return result;
    }
    if (sub == "protect")
        return parse_protect(argc, argv, 2);
    if (sub == "scan")
        return parse_scan(argc, argv, 2);
    return fail("未知子命令 '" + std::string(sub) + "'");
}

} // namespace wvmp::cli

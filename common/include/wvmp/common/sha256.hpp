// MIT-541 水印溯源 v1：发行台账用的 SHA-256（FIPS 180-4）。
//
// 台账记录保护产物指纹，取证场景下 CRC32 碰撞成本过低不可用，故补一个
// 自包含实现（无第三方依赖，单测钉标准测试向量）。仅服务台账/复核，
// 不参与任何保护语义。
#pragma once

#include "wvmp/common/types.hpp"

#include <array>
#include <cstdint>
#include <string>

namespace wvmp {

// 计算数据的 SHA-256，返回 32 字节摘要。
std::array<u8, 32> sha256(const u8* data, size_t size);

// 便捷形：十六进制小写（64 字符）。
std::string sha256_hex(const u8* data, size_t size);

} // namespace wvmp

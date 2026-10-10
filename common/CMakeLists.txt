add_library(wvmp_common
    src/bytes.cpp
    src/sha256.cpp
    src/wm/watermark.cpp
)
add_library(wvmp::common ALIAS wvmp_common)
target_include_directories(wvmp_common PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
wvmp_target_warnings(wvmp_common)

if(WVMP_BUILD_TESTS)
    # MIT-541 水印溯源 v1：wm 核心库 + sha256 单测（钉板 = 参考文档示例
    # 与 FIPS/CPython 向量）。
    add_executable(wvmp_common_tests
        tests/test_watermark.cpp
    )
    target_link_libraries(wvmp_common_tests PRIVATE
        wvmp::common
        wvmp::gtest
        gtest_main
    )
    wvmp_target_warnings(wvmp_common_tests)
    add_test(NAME common_watermark_and_sha256 COMMAND wvmp_common_tests)
endif()

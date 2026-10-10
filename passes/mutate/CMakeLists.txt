add_library(wvmp_pass_mutate OBJECT
    src/mutate_pass.cpp
)
target_include_directories(wvmp_pass_mutate PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
# MIT-541 M2：PeImage 模型头（kImageMeta 槽读取——junk 水印的映像窗口
# 镜像判定）。
target_link_libraries(wvmp_pass_mutate PRIVATE wvmp::framework wvmp::ir wvmp::common wvmp_pass_pe_loader)
wvmp_target_warnings(wvmp_pass_mutate)

if(WVMP_BUILD_TESTS)
    add_subdirectory(tests)
endif()

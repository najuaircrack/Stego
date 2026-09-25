# stego — v2 stego library (static, add_subdirectory-able).
cmake_minimum_required(VERSION 3.20)

add_library(stego STATIC
    src/sha256.cpp
    src/codec.cpp
    src/api.cpp
)

target_include_directories(stego PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

add_library(stego::stego ALIAS stego)

option(STEGO_BUILD_TESTS "Build C++ self-tests + harness (dev/CI only)" OFF)
option(STEGO_BUILD_EXAMPLES "Build C++ example templates (dev/CI only)" OFF)
if(STEGO_BUILD_TESTS)
    enable_testing()
    add_executable(stego_test tests/test_codec.cpp)
    target_link_libraries(stego_test PRIVATE stego::stego)
    add_test(NAME stego_codec COMMAND stego_test)
    add_executable(stego_harness tests/harness.cpp)
    target_link_libraries(stego_harness PRIVATE stego::stego)
    # Amalgamation identity: same vectors through single_include build.
    add_executable(stego_amalgam tests/amalgam_check.cpp)
    target_include_directories(stego_amalgam PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/single_include")
    target_include_directories(stego_amalgam PRIVATE single_include)
endif()
if(STEGO_BUILD_EXAMPLES)
    # GDI+ templates are Windows-only. extract.c is portable (raw RGB input).
    if(WIN32)
        add_executable(extract_cpp examples/extract.cpp)
        target_link_libraries(extract_cpp PRIVATE stego::stego gdiplus)
    endif()
    # extract.c uses only the C ABI over raw RGB (no platform code) — no libs.
    add_executable(extract_c examples/extract.c)
    set_source_files_properties(examples/extract.c PROPERTIES LANGUAGE CXX)
    target_include_directories(extract_c PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/single_include")
endif()

# Install rules (open-source ready): headers + static lib.
include(GNUInstallDirs)
install(DIRECTORY include/stego DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
install(TARGETS stego ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")

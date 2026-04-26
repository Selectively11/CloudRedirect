cmake_minimum_required(VERSION 3.20)
project(CloudRedirect LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# DLL loaded by SteamTools payload via code cave (LoadLibrary + GetProcAddress)
add_library(cloud_redirect SHARED
    src/dllmain.cpp
    src/log.cpp
    src/protobuf.cpp
    src/cloud_intercept.cpp
    src/rpc_handlers.cpp
    src/http_server.cpp
    src/http_util.cpp
    src/local_storage.cpp
    src/cloud_storage.cpp
    src/legacy_metadata_cleanup.cpp
    src/local_disk_provider.cpp
    src/cloud_provider_base.cpp
    src/google_drive.cpp
    src/onedrive.cpp
    src/json.cpp
    src/vdf.cpp
    src/remotecache_repair.cpp
    src/miniz.c
    src/miniz_tdef.c
    src/miniz_tinfl.c
    src/miniz_zip.c
)

target_include_directories(cloud_redirect PRIVATE src)
target_compile_definitions(cloud_redirect PRIVATE MINIZ_NO_STDIO)
target_link_libraries(cloud_redirect PRIVATE Shlwapi Advapi32 ws2_32 winhttp Crypt32 Shell32 Ole32 Psapi)

enable_testing()

# Tests are dev-only (not shipped). Build them only when the directory is present.
if(EXISTS ${CMAKE_SOURCE_DIR}/tests/autocloud_native_tests.cpp)
    add_executable(autocloud_native_tests
        tests/autocloud_native_tests.cpp
        src/local_storage.cpp
        src/log.cpp
    )
    target_include_directories(autocloud_native_tests PRIVATE src)
    target_compile_definitions(autocloud_native_tests PRIVATE CLOUDREDIRECT_TESTING)
    target_link_libraries(autocloud_native_tests PRIVATE Shlwapi Advapi32 Shell32 Ole32)
    add_test(NAME autocloud_native_tests COMMAND autocloud_native_tests)

    add_executable(legacy_metadata_cleanup_tests
        tests/legacy_metadata_cleanup_tests.cpp
        src/legacy_metadata_cleanup.cpp
        src/log.cpp
    )
    target_include_directories(legacy_metadata_cleanup_tests PRIVATE src)
    target_compile_definitions(legacy_metadata_cleanup_tests PRIVATE CLOUDREDIRECT_TESTING)
    target_link_libraries(legacy_metadata_cleanup_tests PRIVATE Shlwapi Advapi32 Shell32 Ole32)
    add_test(NAME legacy_metadata_cleanup_tests COMMAND legacy_metadata_cleanup_tests)

    add_executable(remotecache_repair_tests
        tests/remotecache_repair_tests.cpp
        src/remotecache_repair.cpp
        src/vdf.cpp
    )
    target_include_directories(remotecache_repair_tests PRIVATE src)
    add_test(NAME remotecache_repair_tests COMMAND remotecache_repair_tests)
endif()

# UI (builds DLL first, then publishes the WPF app with the DLL embedded)
add_custom_target(ui ALL
    COMMAND dotnet publish -c Release -r win-x64 --self-contained false -o bin/publish
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/ui
    COMMENT "Publishing CloudRedirect UI"
    DEPENDS cloud_redirect
)


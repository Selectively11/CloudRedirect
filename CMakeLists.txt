cmake_minimum_required(VERSION 3.20)
project(CloudRedirect LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ── Read version from Version.props ─────────────────────────────────────
file(READ "${CMAKE_SOURCE_DIR}/Version.props" VERSION_PROPS_CONTENT)
string(REGEX MATCH "<ReleaseVersion>([^<]+)</ReleaseVersion>" _ "${VERSION_PROPS_CONTENT}")
set(CR_RELEASE_VERSION "${CMAKE_MATCH_1}")

if(NOT CR_RELEASE_VERSION)
    set(CR_RELEASE_VERSION "0.0.0")
endif()

# ── Generate version string with git SHA ────────────────────────────────
execute_process(
    COMMAND git rev-parse --short=7 HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_SHA
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
    RESULT_VARIABLE GIT_RESULT
)
if(NOT GIT_RESULT EQUAL 0)
    set(GIT_SHA "unknown")
endif()

# Check for dirty working tree
execute_process(
    COMMAND git status --porcelain
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_STATUS
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(GIT_STATUS)
    set(GIT_SHA "${GIT_SHA}-dirty")
endif()

set(CR_SO_VERSION "${CR_RELEASE_VERSION}+${GIT_SHA}")

# ── Common sources (platform-agnostic) ──────────────────────────────────

set(COMMON_SOURCES
    src/common/protobuf.cpp
    src/common/json.cpp
    src/common/vdf.cpp
    src/common/bkv_stats.cpp
    src/common/remotecache_repair.cpp
    src/common/manifest_store.cpp
    src/common/token_store.cpp
    src/common/batch_tracker.cpp
    src/common/cloud_staging.cpp
    src/common/pending_ops_journal.cpp
    src/common/rpc_handlers.cpp
    src/common/cloud_work_queue.cpp
    src/common/cloud_storage.cpp
    src/common/local_storage.cpp
    src/common/local_metadata_store.cpp
    src/common/legacy_metadata_cleanup.cpp
    src/common/cli.cpp
    src/common/cloud_provider_base.cpp
    src/common/autocloud_scan.cpp
    src/common/autocloud_bootstrap.cpp
    src/common/miniz.c
    src/common/miniz_tdef.c
    src/common/miniz_tinfl.c
    src/common/miniz_zip.c
)

# ── Platform-specific sources ───────────────────────────────────────────

set(PROVIDER_SOURCES
    src/providers/google_drive.cpp
    src/providers/onedrive.cpp
    src/providers/local_disk_provider.cpp
)

if(WIN32)
    set(PLATFORM_SOURCES
        src/platform/win/dllmain.cpp
        src/platform/win/cloud_intercept.cpp
        src/platform/win/log.cpp
        src/platform/win/http_server.cpp
        src/platform/win/http_util.cpp
        src/platform/win/http_transport_win.cpp
        src/platform/win/token_store_win.cpp
        src/platform/win/platform_win.cpp
    )
else()
    set(PLATFORM_SOURCES
        src/platform/linux/init.cpp
        src/platform/linux/vtable_hook.cpp
        src/platform/linux/cloud_hooks.cpp
        src/platform/linux/cloud_intercept.cpp
        src/platform/linux/http_transport_linux.cpp
        src/platform/linux/token_store_linux.cpp
        src/platform/linux/log.cpp
        src/platform/linux/http_server.cpp
        src/platform/linux/http_util.cpp
        src/platform/linux/platform_linux.cpp
        src/platform/linux/file_util.cpp
    )
endif()

# ── Build target ────────────────────────────────────────────────────────

add_library(cloud_redirect SHARED
    ${COMMON_SOURCES}
    ${PLATFORM_SOURCES}
    ${PROVIDER_SOURCES}
)

set_target_properties(cloud_redirect PROPERTIES PREFIX "")

target_include_directories(cloud_redirect PRIVATE
    src/common
    src/providers
)

target_compile_definitions(cloud_redirect PRIVATE
    MINIZ_NO_STDIO
    CR_VERSION_STRING="${CR_SO_VERSION}"
    CR_RELEASE_VERSION="${CR_RELEASE_VERSION}"
)

if(WIN32)
    target_include_directories(cloud_redirect PRIVATE src/platform/win)
    target_link_libraries(cloud_redirect PRIVATE
        Shlwapi Advapi32 ws2_32 winhttp Crypt32 Shell32 Ole32 Psapi
    )
    
    # CLI wrapper executable
    add_executable(cloud_redirect_cli
        src/platform/win/cli_main.cpp
    )
    target_link_libraries(cloud_redirect_cli PRIVATE Shell32 Ole32)
    # Ensure DLL is built before CLI
    add_dependencies(cloud_redirect_cli cloud_redirect)
else()
    target_include_directories(cloud_redirect PRIVATE src/platform/linux)
    target_link_libraries(cloud_redirect PRIVATE dl pthread)
    # Steam on Linux is 32-bit; use LINUX_32BIT=ON when cross-compiling on 64-bit host
    if(LINUX_32BIT)
        target_compile_options(cloud_redirect PRIVATE -m32)
        target_link_options(cloud_redirect PRIVATE -m32)
        target_link_libraries(cloud_redirect PRIVATE atomic)
        # Fix multilib include path for i686 libstdc++ headers on Fedora
        # Try to detect GCC version for correct path
        execute_process(
            COMMAND ${CMAKE_CXX_COMPILER} -dumpversion
            OUTPUT_VARIABLE GCC_VERSION
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        string(REGEX MATCH "^[0-9]+" GCC_MAJOR "${GCC_VERSION}")
        target_include_directories(cloud_redirect SYSTEM BEFORE PRIVATE
            /usr/include/c++/${GCC_MAJOR}/i686-redhat-linux
        )
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
        # Cross-compiling 32-bit on 64-bit: find the multilib atomic
        find_library(LIBATOMIC_32 NAMES atomic
            PATHS /usr/lib/gcc/x86_64-redhat-linux/16/32
                  /usr/lib/gcc/x86_64-redhat-linux/14/32
                  /usr/lib/gcc/x86_64-linux-gnu/13/32
                  /usr/lib/gcc/x86_64-linux-gnu/12/32
                  /usr/lib/gcc/x86_64-linux-gnu/11/32
                  /usr/lib/i386-linux-gnu
                  /usr/lib32
            NO_DEFAULT_PATH)
        if(LIBATOMIC_32)
            target_link_libraries(cloud_redirect PRIVATE ${LIBATOMIC_32})
        else()
            target_link_libraries(cloud_redirect PRIVATE atomic)
        endif()
    endif()
    # Strip in release
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        target_link_options(cloud_redirect PRIVATE -s)
    endif()
endif()

# ── Tests ───────────────────────────────────────────────────────────────

enable_testing()

if(EXISTS ${CMAKE_SOURCE_DIR}/tests/autocloud_native_tests.cpp)
    if(WIN32)
        add_executable(autocloud_native_tests
            tests/autocloud_native_tests.cpp
            src/common/local_storage.cpp
            src/common/local_metadata_store.cpp
        src/common/autocloud_scan.cpp
        src/common/vdf.cpp
            src/platform/win/log.cpp
            src/platform/win/platform_win.cpp
        )
        target_include_directories(autocloud_native_tests PRIVATE src/common src/platform/win)
        target_compile_definitions(autocloud_native_tests PRIVATE CLOUDREDIRECT_TESTING)
        target_link_libraries(autocloud_native_tests PRIVATE Shlwapi Advapi32 Shell32 Ole32)
        add_test(NAME autocloud_native_tests COMMAND autocloud_native_tests)

        add_executable(legacy_metadata_cleanup_tests
            tests/legacy_metadata_cleanup_tests.cpp
            src/common/legacy_metadata_cleanup.cpp
            src/platform/win/log.cpp
            src/platform/win/platform_win.cpp
        )
        target_include_directories(legacy_metadata_cleanup_tests PRIVATE src/common src/platform/win)
        target_compile_definitions(legacy_metadata_cleanup_tests PRIVATE CLOUDREDIRECT_TESTING)
        target_link_libraries(legacy_metadata_cleanup_tests PRIVATE Shlwapi Advapi32 Shell32 Ole32)
        add_test(NAME legacy_metadata_cleanup_tests COMMAND legacy_metadata_cleanup_tests)
    endif()

    add_executable(remotecache_repair_tests
        tests/remotecache_repair_tests.cpp
        src/common/remotecache_repair.cpp
        src/common/vdf.cpp
    )
    target_include_directories(remotecache_repair_tests PRIVATE src/common)
    add_test(NAME remotecache_repair_tests COMMAND remotecache_repair_tests)

    add_executable(bkv_stats_tests
        tests/bkv_stats_tests.cpp
        src/common/bkv_stats.cpp
    )
    target_include_directories(bkv_stats_tests PRIVATE src/common)
    add_test(NAME bkv_stats_tests COMMAND bkv_stats_tests)

    add_executable(rpc_handlers_tests
        tests/rpc_handlers_tests.cpp
        src/common/protobuf.cpp
    )
    target_include_directories(rpc_handlers_tests PRIVATE src/common)
    add_test(NAME rpc_handlers_tests COMMAND rpc_handlers_tests)

    add_executable(cloud_staging_tests
        tests/cloud_staging_tests.cpp
        src/common/cloud_staging.cpp
    )
    target_include_directories(cloud_staging_tests PRIVATE src/common)
    if(WIN32)
        target_include_directories(cloud_staging_tests PRIVATE src/platform/win)
    else()
        target_include_directories(cloud_staging_tests PRIVATE src/platform/linux)
    endif()
    add_test(NAME cloud_staging_tests COMMAND cloud_staging_tests)

    add_executable(cloud_storage_staging_tests
        tests/cloud_storage_staging_tests.cpp
        src/common/cloud_work_queue.cpp
        src/common/cloud_storage.cpp
        src/common/local_storage.cpp
        src/common/local_metadata_store.cpp
        src/common/legacy_metadata_cleanup.cpp
        src/common/manifest_store.cpp
        src/common/token_store.cpp
        src/common/cloud_staging.cpp
        src/common/pending_ops_journal.cpp
        src/common/json.cpp
        src/common/cloud_provider_base.cpp
        src/common/autocloud_scan.cpp
        src/common/vdf.cpp
        src/common/miniz.c
        src/common/miniz_tdef.c
        src/common/miniz_tinfl.c
        src/common/miniz_zip.c
        src/providers/google_drive.cpp
        src/providers/onedrive.cpp
        src/providers/local_disk_provider.cpp
    )
    target_include_directories(cloud_storage_staging_tests PRIVATE src/common src/providers src/testutil)
    if(WIN32)
        target_include_directories(cloud_storage_staging_tests PRIVATE src/platform/win)
        target_sources(cloud_storage_staging_tests PRIVATE
            src/platform/win/log.cpp
            src/platform/win/platform_win.cpp
            src/platform/win/http_util.cpp
            src/platform/win/http_transport_win.cpp
            src/platform/win/token_store_win.cpp
        )
        target_link_libraries(cloud_storage_staging_tests PRIVATE Shlwapi Advapi32 ws2_32 winhttp Crypt32 Shell32 Ole32)
    else()
        target_include_directories(cloud_storage_staging_tests PRIVATE src/platform/linux)
        target_sources(cloud_storage_staging_tests PRIVATE
            src/platform/linux/log.cpp
            src/platform/linux/platform_linux.cpp
            src/platform/linux/http_util.cpp
            src/platform/linux/http_transport_linux.cpp
            src/platform/linux/token_store_linux.cpp
        )
        target_link_libraries(cloud_storage_staging_tests PRIVATE pthread dl)
    endif()
    add_test(NAME cloud_storage_staging_tests COMMAND cloud_storage_staging_tests)

    add_executable(pending_ops_journal_tests
        tests/pending_ops_journal_tests.cpp
        src/common/pending_ops_journal.cpp
        src/common/json.cpp
    )
    target_include_directories(pending_ops_journal_tests PRIVATE src/common)
    if(WIN32)
        target_include_directories(pending_ops_journal_tests PRIVATE src/platform/win)
        target_sources(pending_ops_journal_tests PRIVATE src/platform/win/log.cpp src/platform/win/platform_win.cpp)
    else()
        target_include_directories(pending_ops_journal_tests PRIVATE src/platform/linux)
        target_sources(pending_ops_journal_tests PRIVATE src/platform/linux/log.cpp src/platform/linux/platform_linux.cpp)
    endif()
    add_test(NAME pending_ops_journal_tests COMMAND pending_ops_journal_tests)

    add_executable(json_tests
        tests/json_tests.cpp
        src/common/json.cpp
    )
    target_include_directories(json_tests PRIVATE src/common)
    add_test(NAME json_tests COMMAND json_tests)

    add_executable(protobuf_tests
        tests/protobuf_tests.cpp
        src/common/protobuf.cpp
    )
    target_include_directories(protobuf_tests PRIVATE src/common)
    add_test(NAME protobuf_tests COMMAND protobuf_tests)

    add_executable(vdf_tests
        tests/vdf_tests.cpp
        src/common/vdf.cpp
    )
    target_include_directories(vdf_tests PRIVATE src/common)
    add_test(NAME vdf_tests COMMAND vdf_tests)
endif()

# ── UI (Windows only) ───────────────────────────────────────────────────

if(WIN32)
    add_custom_target(ui ALL
        COMMAND dotnet publish -c Release -r win-x64 --self-contained false -o bin/publish
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/ui
        COMMENT "Publishing CloudRedirect UI"
        DEPENDS cloud_redirect
    )
endif()

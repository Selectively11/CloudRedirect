cmake_minimum_required(VERSION 3.20)
project(CloudRedirect LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ── Read version from Version.props ─────────────────────────────────────
file(READ "${CMAKE_SOURCE_DIR}/Version.props" VERSION_PROPS_CONTENT)
string(REGEX MATCH "<ReleaseVersion>([^<]+)</ReleaseVersion>" _ "${VERSION_PROPS_CONTENT}")
set(CR_RELEASE_VERSION "${CMAKE_MATCH_1}")
if(NOT DEFINED CR_PRERELEASE)
    string(REGEX MATCH "<ReleasePrerelease>([^<]*)</ReleasePrerelease>" _ "${VERSION_PROPS_CONTENT}")
    set(CR_PRERELEASE "${CMAKE_MATCH_1}")
endif()

if(NOT CR_RELEASE_VERSION)
    set(CR_RELEASE_VERSION "0.0.0")
endif()
set(CR_RELEASE_VERSION "${CR_RELEASE_VERSION}${CR_PRERELEASE}")

# ── Generate version string with git SHA ────────────────────────────────
# Release builds may pass -DCR_GIT_SHA to pin the build id (e.g. when the build
# runs in a sandbox whose worktree shows spurious eol-only diffs).
if(NOT DEFINED CR_GIT_SHA)
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
else()
    set(GIT_SHA "${CR_GIT_SHA}")
endif()

set(CR_SO_VERSION "${CR_RELEASE_VERSION}+${GIT_SHA}")

# ── Common sources (platform-agnostic) ──────────────────────────────────

set(COMMON_SOURCES
    src/common/protobuf.cpp
    src/common/json.cpp
    src/common/coop_yield.cpp
    src/common/vdf.cpp
    src/common/remotecache_repair.cpp
    src/common/manifest_store.cpp
    src/common/app_state.cpp
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
    src/common/steam_kv_injector.cpp
    src/common/parental_bypass.cpp
    src/common/metadata_sync.cpp
    src/common/stats_store.cpp
    src/common/stats_handlers.cpp
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
        src/platform/win/cr_api.cpp
        src/platform/win/cloud_intercept.cpp
        src/platform/win/sig_scanner.cpp
        src/platform/win/sc_resolver.cpp
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
        src/platform/linux/stats_hooks.cpp
        src/platform/linux/gamesplayed_hook.cpp
        src/platform/linux/live_playtime.cpp
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

    # Standalone Steam Cloud file manager for a single AppID (default 760).
    # Self-contained: resolves the steam_api64.dll flat exports at runtime, so it
    # needs no Steamworks SDK headers/libs. steam_api64.dll must sit next to it.
    add_executable(cloud760_tool
        src/platform/win/cloud760_tool.cpp
    )
else()
    target_include_directories(cloud_redirect PRIVATE src/platform/linux)
    target_link_libraries(cloud_redirect PRIVATE dl pthread)
    # Steam on Linux is 32-bit; use LINUX_32BIT=ON when cross-compiling on 64-bit host
    # Match Steam's pre-C++11 ABI
    target_compile_definitions(cloud_redirect PRIVATE _GLIBCXX_USE_CXX11_ABI=0 _FILE_OFFSET_BITS=64)
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
    add_compile_definitions(CR_RELEASE_VERSION="${CR_RELEASE_VERSION}")
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
        src/common/app_state.cpp
        src/common/coop_yield.cpp
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

    add_executable(stats_store_tests
        tests/stats_store_tests.cpp
        src/common/stats_store.cpp
        src/common/json.cpp
        src/common/metadata_sync.cpp
        src/common/vdf.cpp
    )
    target_include_directories(stats_store_tests PRIVATE src/common)
    if(WIN32)
        target_include_directories(stats_store_tests PRIVATE src/platform/win)
        target_sources(stats_store_tests PRIVATE
            src/platform/win/log.cpp
            src/platform/win/platform_win.cpp
        )
        target_link_libraries(stats_store_tests PRIVATE Shlwapi Advapi32 Crypt32 Shell32 Ole32)
    else()
        target_include_directories(stats_store_tests PRIVATE src/platform/linux)
        target_sources(stats_store_tests PRIVATE
            src/platform/linux/log.cpp
            src/platform/linux/platform_linux.cpp
            src/platform/linux/file_util.cpp
        )
        target_link_libraries(stats_store_tests PRIVATE pthread dl)
    endif()
    add_test(NAME stats_store_tests COMMAND stats_store_tests)
endif()

# ── UI (Windows only) ───────────────────────────────────────────────────

if(WIN32)
    # The csproj expects the DLL/CLI at ../build/Release/; copy from the actual
    # build output dir so out-of-tree builds (build-win) work correctly.
    add_custom_target(ui ALL
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_SOURCE_DIR}/build/Release"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:cloud_redirect>"
            "${CMAKE_SOURCE_DIR}/build/Release/cloud_redirect.dll"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:cloud_redirect_cli>"
            "${CMAKE_SOURCE_DIR}/build/Release/cloud_redirect_cli.exe"
        COMMAND dotnet publish -c Release -r win-x64 --self-contained false -o bin/publish
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/ui
        COMMENT "Publishing CloudRedirect UI"
        DEPENDS cloud_redirect cloud_redirect_cli
    )
endif()

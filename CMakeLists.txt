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
    src/local_disk_provider.cpp
    src/cloud_provider_base.cpp
    src/google_drive.cpp
    src/onedrive.cpp
    src/json.cpp
    src/miniz.c
    src/miniz_tdef.c
    src/miniz_tinfl.c
    src/miniz_zip.c
)

target_include_directories(cloud_redirect PRIVATE src)
target_compile_definitions(cloud_redirect PRIVATE MINIZ_NO_STDIO MINIZ_NO_ARCHIVE_WRITING_APIS)
target_link_libraries(cloud_redirect PRIVATE Shlwapi Advapi32 ws2_32 winhttp Crypt32)

# UI (builds DLL first, then publishes the WPF app with the DLL embedded)
add_custom_target(ui ALL
    COMMAND dotnet publish -c Release -r win-x64 --self-contained false -o bin/publish
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/ui
    COMMENT "Publishing CloudRedirect UI"
    DEPENDS cloud_redirect
)


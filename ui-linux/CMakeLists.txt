cmake_minimum_required(VERSION 3.20)
project(CloudRedirectUI VERSION 2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

# ── Read version from Version.props ─────────────────────────────────────
if(NOT CR_RELEASE_VERSION)
    # Check parent dir first (normal layout), then source dir (flatpak sandbox)
    foreach(_vp "${CMAKE_CURRENT_SOURCE_DIR}/../Version.props" "${CMAKE_CURRENT_SOURCE_DIR}/Version.props")
        if(EXISTS "${_vp}")
            file(READ "${_vp}" VERSION_PROPS_CONTENT)
            string(REGEX MATCH "<ReleaseVersion>([^<]+)</ReleaseVersion>" _ "${VERSION_PROPS_CONTENT}")
            set(CR_RELEASE_VERSION "${CMAKE_MATCH_1}")
            break()
        endif()
    endforeach()
endif()

if(NOT CR_RELEASE_VERSION)
    set(CR_RELEASE_VERSION "0.0.0")
endif()

# ── Generate version string ─────────────────────────────────────────────
if(CR_VERSION_OVERRIDE)
    set(CR_VERSION "${CR_RELEASE_VERSION}+${CR_VERSION_OVERRIDE}")
else()
    execute_process(
        COMMAND git rev-parse --short=7 HEAD
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_SHA
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        RESULT_VARIABLE GIT_RESULT
    )
    if(GIT_RESULT EQUAL 0)
        set(CR_VERSION "${CR_RELEASE_VERSION}+${GIT_SHA}")
    else()
        set(CR_VERSION "${CR_RELEASE_VERSION}")
    endif()
endif()
message(STATUS "CloudRedirect UI version: ${CR_VERSION}")

find_package(Qt6 REQUIRED COMPONENTS Core Quick QuickControls2 DBus Network)
find_package(OpenSSL REQUIRED)
find_library(ARGON2_LIB argon2 REQUIRED)

qt_add_executable(cloud-redirect-ui
    src/main.cpp
    src/backend.cpp
    src/deployer.cpp
    src/oauthservice.cpp
    src/proton_auth.cpp
)

qt_add_resources(cloud-redirect-ui "appicon"
    PREFIX /icons
    FILES src/cloudredirect.png
)

qt_add_qml_module(cloud-redirect-ui
    URI CloudRedirect
    VERSION 1.0
    RESOURCE_PREFIX /
    QML_FILES
        qml/Main.qml
        qml/pages/SetupPage.qml
        qml/pages/DashboardPage.qml
        qml/pages/AppsPage.qml
        qml/pages/BackupsPage.qml
        qml/pages/CloudProviderPage.qml
)

target_include_directories(cloud-redirect-ui PRIVATE src)

target_compile_definitions(cloud-redirect-ui PRIVATE
    CR_VERSION="${CR_VERSION}"
)

target_link_libraries(cloud-redirect-ui PRIVATE
    Qt6::Quick
    Qt6::QuickControls2
    Qt6::DBus
    Qt6::Network
    OpenSSL::Crypto
    ${ARGON2_LIB}
    crypt
)

install(TARGETS cloud-redirect-ui DESTINATION bin)
install(FILES dbus/org.cloudredirect.service.xml DESTINATION share/dbus-1/interfaces)

#pragma once
#include <cstdlib>
#include <string>
#include <pwd.h>
#include <unistd.h>


inline bool InFlatpak() {
    static const bool cached = (access("/.flatpak-info", F_OK) == 0);
    return cached;
}

inline std::string XdgHome() {
    const char* home = getenv("HOME");
    if (home && home[0]) return home;
    struct passwd* pw = getpwuid(getuid());
    if (pw && pw->pw_dir) return pw->pw_dir;
    return "/tmp";
}

inline std::string XdgConfigHome() {
    if (!InFlatpak()) {
        const char* xdg = getenv("XDG_CONFIG_HOME");
        if (xdg && xdg[0] && xdg[0] == '/') return xdg;
    }
    return XdgHome() + "/.config";
}

inline std::string XdgDataHome() {
    if (!InFlatpak()) {
        const char* xdg = getenv("XDG_DATA_HOME");
        if (xdg && xdg[0] && xdg[0] == '/') return xdg;
    }
    return XdgHome() + "/.local/share";
}

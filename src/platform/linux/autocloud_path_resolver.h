#pragma once
// Linux path resolution for AutoCloud (Proton and native).
// For Proton games (aka almost all games) we map Windows root tokens to paths
// inside the Proton prefix. This is what Steam normally does.

#ifndef _WIN32

#include <string>

namespace AutoCloudPathResolver {

// For native Linux games, map Windows root tokens to XDG/Linux equivalents.
// This handles games that have AutoCloud rules with Windows roots but
// also have Linux platform support (platforms mask includes bit 8).
inline std::string WindowsRootToLinux(const std::string& windowsRoot) {
    std::string lower;
    for (char c : windowsRoot) lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (lower == "winappdatalocallow") return "LinuxXdgDataHome";
    if (lower == "winappdatalocal")    return "LinuxXdgDataHome";
    if (lower == "winappdataroaming")  return "LinuxXdgConfigHome";
    if (lower == "winmydocuments")     return "LinuxHome";
    if (lower == "winsavedgames")      return "LinuxXdgDataHome";
    return {};
}

// For Proton games, map Windows root tokens to paths inside the Proton prefix.
// Returns the path suffix to append to the compatdata prefix
// (e.g., "/pfx/drive_c/users/steamuser/AppData/LocalLow").
// Returns empty string if the root doesn't need Proton mapping.
inline std::string WindowsRootToProton(const std::string& windowsRoot) {
    std::string lower;
    for (char c : windowsRoot) lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (lower == "winappdatalocallow") return "/pfx/drive_c/users/steamuser/AppData/LocalLow";
    if (lower == "winappdatalocal")    return "/pfx/drive_c/users/steamuser/Local Settings/Application Data";
    if (lower == "winappdataroaming")  return "/pfx/drive_c/users/steamuser/Application Data";
    if (lower == "winmydocuments")     return "/pfx/drive_c/users/steamuser/My Documents";
    if (lower == "winsavedgames")      return "/pfx/drive_c/users/steamuser/Saved Games";
    if (lower == "wincommonappdata")   return "/pfx/drive_c/ProgramData";
    if (lower == "winuserprofile")     return "/pfx/drive_c/users/steamuser";
    return {};
}

} // namespace AutoCloudPathResolver

#endif // !_WIN32

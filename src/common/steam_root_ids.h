#pragma once
// Mapping between Steam's ERemoteStorageFileRoot enum, bare root names
// used by AutoCloud rules, and wire-format tokens Steam emits in RPCs.
//
// Windows IDs confirmed via IDA (steamclient64.dll) and cross-validated
// against live remotecache.vdf entries. Linux IDs from steamclient.so
// (IDA). Linux prepends Invalid=0 and Default=1, shifting all IDs by +1.

#include <cstdint>

namespace SteamRootIds {

struct Entry {
    const char* bareName;  // e.g. "WinAppDataLocal" (AutoCloud rule form)
    const char* token;     // e.g. "%WinAppDataLocal%" (wire form Steam emits)
    uint32_t    rootId;    // ERemoteStorageFileRoot enum value (platform-specific)
};

// NOTE: rootId values here are used for tagging files in our cache
// and for remotecache.vdf repair entries. AutoCloud rule matching
// uses bareName strings, not numeric IDs.

#ifdef _WIN32
// Windows IDs from steamclient64.dll:
//   1=GameInstall, 2=WinMyDocuments, 3=WinAppDataLocal,
//   4=WinAppDataRoaming, 5=SteamUserBaseStorage, 6=MacHome,
//   7=MacAppSupport, 8=MacDocuments, 9=WinSavedGames,
//   10=WinProgramData, 11=SteamCloudDocuments, 12=WinAppDataLocalLow,
//   13=MacCaches, 14=LinuxHome, 15=LinuxXdgDataHome,
//   16=LinuxXdgConfigHome, 17=AndroidSteamPackageRoot,
//   18=WindowsHome, 19=AndroidExternalData, 20=AndroidInternalData.
inline constexpr Entry kEntries[] = {
    {"GameInstall",           "%GameInstall%",           1},
    {"WinMyDocuments",        "%WinMyDocuments%",        2},
    {"WinAppDataLocal",       "%WinAppDataLocal%",       3},
    {"WinAppDataRoaming",     "%WinAppDataRoaming%",     4},
    {"SteamUserBaseStorage",  "%SteamUserBaseStorage%",   5},
    {"WinSavedGames",         "%WinSavedGames%",         9},
    {"WinProgramData",        "%WinProgramData%",        10},
    {"SteamCloudDocuments",   "%SteamCloudDocuments%",   11},
    {"WinAppDataLocalLow",    "%WinAppDataLocalLow%",   12},
    {"WindowsHome",           "%WindowsHome%",           18},
    {"LinuxHome",             "%LinuxHome%",             14},
    {"LinuxXdgDataHome",      "%LinuxXdgDataHome%",     15},
    {"LinuxXdgConfigHome",    "%LinuxXdgConfigHome%",   16},
};
#else
// Linux IDs from steamclient.so (+1 vs Windows):
//   0=Invalid, 1=Default, 2=GameInstall, 3=WinMyDocuments,
//   4=WinAppDataLocal, 5=WinAppDataRoaming, 6=SteamUserBaseStorage,
//   7=MacHome, 8=MacAppSupport, 9=MacDocuments, 10=WinSavedGames,
//   11=WinProgramData, 12=SteamCloudDocuments, 13=WinAppDataLocalLow,
//   14=MacCaches, 15=LinuxHome, 16=LinuxXdgDataHome,
//   17=LinuxXdgConfigHome, 18=AndroidSteamPackageRoot,
//   19=WindowsHome, 20=AndroidExternalData, 21=AndroidInternalData.
inline constexpr Entry kEntries[] = {
    {"GameInstall",           "%GameInstall%",           2},
    {"WinMyDocuments",        "%WinMyDocuments%",        3},
    {"WinAppDataLocal",       "%WinAppDataLocal%",       4},
    {"WinAppDataRoaming",     "%WinAppDataRoaming%",     5},
    {"SteamUserBaseStorage",  "%SteamUserBaseStorage%",   6},
    {"WinSavedGames",         "%WinSavedGames%",         10},
    {"WinProgramData",        "%WinProgramData%",        11},
    {"SteamCloudDocuments",   "%SteamCloudDocuments%",   12},
    {"WinAppDataLocalLow",    "%WinAppDataLocalLow%",   13},
    {"WindowsHome",           "%WindowsHome%",           19},
    {"LinuxHome",             "%LinuxHome%",             15},
    {"LinuxXdgDataHome",      "%LinuxXdgDataHome%",     16},
    {"LinuxXdgConfigHome",    "%LinuxXdgConfigHome%",   17},
};
#endif

} // namespace SteamRootIds

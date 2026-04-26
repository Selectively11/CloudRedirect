#pragma once
// Canonical mapping between Steam's ERemoteStorageFileRoot enum, the bare root
// directory name that AutoCloud rules use (e.g. "WinAppDataLocal"), and the
// wire-format token that Steam emits in RPC responses (e.g. "%WinAppDataLocal%").
//
// Source of truth for this table: the Steam client's RemoteStorage root table
// (confirmed via IDA at 0x139331de0 and cross-checked against
// ClientJobRemoteStorageSync.cpp). Any time Steam adds or renumbers a root,
// update this header and both downstream consumers pick it up automatically.
//
// Consumers:
//   - local_storage.cpp: AutoCloud path resolution keys off `bareName`.
//   - remotecache_repair.cpp: TokenToRootId() keys off `token` for the repair
//     helper that pre-seeds remotecache.vdf.

#include <cstdint>

namespace SteamRootIds {

struct Entry {
    const char* bareName;  // e.g. "WinAppDataLocal" (AutoCloud rule form)
    const char* token;     // e.g. "%WinAppDataLocal%" (wire form Steam emits)
    uint32_t    rootId;    // ERemoteStorageFileRoot enum value
};

// IDs confirmed via IDA:
//   0=Default, 1=GameInstall, 2=WinMyDocuments, 3=WinAppDataLocal,
//   4=WinAppDataRoaming, 6=WinSavedGames, 12=WinAppDataLocalLow,
//   16=LinuxXdgConfigHome.
//
// WinSavedGames is 6 (not 5) because Steam's enum skips 5 (reserved / deprecated
// MacOS slot). Do not compact the numeric values -- parity with Steam matters.
inline constexpr Entry kEntries[] = {
    {"GameInstall",        "%GameInstall%",        1},
    {"WinMyDocuments",     "%WinMyDocuments%",     2},
    {"WinAppDataLocal",    "%WinAppDataLocal%",    3},
    {"WinAppDataRoaming",  "%WinAppDataRoaming%",  4},
    {"WinSavedGames",      "%WinSavedGames%",      6},
    {"WinAppDataLocalLow", "%WinAppDataLocalLow%", 12},
    {"LinuxXdgConfigHome", "%LinuxXdgConfigHome%", 16},
};

} // namespace SteamRootIds

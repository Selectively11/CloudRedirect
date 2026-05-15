#pragma once
#include <string>
#include <vector>

// Sweep leftover Playtime.bin / UserGameStats.bin from pre-canonicalization builds.

namespace LegacyMetadataCleanup {

struct SweepStats {
    int filesRemoved = 0;
    int dirsRemoved = 0;
    int errors = 0;
};

// steamPath must end with backslash. Removes legacy bins + stale .cloudredirect/ dirs
// from Steam\userdata\{acct}\{app}\remote\.
SweepStats PruneSteamUserdata(const std::string& steamPath);

// Removes legacy bins from local blob cache only when the canonical sibling exists
// (never deletes the only copy).
SweepStats PruneLocalBlobCache(const std::string& localRoot);

// Removes legacy *.dat metadata once the .cloudredirect-suffixed canonical exists.
SweepStats PruneLocalLegacyAppMetadata(const std::string& localRoot);

// Pure function: returns cloud paths to legacy bins from a complete listing.
std::vector<std::string> ClassifyLegacyCloudBlobsToDelete(
    const std::vector<std::string>& cloudBlobRawPaths);

// Removes .cloudredirect\{Playtime,UserGameStats}.bin from AutoCloud-scanned user roots.
// Reparse points at .cloudredirect are unlinked, never descended.
SweepStats PruneAutoCloudPollutionRoots(const std::vector<std::string>& roots);

} // namespace LegacyMetadataCleanup

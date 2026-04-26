#pragma once
#include <string>
#include <vector>

// Legacy metadata cleanup. Pre-canonicalization builds wrote
// Playtime.bin / UserGameStats.bin to legacy paths under Steam userdata,
// our local blob cache, the cloud blobs/ folder, and AutoCloud-scanned
// user roots. Helpers here sweep those leftovers; all are idempotent.

namespace LegacyMetadataCleanup {

struct SweepStats {
    int filesRemoved = 0;
    int dirsRemoved = 0;
    int errors = 0;
};

// Layer 1: Sweep `Steam\userdata\{acct}\{app}\remote\`. Unconditionally
// removes top-level Playtime.bin / UserGameStats.bin and the entire
// .cloudredirect\ subdirectory (wrong location for current DLL).
// `steamPath` must end with a backslash. Missing userdata\ is a no-op.
SweepStats PruneSteamUserdata(const std::string& steamPath);

// Layer 2: Sweep `{localRoot}storage\{acct}\{app}\`. Removes top-level
// legacy bins only when the canonical .cloudredirect\{same} sibling
// exists (never delete the only copy). `localRoot` ends with a backslash.
SweepStats PruneLocalBlobCache(const std::string& localRoot);

// Layer 3 (pure): from raw cloud listing entries, return top-level
// legacy bins. Caller must pass a verified-complete listing.
std::vector<std::string> ClassifyLegacyCloudBlobsToDelete(
    const std::vector<std::string>& cloudBlobRawPaths);

// Layer 4: Sweep `<root>\.cloudredirect\{Playtime,UserGameStats}.bin` from
// AutoCloud-scanned user roots (LocalLow, LocalAppData, RoamingAppData,
// Documents, Saved Games). Caller resolves roots with AutoCloud's exact
// ladder; string mismatch silently misses pollution. Removes the bins and
// the .cloudredirect dir if empty; foreign content preserved. Reparse
// points at .cloudredirect are unlinked, never descended. Unconditional
// delete (Layers 1-2's "never delete the only copy" rule does not apply).
SweepStats PruneAutoCloudPollutionRoots(const std::vector<std::string>& roots);

} // namespace LegacyMetadataCleanup

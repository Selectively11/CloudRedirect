#pragma once
// Cloud-storage paths for CloudRedirect's internal metadata blobs.
// Split out of cloud_intercept.h so cloud_storage and other low-level
// modules can consume just the path constants without pulling in the
// full intercept-layer interface (CNetPacket, hook installers, etc.).

#include <cstdint>
#include <string>
#include <string_view>

namespace CloudIntercept {

// Account-scoped storage for CR's own metadata (playtime, stats). Lives under
// a synthetic appId=0 in the cloud provider so Steam's per-app cloud listings
// never see these blobs and the per-app AutoCloud rules can never resolve
// them onto disk under user-visible roots like %LOCALAPPDATA%\.cloudredirect\.
//
// Why appId=0: Steam's RPC dispatch in cloud_intercept.cpp guards against
// appId==0 (lines ~1218, ~1327, ~3403), so Steam never inputs 0 as an appId
// to us. Using it as a CR-internal sentinel for "account-scope, not any
// specific app" is collision-free.
//
// Filenames are subdir-keyed by the real appId so per-app blobs remain
// separable: e.g. "Playtime/1583520.bin", "UserGameStats/1583520.bin".
inline constexpr uint32_t kAccountScopeAppId = 0;

// Legacy paths used by builds prior to the account-scope migration. These
// stored Playtime/UserGameStats under each app's per-app cloud namespace,
// which caused Steam to download them onto disk under the AutoCloud rules
// of every app (e.g. %LOCALAPPDATA%\.cloudredirect\Playtime.bin from any
// app whose AutoCloud rule had root=WinAppDataLocal). That on-disk pollution
// was then swept up by every other app's AutoCloud scan, inflating per-app
// file counts past maxnumfiles and triggering "is over quota. Removing from
// cloud" evictions of real save files. See the migration pass in
// cloud_storage.cpp for the cleanup. These constants are still referenced
// by the cleanup code; do NOT use them for new writes.
inline constexpr const char* kPlaytimeMetadataPath = ".cloudredirect/Playtime.bin";
inline constexpr const char* kStatsMetadataPath    = ".cloudredirect/UserGameStats.bin";

// Even-older paths from the very first builds, before metadata was even
// namespaced under .cloudredirect/. Recognized by the legacy-metadata cleanup
// pass for users who skipped multiple versions.
inline constexpr const char* kLegacyPlaytimeMetadataPath = "Playtime.bin";
inline constexpr const char* kLegacyStatsMetadataPath    = "UserGameStats.bin";

// ============================================================================
// Per-app metadata filenames (local storage + cloud sync)
// Use .cloudredirect extension to avoid collision with game save filenames.
// ============================================================================
inline constexpr const char* kManifestFilename     = "manifest.cloudredirect";
inline constexpr const char* kCNFilename           = "cn.cloudredirect";
inline constexpr const char* kFileTokensFilename   = "file_tokens.cloudredirect";
inline constexpr const char* kRootTokenFilename    = "root_token.cloudredirect";
inline constexpr const char* kDeletedFilename      = "deleted.cloudredirect";

// Legacy filenames (for migration - read old, write new)
inline constexpr const char* kLegacyManifestFilename   = "manifest.dat";
inline constexpr const char* kLegacyCNFilename         = "cn.dat";
inline constexpr const char* kLegacyFileTokensFilename = "file_tokens.dat";
inline constexpr const char* kLegacyRootTokenFilename  = "root_token.dat";
inline constexpr const char* kLegacyDeletedFilename    = "deleted.dat";

// Account-scope filename for an app's playtime blob.
inline std::string AccountPlaytimeFilename(uint32_t appId) {
    return "Playtime/" + std::to_string(appId) + ".bin";
}

// Account-scope filename for an app's UserGameStats blob.
inline std::string AccountStatsFilename(uint32_t appId) {
    return "UserGameStats/" + std::to_string(appId) + ".bin";
}

// True if filename is internal metadata.
inline bool IsInternalMetadataFile(std::string_view cleanName) {
    return cleanName == kPlaytimeMetadataPath ||
           cleanName == kStatsMetadataPath ||
           cleanName == kLegacyPlaytimeMetadataPath ||
           cleanName == kLegacyStatsMetadataPath ||
           cleanName == kManifestFilename ||
           cleanName == kLegacyManifestFilename ||
           cleanName == kCNFilename ||
           cleanName == kLegacyCNFilename ||
           cleanName == kFileTokensFilename ||
           cleanName == kLegacyFileTokensFilename ||
           cleanName == kRootTokenFilename ||
           cleanName == kLegacyRootTokenFilename ||
            cleanName == kDeletedFilename ||
            cleanName == kLegacyDeletedFilename;
}

// Reserved names: metadata files, `.cloudredirect` segments/suffixes.
inline bool IsReservedBlobFilename(std::string_view cleanName) {
    if (IsInternalMetadataFile(cleanName)) return true;

    constexpr std::string_view kReservedSegment = ".cloudredirect";
    size_t segmentStart = 0;
    while (segmentStart < cleanName.size()) {
        size_t segmentEnd = cleanName.find_first_of("/\\", segmentStart);
        std::string_view segment = cleanName.substr(
            segmentStart,
            segmentEnd == std::string_view::npos
                ? cleanName.size() - segmentStart
                : segmentEnd - segmentStart);

        if (segment == kReservedSegment) return true;
        if (segmentEnd == std::string_view::npos) {
            return segment.size() > kReservedSegment.size() &&
                   segment.substr(segment.size() - kReservedSegment.size()) == kReservedSegment;
        }
        segmentStart = segmentEnd + 1;
    }

    return false;
}

// Composite key for per-(account, app) maps. High 32 bits = accountId,
// low 32 bits = appId.
inline uint64_t MakeAppAccountKey(uint32_t accountId, uint32_t appId) {
    return (static_cast<uint64_t>(accountId) << 32) | appId;
}

} // namespace CloudIntercept

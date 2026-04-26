#pragma once
#include "common.h"
#include <functional>
#include <optional>
#include <unordered_map>
#include <unordered_set>

namespace LocalStorage {

struct FileEntry {
    std::string filename;
    std::string sourcePath;          // Real filesystem source for AutoCloud bootstrap only
    std::string rootToken;           // Cloud root token captured/resolved for this file
    std::vector<uint8_t> sha;     // 20-byte SHA1
    uint64_t timestamp = 0;
    uint64_t rawSize = 0;
    bool deleted = false;
    uint32_t rootId = 0;          // 0=remote/, 12=WinAppDataLocalLow, etc.
};

void Init(const std::string& baseRoot);
void InitApp(uint32_t accountId, uint32_t appId);
std::vector<FileEntry> GetFileList(uint32_t accountId, uint32_t appId);
std::optional<FileEntry> GetFileEntry(uint32_t accountId, uint32_t appId, const std::string& filename);
std::vector<uint8_t> ReadFile(uint32_t accountId, uint32_t appId, const std::string& filename);
bool WriteFile(uint32_t accountId, uint32_t appId, const std::string& filename, const uint8_t* data, size_t len);
bool WriteFileNoIncrement(uint32_t accountId, uint32_t appId, const std::string& filename, const uint8_t* data, size_t len);
bool DeleteFile(uint32_t accountId, uint32_t appId, const std::string& filename);
// Atomic compare-and-restore under g_mutex. Returns false if the file was
// modified concurrently or the IO failed.
bool RestoreFileIfUnchanged(uint32_t accountId, uint32_t appId,
                            const std::string& filename,
                            const std::vector<uint8_t>& expectedData,
                            const std::string& backupPath,
                            bool hadOriginal);
bool SetFileTimestamp(uint32_t accountId, uint32_t appId, const std::string& filename, uint64_t unixSeconds);

// Remove empty cache subdirectories upward from each startDir, bounded by
// the app root. Serialized under g_mutex so writers never observe a parent
// dir disappearing between create_directories() and AtomicWriteBinary().
void CleanupEmptyCacheDirs(uint32_t accountId, uint32_t appId,
                           std::vector<std::string> startDirs);
uint64_t GetChangeNumber(uint32_t accountId, uint32_t appId);
void SetChangeNumber(uint32_t accountId, uint32_t appId, uint64_t cn);
uint64_t IncrementChangeNumber(uint32_t accountId, uint32_t appId);
std::vector<uint8_t> SHA1(const uint8_t* data, size_t len);
std::string GetAppPath(uint32_t accountId, uint32_t appId);
// scanLimitHit: scan was truncated; callers must not commit an import nor
//   clear any canonical-token cache (a partial scan is not corruption).
// hasRootCollision: two rules resolved to the same cloud path under different
//   roots; `files` is cleared and the import must abort.
struct AutoCloudScanResult {
    std::vector<FileEntry> files;
    bool scanLimitHit = false;
    bool hasRootCollision = false;
};

AutoCloudScanResult GetAutoCloudFileList(const std::string& steamPath,
                                         uint32_t accountId, uint32_t appId);
// Returns true on successful disk persist; callers (notably the cloud sync
// rollback path) use this to detect silent persist failures.
bool SaveRootTokens(uint32_t accountId, uint32_t appId, const std::unordered_set<std::string>& tokens);
std::unordered_set<std::string> LoadRootTokens(uint32_t accountId, uint32_t appId);

// Per-file token mapping: which root token each file was uploaded under.
bool SaveFileTokens(uint32_t accountId, uint32_t appId,
                    const std::unordered_map<std::string, std::string>& fileTokens);
std::unordered_map<std::string, std::string> LoadFileTokens(uint32_t accountId, uint32_t appId);

// Tombstones block SyncFromCloud from resurrecting locally-deleted files
// when the cloud Remove hasn't drained. Cleared on successful cloud Remove
// or when StoreBlob re-creates the same filename. CN + createTimeUnix
// distinguish a same-machine poisoned-delete from a real cross-machine
// re-write (cross-machine writes advance the blob's mtime).
//
// On-disk format (deleted.dat, one per app): "filename\tcn\tcreateTimeUnix\n".
// Legacy entries without the third field load with createTimeUnix=0 and
// fall back to CN-only comparison.
struct TombstoneInfo {
    uint64_t cn = 0;               // local CN at MarkDeleted time
    uint64_t createTimeUnix = 0;   // 0 = legacy/unknown
};

void MarkDeleted(uint32_t accountId, uint32_t appId, const std::string& filename,
                 uint64_t cnAtDelete);
void ClearDeleted(uint32_t accountId, uint32_t appId, const std::string& filename);

// Evict tombstones whose filenames are absent from keepSet AND were stamped
// strictly before listingCapturedAtUnix; this prevents a fresh tombstone
// stamped mid-sync from being evicted by a stale listing. createTimeUnix==0
// (legacy) bypasses the cutoff. Caller must ensure a complete listing.
void EvictTombstonesNotIn(uint32_t accountId, uint32_t appId,
                          const std::unordered_set<std::string>& keepSet,
                          uint64_t listingCapturedAtUnix);
bool IsDeleted(uint32_t accountId, uint32_t appId, const std::string& filename);
std::unordered_map<std::string, TombstoneInfo> LoadDeleted(uint32_t accountId,
                                                           uint32_t appId);

// Atomic load-rewrite-persist of deleted.dat under exclusive g_mutex. The
// rewrite callback runs while the mutex is held, so it must NOT re-enter
// any LocalStorage API. Collisions onto the same canonical key resolve to
// the newer CN (createTimeUnix breaks ties). Returns false on I/O failure;
// outMigratedCount counts keys whose rewritten form differed from the input.
bool MigrateDeletedKeys(uint32_t accountId, uint32_t appId,
                        const std::function<std::string(const std::string&)>& keyRewrite,
                        std::unordered_map<std::string, TombstoneInfo>& outFinalState,
                        size_t& outMigratedCount);

#ifdef CLOUDREDIRECT_TESTING
bool TestResolveAutoCloudRootOverride(const std::string& root, const std::string& path,
                                      const std::string& overrideRoot,
                                      const std::string& useInstead,
                                      const std::string& addPath,
                                      const std::string& find,
                                      const std::string& replace,
                                      std::string& outRoot,
                                      std::string& outResolvedPath);
bool TestIsSafeAutoCloudRelativePath(const std::string& path);
bool TestParseMinimalAutoCloudKVFixture();
std::vector<std::string> TestParseAutoCloudSiblings(const std::string& raw);
bool TestAutoCloudPlatformAndExcludeFilters();
#endif

} // namespace LocalStorage

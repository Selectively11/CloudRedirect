#include "manifest_store.h"
#include "cloud_storage.h"
#include "cloud_metadata_paths.h"
#include "file_util.h"
#include "json.h"
#include "log.h"

#include <filesystem>
#include <fstream>
#include <sstream>

using CloudIntercept::kManifestFilename;
using CloudIntercept::kLegacyManifestFilename;
using CloudIntercept::kDeletedFilename;
using CloudIntercept::kLegacyDeletedFilename;
using CloudIntercept::kRootTokenFilename;
using CloudIntercept::kLegacyRootTokenFilename;
using CloudIntercept::kFileTokensFilename;
using CloudIntercept::kLegacyFileTokensFilename;

namespace CloudStorage {
namespace {

// --- manifest-repair helpers ---
static Manifest RepairManifestWithRemoteBlobListing(
    const Manifest& cloudManifest,
    const Manifest& localManifest,
    const std::unordered_set<std::string>& remoteBlobNames,
    size_t* repairedCount) {
    Manifest repaired = cloudManifest;
    size_t added = 0;
    for (const auto& filename : remoteBlobNames) {
        if (CloudIntercept::IsReservedBlobFilename(filename)) continue;
        if (repaired.find(filename) != repaired.end()) continue;
        auto localIt = localManifest.find(filename);
        if (localIt == localManifest.end()) continue;
        repaired[filename] = localIt->second;
        ++added;
    }
    if (repairedCount) *repairedCount = added;
    return repaired;
}

static Manifest PruneManifestToRemoteBlobListing(
    const Manifest& manifest,
    const std::unordered_set<std::string>& remoteBlobNames,
    size_t* prunedCount) {
    Manifest pruned;
    size_t removed = 0;
    for (const auto& [filename, entry] : manifest) {
        if (CloudIntercept::IsReservedBlobFilename(filename)) continue;
        if (remoteBlobNames.find(filename) != remoteBlobNames.end()) {
            pruned[filename] = entry;
        } else { ++removed; }
    }
    if (prunedCount) *prunedCount = removed;
    return pruned;
}

// --- provider ref + local root, set by ManifestStore_Init ---
static ICloudProvider*                     g_manifestProvider = nullptr;
static std::string                        g_manifestLocalRoot;

// --- local helpers ---

static std::string ManifestLocalPath(uint32_t accountId, uint32_t appId) {
    return g_manifestLocalRoot + "storage" + std::string(kPathSepStr)
        + std::to_string(accountId) + std::string(kPathSepStr)
        + std::to_string(appId) + std::string(kPathSepStr) + kManifestFilename;
}

static std::string ShaToHex(const std::vector<uint8_t>& sha) {
    std::string hex;
    hex.reserve(sha.size() * 2);
    for (uint8_t b : sha) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", b);
        hex += buf;
    }
    return hex;
}

static std::vector<uint8_t> HexToSha(const std::string& hex) {
    constexpr size_t kMaxShaHexLength = 40;
    if (hex.size() > kMaxShaHexLength) {
        LOG("[ManifestStore] HexToSha: hex string too long (%zu bytes)", hex.size());
        return {};
    }
    std::vector<uint8_t> sha;
    sha.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        unsigned int b;
        if (sscanf(hex.c_str() + i, "%02x", &b) == 1) {
            sha.push_back((uint8_t)b);
        }
    }
    return sha;
}

static Manifest ParseManifestJson(const std::string& json) {
    Manifest result;
    if (json.empty()) return result;

    constexpr size_t MAX_MANIFEST_ENTRIES = 100000;

    auto root = Json::Parse(json);
    if (root.type != Json::Type::Object) {
        LOG("[ManifestStore] ParseManifestJson: invalid JSON (type=%d, len=%zu)",
            (int)root.type, json.size());
        return result;
    }

    for (const auto& [filename, entry] : root.objVal) {
        if (result.size() >= MAX_MANIFEST_ENTRIES) {
            LOG("[ManifestStore] ParseManifestJson: entry limit reached (%zu), rejecting manifest",
                MAX_MANIFEST_ENTRIES);
            result.clear();
            return result;
        }
        if (entry.type != Json::Type::Object) continue;

        ManifestEntry me;
        if (entry.has("sha"))   me.sha      = HexToSha(entry["sha"].str());
        if (entry.has("ts"))    me.timestamp = (uint64_t)entry["ts"].integer();
        if (entry.has("size"))  me.size     = (uint64_t)entry["size"].integer();
        result[filename] = std::move(me);
    }
    return result;
}

static std::string ManifestToJson(const Manifest& manifest) {
    Json::Value root = Json::Object();
    for (const auto& [filename, entry] : manifest) {
        Json::Value obj = Json::Object();
        obj.objVal["sha"]  = Json::String(ShaToHex(entry.sha));
        obj.objVal["ts"]   = Json::Number((double)entry.timestamp);
        obj.objVal["size"] = Json::Number((double)entry.size);
        root.objVal[filename] = std::move(obj);
    }
    return Json::Stringify(root);
}

enum class ManifestUploadMode {
    LocalOnly,
    Async,
    Sync,
};

static bool SaveManifestImpl(uint32_t accountId, uint32_t appId,
                             const Manifest& manifest,
                             ManifestUploadMode uploadMode) {
    const char* opName = uploadMode == ManifestUploadMode::LocalOnly
        ? "SaveManifestLocal" : "SaveManifest";

    Manifest cleanedManifest;
    for (const auto& [filename, entry] : manifest) {
        if (CloudIntercept::IsInternalMetadataFile(filename)) {
            LOG("[ManifestStore] %s app %u: stripping internal metadata '%s' from manifest",
                opName, appId, filename.c_str());
            continue;
        }
        cleanedManifest[filename] = entry;
    }

    std::string json = ManifestToJson(cleanedManifest);
    std::string localPath = ManifestLocalPath(accountId, appId);
    {
        std::error_code ec;
        auto parentPath = std::filesystem::path(FileUtil::Utf8ToPath(localPath)).parent_path();
        std::filesystem::create_directories(parentPath, ec);
    }

    if (!FileUtil::AtomicWriteText(localPath, json)) {
        LOG("[ManifestStore] %s app %u: failed to write local manifest", opName, appId);
        return false;
    }

    if (g_manifestProvider && g_manifestProvider->IsAuthenticated()) {
        if (uploadMode == ManifestUploadMode::Sync) {
            InflightSyncScope guard;
            if (!guard) return false;
            std::string cloudPath = CloudMetadataPath(accountId, appId, kManifestFilename);
            if (!UploadCloudMetadataText(accountId, appId, kManifestFilename, json)) {
                LOG("[ManifestStore] %s app %u: synchronous cloud upload failed",
                    opName, appId);
                return false;
            }
            RemoveCloudMetadataIfPresent(accountId, appId, kLegacyManifestFilename);
        } else if (uploadMode == ManifestUploadMode::Async) {
            std::string cloudPath = CloudMetadataPath(accountId, appId, kManifestFilename);
            CloudWorkQueue::WorkItem wi;
            wi.type = CloudWorkQueue::WorkItem::Upload;
            wi.cloudPath = std::move(cloudPath);
            wi.data.assign(json.begin(), json.end());
            CloudWorkQueue::EnqueueWork(std::move(wi));
        }
    }

    LOG("[ManifestStore] %s app %u: saved %zu files", opName, appId, cleanedManifest.size());
    return true;
}

} // namespace

// --- public API ---

void ManifestStore_Init(const std::string& localRoot, ICloudProvider* provider) {
    g_manifestLocalRoot = localRoot;
    g_manifestProvider = provider;
    LOG("[ManifestStore] Initialized at %s", localRoot.c_str());
}

Manifest FetchCloudManifest(uint32_t accountId, uint32_t appId) {
    InflightSyncScope guard;
    if (!guard) return {};
    if (!g_manifestProvider || !g_manifestProvider->IsAuthenticated()) return {};

    std::vector<uint8_t> data;
    bool usedLegacy = false;
    if (!DownloadCloudMetadataWithLegacyFallback(accountId, appId,
            kManifestFilename, kLegacyManifestFilename, data, &usedLegacy)) {
        LOG("[ManifestStore] FetchCloudManifest app %u: manifest not found or download failed", appId);
        return {};
    }

    constexpr size_t MAX_MANIFEST_SIZE = 16 * 1024 * 1024;
    if (data.size() > MAX_MANIFEST_SIZE) {
        LOG("[ManifestStore] FetchCloudManifest app %u: manifest too large (%zu bytes), rejecting",
            appId, data.size());
        return {};
    }

    std::string json(data.begin(), data.end());
    auto root = Json::Parse(json);
    if (usedLegacy) {
        if (root.type == Json::Type::Object &&
            UploadCloudMetadataText(accountId, appId, kManifestFilename, json)) {
            RemoveCloudMetadataIfPresent(accountId, appId, kLegacyManifestFilename);
        } else if (root.type == Json::Type::Object) {
            LOG("[ManifestStore] FetchCloudManifest app %u: failed to migrate legacy cloud manifest",
                appId);
        }
    } else {
        RemoveCloudMetadataIfPresent(accountId, appId, kLegacyManifestFilename);
    }

    RemoveCloudMetadataIfPresent(accountId, appId, kDeletedFilename);
    RemoveCloudMetadataIfPresent(accountId, appId, kLegacyDeletedFilename);
    RemoveLegacyCloudMetadataIfCanonicalExists(accountId, appId,
                                              kRootTokenFilename, kLegacyRootTokenFilename);
    RemoveLegacyCloudMetadataIfCanonicalExists(accountId, appId,
                                              kFileTokensFilename, kLegacyFileTokensFilename);

    auto manifest = ParseManifestJson(json);
    LOG("[ManifestStore] FetchCloudManifest app %u: loaded %zu files from cloud manifest",
        appId, manifest.size());
    return manifest;
}

bool SaveManifest(uint32_t accountId, uint32_t appId, const Manifest& manifest) {
    return SaveManifestImpl(accountId, appId, manifest, ManifestUploadMode::Async);
}

bool SaveManifestLocal(uint32_t accountId, uint32_t appId, const Manifest& manifest) {
    return SaveManifestImpl(accountId, appId, manifest, ManifestUploadMode::LocalOnly);
}

bool PublishFullManifestForCommit(uint32_t accountId, uint32_t appId) {
    auto mtx = AcquireAppSyncMutex(accountId, appId);
    std::lock_guard<std::mutex> lock(*mtx);

    if (!CloudWorkQueue::DrainQueueForApp(accountId, appId)) {
        LOG("[ManifestStore] PublishFullManifestForCommit app %u: pending work failed", appId);
        return false;
    }

    Manifest manifest = BuildManifestFromLocalBlobs(accountId, appId);
    if (!SaveManifestImpl(accountId, appId, manifest, ManifestUploadMode::Sync)) {
        LOG("[ManifestStore] PublishFullManifestForCommit app %u: publish failed", appId);
        return false;
    }

    LOG("[ManifestStore] PublishFullManifestForCommit app %u: published %zu files",
        appId, manifest.size());
    return true;
}

bool PublishManifestDeltaForCommit(uint32_t accountId, uint32_t appId,
                                   const std::vector<std::string>& uploads,
                                   const std::vector<std::string>& deletes) {
    auto mtx = AcquireAppSyncMutex(accountId, appId);
    std::lock_guard<std::mutex> lock(*mtx);

    if (!CloudWorkQueue::DrainQueueForApp(accountId, appId)) {
        LOG("[ManifestStore] PublishManifestDeltaForCommit app %u: pending work failed", appId);
        return false;
    }

    Manifest manifest;
    if (!TryLoadLocalManifest(accountId, appId, manifest)) {
        LOG("[ManifestStore] PublishManifestDeltaForCommit app %u: local manifest missing; "
            "falling back to full publish", appId);
        manifest = BuildManifestFromLocalBlobs(accountId, appId);
        if (!SaveManifestImpl(accountId, appId, manifest, ManifestUploadMode::Sync)) {
            LOG("[ManifestStore] PublishManifestDeltaForCommit app %u: fallback publish failed", appId);
            return false;
        }
        LOG("[ManifestStore] PublishManifestDeltaForCommit app %u: published fallback with %zu files",
            appId, manifest.size());
        return true;
    }

    auto repairStatus = RepairCloudManifest(accountId, appId, manifest,
                                            /*pruneAbsentRemote=*/false,
                                            /*persistRepair=*/false);
    if (repairStatus == ManifestRepairStatus::Incomplete) {
        LOG("[ManifestStore] PublishManifestDeltaForCommit app %u: repair incomplete; "
            "falling back to full publish", appId);
        manifest = BuildManifestFromLocalBlobs(accountId, appId);
        if (!SaveManifestImpl(accountId, appId, manifest, ManifestUploadMode::Sync)) {
            LOG("[ManifestStore] PublishManifestDeltaForCommit app %u: fallback publish failed", appId);
            return false;
        }
        LOG("[ManifestStore] PublishManifestDeltaForCommit app %u: published fallback with %zu files",
            appId, manifest.size());
        return true;
    }
    if (repairStatus == ManifestRepairStatus::Repaired) {
        LOG("[ManifestStore] PublishManifestDeltaForCommit app %u: repaired; persisting locally", appId);
        (void)SaveManifestLocal(accountId, appId, manifest);
    }

    for (const auto& filename : deletes)  manifest.erase(filename);
    size_t skippedUploads = 0;
    for (const auto& filename : uploads) {
        if (CloudIntercept::IsReservedBlobFilename(filename)) continue;
        auto entry = LocalStorage::GetFileEntry(accountId, appId, filename);
        if (!entry.has_value()) {
            LOG("[ManifestStore] PublishManifestDeltaForCommit app %u: skipping missing local entry for %s",
                appId, filename.c_str());
            ++skippedUploads;
            continue;
        }
        ManifestEntry me;
        me.sha = entry->sha;
        me.timestamp = entry->timestamp;
        me.size = entry->rawSize;
        manifest[filename] = std::move(me);
    }
    if (skippedUploads > 0) {
        LOG("[ManifestStore] PublishManifestDeltaForCommit app %u: skipped %zu uploads with missing local entries",
            appId, skippedUploads);
    }

    if (!SaveManifestImpl(accountId, appId, manifest, ManifestUploadMode::Sync)) {
        LOG("[ManifestStore] PublishManifestDeltaForCommit app %u: publish failed", appId);
        return false;
    }

    LOG("[ManifestStore] PublishManifestDeltaForCommit app %u: published delta (%zu up, %zu del, "
        "%zu total)", appId, uploads.size(), deletes.size(), manifest.size());
    return true;
}

Manifest LoadLocalManifest(uint32_t accountId, uint32_t appId) {
    Manifest manifest;
    (void)TryLoadLocalManifest(accountId, appId, manifest);
    return manifest;
}

bool TryLoadLocalManifest(uint32_t accountId, uint32_t appId, Manifest& outManifest) {
    outManifest.clear();
    std::string localPath = ManifestLocalPath(accountId, appId);
    std::ifstream in(FileUtil::Utf8ToPath(localPath), std::ios::binary);
    if (!in) return false;

    in.seekg(0, std::ios::end);
    auto fileSize = in.tellg();
    constexpr size_t MAX_MANIFEST_SIZE = 16 * 1024 * 1024;
    if (fileSize == std::streampos(-1) || static_cast<size_t>(fileSize) > MAX_MANIFEST_SIZE) {
        LOG("[ManifestStore] LoadLocalManifest app %u: file too large or unreadable (%lld bytes)",
            appId, (long long)fileSize);
        in.close();
        return false;
    }
    in.seekg(0);

    std::string json((std::istreambuf_iterator<char>(in)), {});
    in.close();

    outManifest = ParseManifestJson(json);
    LOG("[ManifestStore] LoadLocalManifest app %u: loaded %zu files", appId, outManifest.size());
    return true;
}

Manifest BuildManifestFromLocalBlobs(uint32_t accountId, uint32_t appId) {
    Manifest manifest;
    auto files = LocalStorage::GetFileList(accountId, appId);
    for (const auto& fe : files) {
        if (CloudIntercept::IsReservedBlobFilename(fe.filename)) continue;
        ManifestEntry entry;
        entry.sha = fe.sha;
        entry.timestamp = fe.timestamp;
        entry.size = fe.rawSize;
        manifest[fe.filename] = std::move(entry);
    }
    LOG("[ManifestStore] BuildManifestFromLocalBlobs app %u: built with %zu files",
        appId, manifest.size());
    return manifest;
}

ManifestRepairStatus RepairCloudManifest(uint32_t accountId, uint32_t appId,
                                          Manifest& manifest,
                                          bool pruneAbsentRemote,
                                          bool persistRepair) {
    InflightSyncScope guard;
    if (!guard) return ManifestRepairStatus::Incomplete;
    if (!g_manifestProvider || !g_manifestProvider->IsAuthenticated())
        return ManifestRepairStatus::Complete;

    std::string blobPrefix = std::to_string(accountId) + "/"
                           + std::to_string(appId) + "/blobs/";
    std::vector<ICloudProvider::FileInfo> remoteBlobs;
    bool complete = false;
    if (!g_manifestProvider->ListChecked(blobPrefix, remoteBlobs, &complete) || !complete) {
        LOG("[ManifestStore] RepairManifest app %u: listing unavailable; skipping repair", appId);
        return ManifestRepairStatus::Incomplete;
    }

    std::unordered_set<std::string> remoteBlobNames;
    std::unordered_map<std::string, ICloudProvider::FileInfo> remoteBlobInfo;
    for (const auto& fi : remoteBlobs) {
        uint32_t parsedAccountId = 0, parsedAppId = 0;
        std::string filename;
        if (!ParseCloudBlobPath(fi.path, parsedAccountId, parsedAppId, filename)) continue;
        if (parsedAccountId != accountId || parsedAppId != appId) continue;
        filename = CanonicalizeInternalMetadataName(filename);
        if (CloudIntercept::IsReservedBlobFilename(filename)) continue;
        remoteBlobNames.insert(filename);
        remoteBlobInfo[filename] = fi;
    }

    size_t repairedCount = 0;
    Manifest localManifest = BuildManifestFromLocalBlobs(accountId, appId);
    Manifest repaired = RepairManifestWithRemoteBlobListing(
        manifest, localManifest, remoteBlobNames, &repairedCount);

    size_t downloadedCount = 0;
    bool incomplete = false;
    for (const auto& filename : remoteBlobNames) {
        if (repaired.find(filename) != repaired.end()) continue;
        auto infoIt = remoteBlobInfo.find(filename);
        if (infoIt == remoteBlobInfo.end()) { incomplete = true; continue; }

        std::vector<uint8_t> data;
        if (!g_manifestProvider->Download(infoIt->second.path, data)) {
            LOG("[ManifestStore] RepairManifest app %u: failed to download blob %s",
                appId, filename.c_str());
            incomplete = true; continue;
        }

        const uint8_t emptyBlob = 0;
        const uint8_t* blobPtr = data.empty() ? &emptyBlob : data.data();
        if (!LocalStorage::WriteFileNoIncrement(accountId, appId, filename,
                blobPtr, data.size())) {
            LOG("[ManifestStore] RepairManifest app %u: failed to cache blob %s",
                appId, filename.c_str());
            incomplete = true; continue;
        }
        if (infoIt->second.modifiedTime != 0) {
            LocalStorage::SetFileTimestamp(accountId, appId, filename,
                                           infoIt->second.modifiedTime);
        }

        ManifestEntry entry;
        entry.sha = LocalStorage::SHA1(blobPtr, data.size());
        entry.timestamp = infoIt->second.modifiedTime;
        entry.size = data.size();
        repaired[filename] = std::move(entry);
        ++downloadedCount;
    }

    size_t prunedCount = 0;
    if (pruneAbsentRemote) {
        repaired = PruneManifestToRemoteBlobListing(repaired, remoteBlobNames, &prunedCount);
    }

    if (incomplete) return ManifestRepairStatus::Incomplete;
    if (repairedCount == 0 && downloadedCount == 0 && prunedCount == 0)
        return ManifestRepairStatus::Complete;

    LOG("[ManifestStore] RepairManifest app %u: restored %zu local + %zu downloaded, "
        "pruned %zu", appId, repairedCount, downloadedCount, prunedCount);
    
    if (!persistRepair) {
        manifest = std::move(repaired);
        return ManifestRepairStatus::Repaired;
    }
    if (!SaveManifest(accountId, appId, repaired))
        return ManifestRepairStatus::Incomplete;
    manifest = std::move(repaired);
    return ManifestRepairStatus::Repaired;
}

bool UpdateManifestEntry(uint32_t accountId, uint32_t appId,
                         const std::string& filename,
                         const std::vector<uint8_t>& sha,
                         uint64_t timestamp, uint64_t size) {
    if (CloudIntercept::IsReservedBlobFilename(filename)) {
        LOG("[ManifestStore] UpdateManifestEntry app %u: rejecting reserved name '%s'",
            appId, filename.c_str());
        return true;
    }

    auto mtx = AcquireAppSyncMutex(accountId, appId);
    std::lock_guard<std::mutex> lock(*mtx);

    Manifest manifest = LoadLocalManifest(accountId, appId);
    auto repairStatus = RepairCloudManifest(accountId, appId, manifest);
    if (repairStatus == ManifestRepairStatus::Incomplete) {
        manifest = BuildManifestFromLocalBlobs(accountId, appId);
        if (manifest.empty()) return false;
    }

    ManifestEntry entry;
    entry.sha = sha;
    entry.timestamp = timestamp;
    entry.size = size;
    manifest[filename] = std::move(entry);

    return SaveManifest(accountId, appId, manifest);
}

bool RemoveManifestEntry(uint32_t accountId, uint32_t appId,
                         const std::string& filename) {
    auto mtx = AcquireAppSyncMutex(accountId, appId);
    std::lock_guard<std::mutex> lock(*mtx);

    Manifest manifest = LoadLocalManifest(accountId, appId);
    auto repairStatus = RepairCloudManifest(accountId, appId, manifest);
    if (repairStatus == ManifestRepairStatus::Incomplete) {
        manifest = BuildManifestFromLocalBlobs(accountId, appId);
        if (manifest.empty()) return false;
    }

    auto it = manifest.find(filename);
    if (it == manifest.end()) return true;
    manifest.erase(it);
    return SaveManifest(accountId, appId, manifest);
}

// --- manifest snapshots for Steam-faithful delta changelist ---

static std::string ManifestSnapshotFilename(uint32_t accountId, uint32_t appId,
                                            uint64_t cn) {
    return LocalStorage::GetAppPath(accountId, appId) +
        "manifest." + std::to_string(cn) + ".cloudredirect";
}

static Manifest LoadManifestSnapshotInternal(uint32_t accountId, uint32_t appId,
                                              uint64_t cn) {
    std::string path = ManifestSnapshotFilename(accountId, appId, cn);
    std::ifstream f(FileUtil::Utf8ToPath(path), std::ios::binary);
    if (!f) return {};

    f.seekg(0, std::ios::end);
    auto sz = f.tellg();
    if (sz <= 0 || static_cast<size_t>(sz) > 16 * 1024 * 1024) return {};
    f.seekg(0);
    std::string json(static_cast<size_t>(sz), '\0');
    f.read(json.data(), sz);
    auto bytesRead = f.gcount();
    if (bytesRead != static_cast<std::streamsize>(sz))
        json.resize(static_cast<size_t>(bytesRead));
    return ParseManifestJson(json);
}

static void PruneOldManifestSnapshots(uint32_t accountId, uint32_t appId,
                                       uint64_t currentCN, int keepCount) {
    if (keepCount <= 0 || currentCN <= static_cast<uint64_t>(keepCount)) return;
    // Only prune the single snapshot that just fell off the retention window
    // instead of iterating from CN=1 (which is O(CN) per save).
    uint64_t toPrune = currentCN - static_cast<uint64_t>(keepCount);
    std::string path = ManifestSnapshotFilename(accountId, appId, toPrune);
    std::error_code ec;
    std::filesystem::remove(FileUtil::Utf8ToPath(path), ec);
}

void SaveManifestSnapshot(uint32_t accountId, uint32_t appId, uint64_t cn) {
    Manifest manifest = LoadLocalManifest(accountId, appId);
    std::string json = ManifestToJson(manifest);
    std::string path = ManifestSnapshotFilename(accountId, appId, cn);
    if (FileUtil::AtomicWriteText(path, json)) {
        PruneOldManifestSnapshots(accountId, appId, cn, 100);
    } else {
        LOG("[ManifestStore] SaveManifestSnapshot app %u CN=%llu: write failed, skipping prune",
            appId, (unsigned long long)cn);
    }
}

bool ManifestSnapshotExists(uint32_t accountId, uint32_t appId, uint64_t cn) {
    std::error_code ec;
    return std::filesystem::exists(
        FileUtil::Utf8ToPath(ManifestSnapshotFilename(accountId, appId, cn)), ec) && !ec;
}

ManifestDelta ComputeManifestDelta(uint32_t accountId, uint32_t appId,
                                    uint64_t clientCN, uint64_t serverCN,
                                    const Manifest& serverManifest) {
    ManifestDelta delta;
    delta.serverCN = serverCN;

    bool snapshotExists = ManifestSnapshotExists(accountId, appId, clientCN);
    Manifest baseline = snapshotExists
        ? LoadManifestSnapshotInternal(accountId, appId, clientCN)
        : Manifest{};
    // Treat corrupt snapshot as missing; empty "{}" is valid.
    if (snapshotExists && baseline.empty()) {
        std::string snapPath = ManifestSnapshotFilename(accountId, appId, clientCN);
        std::error_code szEc;
        auto snapSize = std::filesystem::file_size(FileUtil::Utf8ToPath(snapPath), szEc);
        if (szEc || snapSize < 2) {
            snapshotExists = false;
        }
        // or corrupt JSON. If it's "{}", baseline is correctly empty.
    }
    Manifest current;
    if (serverCN == clientCN) {
        if (!snapshotExists) {
            // Snapshot missing at this CN — can't verify "already synced."
            // Signal to caller: fall back to full manifest.
            delta.serverCN = 0;
        }
        return delta;
    }
    // Can't compute deletions without baseline snapshot.
    if (!snapshotExists) {
        delta.serverCN = 0;
        return delta;
    }
    // Use the authoritative server manifest when available; fall back to local.
    if (!serverManifest.empty()) {
        current = serverManifest;
    } else {
        current = LoadLocalManifest(accountId, appId);
        if (current.empty()) current = BuildManifestFromLocalBlobs(accountId, appId);
    }
    if (current.empty()) return delta;

    // Find new/modified entries: in current but not in baseline, or changed
    for (const auto& [name, entry] : current) {
        if (CloudIntercept::IsReservedBlobFilename(name)) continue;
        auto it = baseline.find(name);
        if (it == baseline.end() || it->second.sha != entry.sha) {
            ManifestDelta::FileChange fc;
            fc.filename = name;
            fc.sha = entry.sha;
            fc.timestamp = entry.timestamp;
            fc.size = entry.size;
            fc.deleted = false;
            delta.files.push_back(std::move(fc));
        }
    }

    // Find deleted entries: in baseline but not in current
    for (const auto& [name, entry] : baseline) {
        if (CloudIntercept::IsReservedBlobFilename(name)) continue;
        if (current.find(name) == current.end()) {
            ManifestDelta::FileChange fc;
            fc.filename = name;
            fc.deleted = true;
            delta.files.push_back(std::move(fc));
        }
    }

    return delta;
}

} // namespace CloudStorage

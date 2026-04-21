#include "rpc_handlers.h"
#include "cloud_intercept.h"
#include "local_storage.h"
#include "http_server.h"
#include "http_util.h"
#include "cloud_storage.h"
#include "file_util.h"
#include "vdf.h"
#include "log.h"
#include "json.h"
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <fstream>
#include <sstream>

namespace CloudIntercept {


// per-app upload batch tracking
static std::atomic<uint64_t> g_nextBatchId{1};

static uint64_t MakeAppAccountKey(uint32_t accountId, uint32_t appId) {
    return (static_cast<uint64_t>(accountId) << 32) | appId;
}

static bool RequireAccountId(const char* op, uint32_t appId, uint32_t& accountId) {
    constexpr ULONGLONG timeoutMs = 5000;
    constexpr DWORD sleepMs = 10;

    ULONGLONG deadline = GetTickCount64() + timeoutMs;
    do {
        accountId = GetAccountId();
        if (accountId != 0) return true;
        Sleep(sleepMs);
    } while (GetTickCount64() < deadline);

    LOG("[NS] %s app=%u timed out waiting for Steam account ID", op, appId);
    return false;
}

static bool IsInternalMetadataFile(std::string_view cleanName) {
    return cleanName == kPlaytimeMetadataPath || cleanName == kStatsMetadataPath;
}

static uint64_t ParsePlaytimeField(const Json::Value& value) {
    if (value.type == Json::Type::Number) {
        return value.number() > 0 ? static_cast<uint64_t>(value.number()) : 0;
    }
    if (value.type == Json::Type::String) {
        return strtoull(value.str().c_str(), nullptr, 10);
    }
    return 0;
}

static void ParsePlaytimeBlob(const std::string& blob, uint64_t& lastPlayed, uint64_t& playtime) {
    auto parsed = Json::Parse(blob);
    if (parsed.type == Json::Type::Object) {
        if (parsed.has("LastPlayed"))
            lastPlayed = ParsePlaytimeField(parsed["LastPlayed"]);
        if (parsed.has("Playtime"))
            playtime = ParsePlaytimeField(parsed["Playtime"]);
        return;
    }

    std::istringstream blobStream(blob);
    std::string blobLine;
    while (std::getline(blobStream, blobLine)) {
        size_t tab = blobLine.find('\t');
        if (tab == std::string::npos) continue;
        std::string key = blobLine.substr(0, tab);
        std::string val = blobLine.substr(tab + 1);
        if (key == "LastPlayed") lastPlayed = strtoull(val.c_str(), nullptr, 10);
        else if (key == "Playtime") playtime = strtoull(val.c_str(), nullptr, 10);
    }
}

// per-app root tokens extracted from upload filenames (e.g., "%GameInstall%")
// populated when HandleBeginBatch or HandleBeginFileUpload sees a %Token% prefix.
// Used to know which tokens exist for an app; the changelist only presents each
// file under the specific token it was uploaded with (tracked in g_fileTokens).
static std::unordered_map<uint64_t, std::unordered_set<std::string>> g_appRootTokens;
static std::mutex g_rootTokenMutex;

// per-app file-to-token mapping: which root token each file was uploaded under.
// Key: (accountId, appId) -> { cleanName -> rootToken }
// This prevents the changelist from duplicating files across ALL tokens, which
// caused Steam's rootoverrides to see the cross-platform copy as stale and
// issue spurious deletes (killing the only actual blob).
static std::unordered_map<uint64_t, std::unordered_map<std::string, std::string>> g_fileTokens;
static std::mutex g_fileTokensMutex;

// Track which apps had file-token changes during the current batch.
// PersistFileTokens is deferred to HandleCompleteBatch instead of being
// called per-file, eliminating redundant file_tokens.dat cloud uploads.
static std::unordered_set<uint64_t> g_fileTokensDirtyApps;
static std::mutex g_fileTokensDirtyMutex;


// Strip Steam root tokens like "%GameInstall%" from the start of a filename.
// Steam uses these as path prefixes (e.g. "%GameInstall%Saves/Slot1/file.dat")
// to indicate the file's root directory. Our local storage doesn't need them.
// Also strips any stray \r or \n between the token and the path.
static std::string StripRootToken(const std::string& filename) {
    if (filename.size() >= 2 && filename[0] == '%') {
        size_t end = filename.find('%', 1);
        if (end != std::string::npos && end + 1 < filename.size()) {
            size_t start = end + 1;
            // Skip any trailing \r or \n after the token (corrupted data cleanup)
            while (start < filename.size() && (filename[start] == '\r' || filename[start] == '\n'))
                ++start;
            return filename.substr(start);
        }
    }
    return filename;
}

// Extract just the root token (e.g., "%GameInstall%") from a filename.
// Returns empty string if no token present.
static std::string ExtractRootToken(const std::string& filename) {
    if (filename.size() >= 2 && filename[0] == '%') {
        size_t end = filename.find('%', 1);
        if (end != std::string::npos && end + 1 < filename.size()) {
            return filename.substr(0, end + 1); // e.g., "%GameInstall%"
        }
    }
    return "";
}

// Capture a root token for an app from a filename containing a %Token% prefix.
// Tracked at two levels: g_appRootTokens (all tokens per app) and g_fileTokens
// (per-file -> token mapping for changelist). Returns true if new token added.
static bool TryCaptureRootToken(uint32_t accountId, uint32_t appId, const std::string& token) {
    if (token.empty()) return false;

    bool isNew = false;
    std::unordered_set<std::string> tokensCopy;
    uint64_t key = MakeAppAccountKey(accountId, appId);
    {
        std::lock_guard<std::mutex> lock(g_rootTokenMutex);
        auto& tokenSet = g_appRootTokens[key];
        auto result = tokenSet.insert(token);
        isNew = result.second;
        if (isNew) {
            LOG("[NS-TOK] Captured root token for account %u app %u: %s (now %zu tokens)",
                accountId, appId, token.c_str(), tokenSet.size());
            tokensCopy = tokenSet;  // copy under lock
        }
    }
    // Perform disk I/O + cloud upload outside the lock
    if (isNew) {
        CloudStorage::SaveRootTokens(accountId, appId, tokensCopy);
    }
    return isNew;
}

// Record which root token a file was uploaded under.
// Called from HandleCommitFileUpload after successful commit.
static void RecordFileToken(uint32_t accountId, uint32_t appId, const std::string& cleanName, const std::string& token) {
    if (token.empty() || cleanName.empty()) return;
    std::lock_guard<std::mutex> lock(g_fileTokensMutex);
    g_fileTokens[MakeAppAccountKey(accountId, appId)][cleanName] = token;
    LOG("[NS-FT] Recorded file token: account=%u app=%u file=%s token=%s",
        accountId, appId, cleanName.c_str(), token.c_str());
}

// Get the root token a file was uploaded under (empty if unknown).
static std::string GetFileToken(uint32_t accountId, uint32_t appId, const std::string& cleanName) {
    std::lock_guard<std::mutex> lock(g_fileTokensMutex);
    auto appIt = g_fileTokens.find(MakeAppAccountKey(accountId, appId));
    if (appIt == g_fileTokens.end()) return "";
    auto fileIt = appIt->second.find(cleanName);
    if (fileIt == appIt->second.end()) return "";
    return fileIt->second;
}

// Remove a file's token mapping (called on delete).
static void RemoveFileToken(uint32_t accountId, uint32_t appId, const std::string& cleanName) {
    std::lock_guard<std::mutex> lock(g_fileTokensMutex);
    auto appIt = g_fileTokens.find(MakeAppAccountKey(accountId, appId));
    if (appIt != g_fileTokens.end()) {
        appIt->second.erase(cleanName);
        LOG("[NS-FT] Removed file token: account=%u app=%u file=%s", accountId, appId, cleanName.c_str());
    }
}

// Save in-memory file token map to disk and cloud for a given app.
static void PersistFileTokens(uint32_t accountId, uint32_t appId) {
    std::unordered_map<std::string, std::string> snapshot;
    {
        std::lock_guard<std::mutex> lock(g_fileTokensMutex);
        auto it = g_fileTokens.find(MakeAppAccountKey(accountId, appId));
        if (it != g_fileTokens.end()) snapshot = it->second;
    }
    CloudStorage::SaveFileTokens(accountId, appId, snapshot);
}

// Mark an app's file tokens as needing persistence.
// Actual persist is deferred to HandleCompleteBatch to avoid
// redundant file_tokens.dat cloud uploads (one per file).
static void MarkFileTokensDirty(uint32_t accountId, uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_fileTokensDirtyMutex);
    g_fileTokensDirtyApps.insert(MakeAppAccountKey(accountId, appId));
}

static void InvalidateTokenCaches(uint32_t accountId, uint32_t appId) {
    uint64_t key = MakeAppAccountKey(accountId, appId);
    {
        std::lock_guard<std::mutex> lock(g_rootTokenMutex);
        g_appRootTokens.erase(key);
    }
    {
        std::lock_guard<std::mutex> lock(g_fileTokensMutex);
        g_fileTokens.erase(key);
    }
}


static std::string GetMachineName() {
    char buf[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD len = sizeof(buf);
    if (GetComputerNameA(buf, &len))
        return std::string(buf, len);
    return "UNKNOWN";
}


uint32_t ExtractAppId(const char* method, const std::vector<PB::Field>& body) {
    uint32_t fieldNum = 1;
    if (strcmp(method, RPC_COMMIT_UPLOAD) == 0) fieldNum = 2;
    auto* f = PB::FindField(body, fieldNum);
    return f ? (uint32_t)f->varintVal : 0;
}


// Returns file list from HttpServer blob store (what's been uploaded).
// Steam compares this against remotecache.vdf to decide uploads/downloads.
PB::Writer HandleGetChangelist(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    auto* cnField = PB::FindField(reqBody, 2);
    uint64_t clientChangeNumber = cnField ? cnField->varintVal : 0;

    uint32_t accountId = 0;
    if (!RequireAccountId("GetAppFileChangelist", appId, accountId)) {
        PB::Writer body;
        body.WriteVarint(1, 0);
        body.WriteVarint(3, 0);
        body.WriteString(5, GetMachineName());
        body.WriteVarint(6, 0);
        return body;
    }
    uint64_t appKey = MakeAppAccountKey(accountId, appId);
    // Filenames from GetFileList are generated by filesystem::relative() against a controlled
    // app root directory, so they cannot contain path traversal sequences (e.g. "../").
    auto files = LocalStorage::GetFileList(accountId, appId);
    uint64_t serverChangeNumber = LocalStorage::GetChangeNumber(accountId, appId);

    files.erase(std::remove_if(files.begin(), files.end(),
        [](const LocalStorage::FileEntry& fe) {
            return IsInternalMetadataFile(fe.filename);
        }), files.end());

    LOG("[NS-CL] GetAppFileChangelist app=%u clientCN=%llu serverCN=%llu files=%zu",
        appId, clientChangeNumber, serverChangeNumber, files.size());

    // build path_prefix table and file entries
    std::unordered_map<std::string, uint32_t> prefixMap;
    std::vector<std::string> prefixList;
    std::string machineName = GetMachineName();

    // Look up ALL root tokens for this app (captured from upload filenames).
    std::unordered_set<std::string> rootTokens;
    {
        std::lock_guard<std::mutex> lock(g_rootTokenMutex);
        auto it = g_appRootTokens.find(appKey);
        if (it != g_appRootTokens.end()) {
            rootTokens = it->second;
        }
    }
    // If not in memory, try loading from disk (persisted from previous session)
    if (rootTokens.empty()) {
        rootTokens = CloudStorage::LoadRootTokens(accountId, appId);
        if (!rootTokens.empty()) {
            std::lock_guard<std::mutex> lock(g_rootTokenMutex);
            g_appRootTokens[appKey] = rootTokens;
        }
    }
    // If still empty, use empty string (no root token prefix -- legacy behavior)
    if (rootTokens.empty()) {
        rootTokens.insert("");
    }

    for (auto& t : rootTokens) {
        LOG("[NS-CL] Root token for app %u: '%s'", appId, t.c_str());
    }

    // Load per-file token map (which token each file was uploaded under).
    // If not in memory, load from disk. Snapshot the map so we can do
    // lockless lookups in the file loop below (H5: was N lock acquisitions).
    std::unordered_map<std::string, std::string> fileTokenSnapshot;
    {
        std::lock_guard<std::mutex> lock(g_fileTokensMutex);
        if (g_fileTokens.find(appKey) == g_fileTokens.end()) {
            auto loaded = CloudStorage::LoadFileTokens(accountId, appId);
            if (!loaded.empty()) {
                g_fileTokens[appKey] = std::move(loaded);
                LOG("[NS-CL] Loaded %zu file-token mappings for account %u app %u",
                    g_fileTokens[appKey].size(), accountId, appId);
            }
        }
        auto it = g_fileTokens.find(appKey);
        if (it != g_fileTokens.end()) {
            fileTokenSnapshot = it->second;
        }
    }

    // Pick a default token for files with no recorded token
    // (e.g., files synced from cloud before file_tokens.dat existed).
    // Prefer %GameInstall% if available, otherwise pick the lexicographically
    // smallest token for deterministic behavior across restarts.
    std::string defaultToken;
    if (!rootTokens.empty()) {
        if (rootTokens.count("%GameInstall%"))
            defaultToken = "%GameInstall%";
        else {
            std::vector<std::string> sorted(rootTokens.begin(), rootTokens.end());
            std::sort(sorted.begin(), sorted.end());
            defaultToken = sorted.front();
        }
    }

    struct PreparedFile {
        std::string leaf;
        uint32_t prefixIdx;
        const LocalStorage::FileEntry* entry;
    };
    std::vector<PreparedFile> prepared;

    for (auto& fe : files) {
        // split filename into directory prefix + leaf
        size_t lastSlash = fe.filename.rfind('/');
        std::string dirPrefix, leaf;
        if (lastSlash != std::string::npos) {
            dirPrefix = fe.filename.substr(0, lastSlash + 1);
            leaf = fe.filename.substr(lastSlash + 1);
        } else {
            leaf = fe.filename;
        }

        // Look up which token this specific file was uploaded under.
        // Only emit it under THAT token -- not all tokens.
        // This prevents Steam's rootoverrides from seeing cross-platform
        // duplicates and issuing spurious deletes.
        // Uses pre-loop snapshot (H5: avoids per-file mutex acquisition).
        std::string fileToken;
        auto ftIt = fileTokenSnapshot.find(fe.filename);
        if (ftIt != fileTokenSnapshot.end()) fileToken = ftIt->second;
        if (fileToken.empty()) {
            fileToken = defaultToken;
            LOG("[NS-CL]   file: %s has no recorded token, using default '%s'",
                fe.filename.c_str(), fileToken.c_str());
        }

        std::string fullPrefix = fileToken + dirPrefix;

        uint32_t prefixIdx;
        auto it = prefixMap.find(fullPrefix);
        if (it != prefixMap.end()) {
            prefixIdx = it->second;
        } else {
            prefixIdx = (uint32_t)prefixList.size();
            prefixMap[fullPrefix] = prefixIdx;
            prefixList.push_back(fullPrefix);
        }

        prepared.push_back({leaf, prefixIdx, &fe});
        LOG("[NS-CL]   file: %s (prefix[%u]=%s, size=%llu, ts=%llu)",
            fe.filename.c_str(), prefixIdx, fullPrefix.c_str(), fe.rawSize, fe.timestamp);
    }

    PB::Writer body;
    body.WriteVarint(1, serverChangeNumber);                     // current_change_number
    // is_only_delta: false = full listing (simplest, always correct)
    body.WriteVarint(3, 0);

    // file entries (field 2, repeated)
    for (auto& pf : prepared) {
        PB::Writer fileSub;
        fileSub.WriteString(1, pf.leaf);                        // file_name (leaf only)
        if (!pf.entry->sha.empty())
            fileSub.WriteBytes(2, pf.entry->sha.data(), pf.entry->sha.size()); // sha_file
        fileSub.WriteVarint(3, pf.entry->timestamp);            // time_stamp
        fileSub.WriteVarint(4, pf.entry->rawSize);              // raw_file_size
        fileSub.WriteVarint(5, 0);                              // persist_state = persisted
        fileSub.WriteVarint(6, 0xFFFFFFFF);                     // platforms_to_sync = all
        fileSub.WriteVarint(7, pf.prefixIdx);                    // path_prefix_index (0 = first real prefix)
        fileSub.WriteVarint(8, 0);                              // machine_name_index
        body.WriteSubmessage(2, fileSub);
    }

    // path_prefixes (field 4, repeated)
    for (auto& p : prefixList) {
        body.WriteString(4, p);
    }

    // machine_names (field 5, repeated)
    body.WriteString(5, machineName);

    // app_buildid_hwm (field 6) -- not critical, set to 0
    body.WriteVarint(6, 0);

    LOG("[NS-CL] Response: %zu files, %zu prefixes, CN=%llu",
        prepared.size(), prefixList.size(), serverChangeNumber);

    // Hex dump our generated response for comparison with real Steam
#ifdef DEBUG_HEX_DUMP
    {
        auto& ourData = body.Data();
        LOG("[NS-CL-HEX] Our changelist response: %zu bytes", ourData.size());
        for (size_t off = 0; off < ourData.size(); off += 32) {
            char hexLine[200];
            int pos = 0;
            size_t end = (off + 32 < ourData.size()) ? off + 32 : ourData.size();
            for (size_t i = off; i < end; i++) {
                pos += snprintf(hexLine + pos, sizeof(hexLine) - pos, "%02X ", ourData[i]);
            }
            LOG("[NS-CL-HEX] offset=%04X: %s", (unsigned)off, hexLine);
        }
    }
#endif

    return body;
}

// --- Binary KV reader/writer for UserGameStats merge ---

enum BkvType : uint8_t {
    BKV_SECTION   = 0x00,
    BKV_STRING    = 0x01,
    BKV_INT       = 0x02,
    BKV_FLOAT     = 0x03,
    BKV_UINT64    = 0x07,
    BKV_END       = 0x08,
    BKV_INT64     = 0x0A,
};

struct BkvNode {
    BkvType type;
    std::string name;
    // value storage (union-like, depends on type)
    uint32_t intVal = 0;
    float floatVal = 0.0f;
    uint64_t uint64Val = 0;
    int64_t int64Val = 0;
    std::string strVal;
    std::vector<BkvNode> children; // for BKV_SECTION
};

static constexpr int BKV_MAX_DEPTH = 128;
static constexpr size_t BKV_MAX_NODES = 100000;

static bool BkvRead(const uint8_t* data, size_t len, size_t& pos, std::vector<BkvNode>& out, int depth, size_t& totalNodes) {
    if (depth > BKV_MAX_DEPTH) {
        LOG("[Stats] BKV nesting too deep (%d), aborting parse", depth);
        return false;
    }
    while (pos < len) {
        uint8_t tag = data[pos++];
        if (tag == BKV_END)
            return true;

        BkvNode node;
        node.type = static_cast<BkvType>(tag);

        // read null-terminated name
        const char* nameStart = reinterpret_cast<const char*>(data + pos);
        size_t nameEnd = pos;
        while (nameEnd < len && data[nameEnd] != 0) nameEnd++;
        if (nameEnd >= len) return false;
        node.name.assign(nameStart, nameEnd - pos);
        pos = nameEnd + 1;

        switch (node.type) {
        case BKV_SECTION:
            if (!BkvRead(data, len, pos, node.children, depth + 1, totalNodes))
                return false;
            break;
        case BKV_STRING: {
            const char* s = reinterpret_cast<const char*>(data + pos);
            size_t end = pos;
            while (end < len && data[end] != 0) end++;
            if (end >= len) return false;
            node.strVal.assign(s, end - pos);
            pos = end + 1;
            break;
        }
        case BKV_INT:
        case BKV_FLOAT:
            if (pos + 4 > len) return false;
            if (node.type == BKV_INT)
                memcpy(&node.intVal, data + pos, 4);
            else
                memcpy(&node.floatVal, data + pos, 4);
            pos += 4;
            break;
        case BKV_UINT64:
            if (pos + 8 > len) return false;
            memcpy(&node.uint64Val, data + pos, 8);
            pos += 8;
            break;
        case BKV_INT64:
            if (pos + 8 > len) return false;
            memcpy(&node.int64Val, data + pos, 8);
            pos += 8;
            break;
        default:
            LOG("[Stats] Unknown BKV tag 0x%02X at offset %zu", tag, pos - 1);
            return false;
        }
        if (++totalNodes > BKV_MAX_NODES) {
            LOG("[Stats] BKV node limit exceeded (%zu), aborting parse", totalNodes);
            return false;
        }
        out.push_back(std::move(node));
    }
    return depth == 0;
}

static void BkvWrite(const std::vector<BkvNode>& nodes, std::vector<uint8_t>& out) {
    for (auto& n : nodes) {
        out.push_back(static_cast<uint8_t>(n.type));
        out.insert(out.end(), n.name.begin(), n.name.end());
        out.push_back(0);

        switch (n.type) {
        case BKV_SECTION:
            BkvWrite(n.children, out);
            out.push_back(BKV_END);
            break;
        case BKV_STRING:
            out.insert(out.end(), n.strVal.begin(), n.strVal.end());
            out.push_back(0);
            break;
        case BKV_INT:
            out.insert(out.end(), reinterpret_cast<const uint8_t*>(&n.intVal),
                       reinterpret_cast<const uint8_t*>(&n.intVal) + 4);
            break;
        case BKV_FLOAT:
            out.insert(out.end(), reinterpret_cast<const uint8_t*>(&n.floatVal),
                       reinterpret_cast<const uint8_t*>(&n.floatVal) + 4);
            break;
        case BKV_UINT64:
            out.insert(out.end(), reinterpret_cast<const uint8_t*>(&n.uint64Val),
                       reinterpret_cast<const uint8_t*>(&n.uint64Val) + 8);
            break;
        case BKV_INT64:
            out.insert(out.end(), reinterpret_cast<const uint8_t*>(&n.int64Val),
                       reinterpret_cast<const uint8_t*>(&n.int64Val) + 8);
            break;
        default:
            break;
        }
    }
}

static BkvNode* BkvFind(std::vector<BkvNode>& nodes, const std::string& name) {
    for (auto& n : nodes)
        if (n.name == name) return &n;
    return nullptr;
}

// Merge cloud stats into local stats (monotonic: more achievements/stats wins).
// Returns merged node tree ready to write.
static std::vector<BkvNode> MergeStats(
    std::vector<BkvNode>& local, std::vector<BkvNode>& cloud)
{
    // Top level should be a single "cache" section in each
    BkvNode* localCache = BkvFind(local, "cache");
    BkvNode* cloudCache = BkvFind(cloud, "cache");
    if (!localCache || !cloudCache) {
        // If either is missing/malformed, prefer whichever has a cache section
        if (cloudCache) return std::move(cloud);
        return std::move(local);
    }

    // Walk cloud stat sections and merge into local
    for (auto& cloudStat : cloudCache->children) {
        if (cloudStat.type != BKV_SECTION) continue;
        // skip non-stat sections (crc, PendingChanges are INT not SECTION)

        BkvNode* localStat = BkvFind(localCache->children, cloudStat.name);
        if (!localStat) {
            // stat exists in cloud but not locally -- take it
            localCache->children.push_back(cloudStat);
            continue;
        }

        BkvNode* localData = BkvFind(localStat->children, "data");
        BkvNode* cloudData = BkvFind(cloudStat.children, "data");
        if (!localData || !cloudData) continue;

        BkvNode* cloudAchTimes = BkvFind(cloudStat.children, "AchievementTimes");
        BkvNode* localAchTimes = BkvFind(localStat->children, "AchievementTimes");

        if (cloudAchTimes || localAchTimes) {
            // Achievement stat: OR the bitfields
            localData->intVal |= cloudData->intVal;

            // Ensure local has an AchievementTimes section
            if (!localAchTimes) {
                localStat->children.push_back(BkvNode{BKV_SECTION, "AchievementTimes"});
                localAchTimes = &localStat->children.back();
            }

            // Merge timestamps: for each bit index, keep earliest nonzero
            if (cloudAchTimes) {
                for (auto& ct : cloudAchTimes->children) {
                    if (ct.type != BKV_INT) continue;
                    BkvNode* lt = BkvFind(localAchTimes->children, ct.name);
                    if (!lt) {
                        localAchTimes->children.push_back(ct);
                    } else if (ct.intVal != 0 && (lt->intVal == 0 || ct.intVal < lt->intVal)) {
                        lt->intVal = ct.intVal;
                    }
                }
            }
        } else {
            // Regular stat: take max
            if (localData->type == BKV_INT && cloudData->type == BKV_INT) {
                if (cloudData->intVal > localData->intVal)
                    localData->intVal = cloudData->intVal;
            } else if (localData->type == BKV_FLOAT && cloudData->type == BKV_FLOAT) {
                if (cloudData->floatVal > localData->floatVal)
                    localData->floatVal = cloudData->floatVal;
            } else if (localData->type == BKV_UINT64 && cloudData->type == BKV_UINT64) {
                if (cloudData->uint64Val > localData->uint64Val)
                    localData->uint64Val = cloudData->uint64Val;
            } else if (localData->type == BKV_INT64 && cloudData->type == BKV_INT64) {
                if (cloudData->int64Val > localData->int64Val)
                    localData->int64Val = cloudData->int64Val;
            }
        }
    }

    // Recalculate CRC: set to 0 so Steam recalculates on load
    BkvNode* crc = BkvFind(localCache->children, "crc");
    if (crc && crc->type == BKV_INT)
        crc->intVal = 0;

    return std::move(local);
}

// Merge cloud stats into the local stats file on disk.
static bool MergeStatsFile(uint32_t appId, uint32_t accountId,
                           const std::vector<uint8_t>& cloudData)
{
    std::string statsPath = GetSteamPath() + "appcache\\stats\\UserGameStats_"
        + std::to_string(accountId) + "_" + std::to_string(appId) + ".bin";

    // Parse cloud data
    size_t cloudPos = 0;
    size_t cloudNodeCount = 0;
    std::vector<BkvNode> cloudNodes;
    if (!BkvRead(cloudData.data(), cloudData.size(), cloudPos, cloudNodes, 0, cloudNodeCount)) {
        LOG("[Stats] Failed to parse cloud stats for app %u, skipping merge", appId);
        return false;
    }

    // Read local file
    std::ifstream localFile(statsPath, std::ios::binary | std::ios::ate);
    if (!localFile.is_open()) {
        // No local file -- parse and rewrite cloud data to strip junk
        std::vector<uint8_t> outBuf;
        BkvWrite(cloudNodes, outBuf);
        if (!FileUtil::AtomicWriteBinary(statsPath, outBuf.data(), outBuf.size())) {
            LOG("[Stats] Failed to create stats file for app %u", appId);
            return false;
        }
        LOG("[Stats] No local stats, wrote cloud stats for app %u (%zu bytes)", appId, outBuf.size());
        return true;
    }

    auto localSize = localFile.tellg();
    if (localSize <= 0) {
        localFile.close();
        std::vector<uint8_t> outBuf;
        BkvWrite(cloudNodes, outBuf);
        if (!FileUtil::AtomicWriteBinary(statsPath, outBuf.data(), outBuf.size()))
            return false;
        LOG("[Stats] Local stats empty, wrote cloud stats for app %u (%zu bytes)", appId, outBuf.size());
        return true;
    }

    std::vector<uint8_t> localData(static_cast<size_t>(localSize));
    localFile.seekg(0);
    localFile.read(reinterpret_cast<char*>(localData.data()), localSize);
    localFile.close();

    // Parse local data
    size_t localPos = 0;
    size_t localNodeCount = 0;
    std::vector<BkvNode> localNodes;
    if (!BkvRead(localData.data(), localData.size(), localPos, localNodes, 0, localNodeCount)) {
        LOG("[Stats] Failed to parse local stats for app %u, overwriting with cloud", appId);
        std::ofstream f(statsPath, std::ios::binary | std::ios::trunc);
        if (!f.is_open()) return false;
        f.write(reinterpret_cast<const char*>(cloudData.data()), cloudData.size());
        return true;
    }

    // Merge
    auto merged = MergeStats(localNodes, cloudNodes);

    // Serialize
    std::vector<uint8_t> outBuf;
    BkvWrite(merged, outBuf);

    // Write atomically (tmp + rename) to avoid partial reads on crash
    if (!FileUtil::AtomicWriteBinary(statsPath, outBuf.data(), outBuf.size())) {
        LOG("[Stats] Failed to write merged stats for app %u", appId);
        return false;
    }

    LOG("[Stats] Merged stats for app %u (local=%zu cloud=%zu merged=%zu bytes)",
        appId, localData.size(), cloudData.size(), outBuf.size());
    return true;
}

// SignalAppLaunchIntent
// Steam calls this before sync. We respond with empty pending_remote_operations.
PB::Writer HandleLaunchIntent(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    LOG("[NS] SignalAppLaunchIntent app=%u", appId);

    RecordLaunchTime(appId);
    // Pull latest data from cloud provider (if active) before game starts.
    // This downloads CN, root tokens, metadata, and any missing blobs.
    uint32_t accountId = 0;
    if (!RequireAccountId("SignalAppLaunchIntent", appId, accountId)) {
        PB::Writer body;
        return body;
    }
    if (CloudStorage::IsCloudActive()) {
        LOG("[NS] Syncing app %u from cloud (%s) before launch...",
            appId, CloudStorage::ProviderName());
        bool hadNewer = CloudStorage::SyncFromCloud(accountId, appId);
        InvalidateTokenCaches(accountId, appId);
        LOG("[NS] Cloud sync complete for app %u (hadNewer=%d)", appId, hadNewer);

        // Merge achievement/stats data from cloud with local
        if (SyncAchievementsEnabled()) {
            auto statsData = CloudStorage::RetrieveBlob(accountId, appId, kStatsMetadataPath);
            if (!statsData.empty()) {
                MergeStatsFile(appId, accountId, statsData);
            }
        }

        // Restore playtime from cloud
        if (SyncPlaytimeEnabled()) {
            auto ptData = CloudStorage::RetrieveBlob(accountId, appId, kPlaytimeMetadataPath);
            if (!ptData.empty()) {
                std::string blob(reinterpret_cast<const char*>(ptData.data()), ptData.size());
                uint64_t cloudLastPlayed = 0, cloudPlaytime = 0;
                ParsePlaytimeBlob(blob, cloudLastPlayed, cloudPlaytime);

                if (cloudLastPlayed == 0 && cloudPlaytime == 0) {
                    LOG("[Playtime] Cloud blob empty/invalid for app %u, skipping merge", appId);
                } else {
                    // Read localconfig.vdf and merge playtime (take max)
                    std::string vdfPath = GetSteamPath() + "userdata\\" + std::to_string(accountId)
                        + "\\config\\localconfig.vdf";

                    std::ifstream vdfIn(vdfPath);
                    if (vdfIn.is_open()) {
                        std::string vdfContent((std::istreambuf_iterator<char>(vdfIn)), {});
                        vdfIn.close();

                        // Find the app section and read current values
                        std::string appIdStr = std::to_string(appId);
                        const char* sections[] = { "UserLocalConfigStore", "Software", "Valve", "Steam", "Apps", appIdStr.c_str() };
                        uint64_t localLastPlayed = 0, localPlaytime = 0;

                        struct FieldLoc { size_t valStart; size_t valEnd; };
                        FieldLoc lpLoc = {0, 0}, ptLoc = {0, 0};

                        bool found = VdfUtil::ForEachFieldInSection(vdfContent, sections, 6,
                            [&](const VdfUtil::FieldInfo& fi) {
                                if (fi.key == "LastPlayed") {
                                    localLastPlayed = strtoull(std::string(fi.value).c_str(), nullptr, 10);
                                    lpLoc = { fi.valStart, fi.valEnd };
                                } else if (fi.key == "Playtime") {
                                    localPlaytime = strtoull(std::string(fi.value).c_str(), nullptr, 10);
                                    ptLoc = { fi.valStart, fi.valEnd };
                                }
                                return true;
                            });

                        if (!found) {
                            LOG("[Playtime] App %u section not found in localconfig.vdf, skipping merge", appId);
                        } else {
                            uint64_t mergedLP = (cloudLastPlayed > localLastPlayed) ? cloudLastPlayed : localLastPlayed;
                            uint64_t mergedPT = (cloudPlaytime > localPlaytime) ? cloudPlaytime : localPlaytime;

                            bool needWrite = (mergedLP != localLastPlayed || mergedPT != localPlaytime);
                            if (needWrite) {
                                std::string newLP = std::to_string(mergedLP);
                                std::string newPT = std::to_string(mergedPT);
                                bool lpValid = lpLoc.valEnd > lpLoc.valStart;
                                bool ptValid = ptLoc.valEnd > ptLoc.valStart;

                                struct Replacement { size_t start; size_t len; std::string text; };
                                std::vector<Replacement> reps;
                                if (lpValid) reps.push_back({lpLoc.valStart, lpLoc.valEnd - lpLoc.valStart, newLP});
                                if (ptValid) reps.push_back({ptLoc.valStart, ptLoc.valEnd - ptLoc.valStart, newPT});

                                if (reps.empty()) {
                                    LOG("[Playtime] App %u section has no LastPlayed/Playtime fields, skipping write", appId);
                                } else {
                                    // Apply in reverse offset order so earlier offsets stay valid
                                    std::sort(reps.begin(), reps.end(),
                                        [](const Replacement& a, const Replacement& b) { return a.start > b.start; });
                                    for (auto& r : reps)
                                        vdfContent.replace(r.start, r.len, r.text);
                                }

                                if (FileUtil::AtomicWriteText(vdfPath, vdfContent)) {
                                    LOG("[Playtime] Merged playtime for app %u: LastPlayed %llu->%llu, Playtime %llu->%llu",
                                        appId, localLastPlayed, mergedLP, localPlaytime, mergedPT);
                                } else {
                                    LOG("[Playtime] Failed to write localconfig.vdf for app %u", appId);
                                }
                            } else {
                                LOG("[Playtime] Local playtime already up-to-date for app %u", appId);
                            }
                        }
                    } else {
                        LOG("[Playtime] Cannot open localconfig.vdf for reading (app %u)", appId);
                    }
                }
            }
        }
    }

    PB::Writer body; // empty = no pending remote operations
    return body;
}

// ClientGetAppQuotaUsage
PB::Writer HandleQuotaUsage(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    uint32_t accountId = 0;
    if (!RequireAccountId("ClientGetAppQuotaUsage", appId, accountId)) {
        PB::Writer body;
        body.WriteVarint(1, 0);
        body.WriteVarint(2, 0);
        body.WriteVarint(3, 10000);
        body.WriteVarint(4, 1073741824ULL);
        return body;
    }
    auto files = LocalStorage::GetFileList(accountId, appId);
    files.erase(std::remove_if(files.begin(), files.end(),
        [](const LocalStorage::FileEntry& fe) {
            return IsInternalMetadataFile(fe.filename);
        }), files.end());
    uint64_t totalBytes = 0;
    for (auto& f : files) totalBytes += f.rawSize;

    PB::Writer body;
    body.WriteVarint(1, (uint64_t)files.size());    // existing_files
    body.WriteVarint(2, totalBytes);                 // existing_bytes
    body.WriteVarint(3, 10000);                      // max_num_files
    body.WriteVarint(4, 1073741824ULL);              // max_num_bytes (1 GB)

    LOG("[NS] QuotaUsage app=%u files=%zu bytes=%llu", appId, files.size(), totalBytes);
    return body;
}

// BeginAppUploadBatch
PB::Writer HandleBeginBatch(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    uint64_t batchId = g_nextBatchId.fetch_add(1);
    uint32_t accountId = 0;
    if (!RequireAccountId("BeginAppUploadBatch", appId, accountId)) {
        PB::Writer body;
        body.WriteVarint(1, batchId);
        body.WriteVarint(4, 0);
        return body;
    }
    uint64_t changeNumber = LocalStorage::GetChangeNumber(accountId, appId);

    // log files to upload/delete and capture root tokens from filenames
    int uploadCount = 0, deleteCount = 0;
    for (auto& f : reqBody) {
        if (f.fieldNum == 3 && f.wireType == PB::LengthDelimited) {
            std::string name(reinterpret_cast<const char*>(f.data), f.dataLen);
            LOG("[NS-BATCH]   upload: %s", name.c_str());
            TryCaptureRootToken(accountId, appId, ExtractRootToken(name));
            ++uploadCount;
        }
        if (f.fieldNum == 4 && f.wireType == PB::LengthDelimited) {
            std::string name(reinterpret_cast<const char*>(f.data), f.dataLen);
            LOG("[NS-BATCH]   delete: %s", name.c_str());
            TryCaptureRootToken(accountId, appId, ExtractRootToken(name));
            ++deleteCount;
        }
    }

    PB::Writer body;
    body.WriteVarint(1, batchId);                    // batch_id
    body.WriteVarint(4, changeNumber);               // app_change_number

    LOG("[NS] BeginBatch app=%u batchId=%llu uploads=%d deletes=%d",
        appId, batchId, uploadCount, deleteCount);
    return body;
}

// ClientBeginFileUpload
// Tell Steam to PUT the file to our local HTTP server.
PB::Writer HandleBeginFileUpload(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    // extract request fields
    uint64_t fileSize = 0, rawFileSize = 0;
    std::string filename;
    std::vector<uint8_t> fileSha;
    uint64_t timestamp = 0;

    for (auto& f : reqBody) {
        if (f.fieldNum == 2 && f.wireType == PB::Varint) fileSize = f.varintVal;
        if (f.fieldNum == 3 && f.wireType == PB::Varint) rawFileSize = f.varintVal;
        if (f.fieldNum == 4 && f.wireType == PB::LengthDelimited)
            fileSha.assign(f.data, f.data + f.dataLen);
        if (f.fieldNum == 5 && f.wireType == PB::Varint) timestamp = f.varintVal;
        if (f.fieldNum == 6 && f.wireType == PB::LengthDelimited)
            filename.assign(reinterpret_cast<const char*>(f.data), f.dataLen);
    }

    uint16_t port = HttpServer::GetPort();
    uint32_t accountId = 0;
    if (!RequireAccountId("ClientBeginFileUpload", appId, accountId)) {
        return PB::Writer();
    }
    std::string urlHost = "127.0.0.1:" + std::to_string(port);
    std::string rootToken = ExtractRootToken(filename);
    std::string cleanName = StripRootToken(filename);
    std::string urlPath = "/upload/" + std::to_string(accountId) + "/" + std::to_string(appId)
        + "/" + HttpUtil::UrlEncode(cleanName, true);

    // Remember the root token for this app (used for default fallback in changelist).
    // The per-file token mapping (g_fileTokens) is set in HandleCommitFileUpload
    // after the upload succeeds.
    TryCaptureRootToken(accountId, appId, rootToken);

    LOG("[NS-UP] BeginFileUpload app=%u file=%s (clean=%s) size=%llu rawSize=%llu -> %s%s",
        appId, filename.c_str(), cleanName.c_str(), fileSize, rawFileSize, urlHost.c_str(), urlPath.c_str());

    // Steam has the data at fileSize bytes (possibly ZIP-compressed).
    // Request exactly that many bytes so the PUT actually happens.
    uint64_t blockLen = fileSize > 0 ? fileSize : rawFileSize;

    // build block request submessage (ClientCloudFileUploadBlockDetails)
    PB::Writer blockReq;
    blockReq.WriteString(1, urlHost);                // url_host
    blockReq.WriteString(2, urlPath);                // url_path
    blockReq.WriteVarint(3, 0);                      // use_https = false
    blockReq.WriteVarint(4, 4);                      // http_method = PUT (EHTTPMethod: 4)
    // no request_headers needed for our simple server
    blockReq.WriteVarint(6, 0);                      // block_offset = 0
    blockReq.WriteVarint(7, blockLen);               // block_length

    PB::Writer body;
    body.WriteVarint(1, 0);                          // encrypt_file = false
    body.WriteSubmessage(2, blockReq);               // block_requests (repeated, just 1)

    // hex dump response for debugging upload failures
#ifdef DEBUG_HEX_DUMP
    {
        auto& d = body.Data();
        std::string hex;
        for (size_t i = 0; i < d.size(); i++) {
            char tmp[4]; snprintf(tmp, sizeof(tmp), "%02X ", d[i]);
            hex += tmp;
        }
        LOG("[NS-UP] Response hex (%zu bytes): %s", d.size(), hex.c_str());
        auto& bd = blockReq.Data();
        std::string bhex;
        for (size_t i = 0; i < bd.size(); i++) {
            char tmp[4]; snprintf(tmp, sizeof(tmp), "%02X ", bd[i]);
            bhex += tmp;
        }
        LOG("[NS-UP] BlockReq hex (%zu bytes): %s", bd.size(), bhex.c_str());
    }
#endif

    return body;
}

// ClientCommitFileUpload
// The file has been PUT to our HTTP server. Update local metadata.
PB::Writer HandleCommitFileUpload(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    bool transferSucceeded = false;
    std::string filename;

    for (auto& f : reqBody) {
        if (f.fieldNum == 1 && f.wireType == PB::Varint) transferSucceeded = (f.varintVal != 0);
        if (f.fieldNum == 4 && f.wireType == PB::LengthDelimited)
            filename.assign(reinterpret_cast<const char*>(f.data), f.dataLen);
    }

    LOG("[NS-UP] CommitFileUpload app=%u file=%s succeeded=%d",
        appId, filename.c_str(), transferSucceeded);

    std::string cleanName = StripRootToken(filename);
    bool committed = false;
    uint32_t accountId = 0;
    if (!RequireAccountId("ClientCommitFileUpload", appId, accountId)) {
        PB::Writer body;
        body.WriteVarint(1, 0);
        return body;
    }
    if (transferSucceeded) {
        // the file was PUT to HttpServer's blob store already -- verify it exists
        if (HttpServer::HasBlob(accountId, appId, cleanName)) {
            committed = true;

            // Read blob for cloud upload. No SHA re-verification: Steam sent the
            // data over localhost TCP and told us the transfer succeeded. Re-reading
            // from disk and re-hashing is redundant -- the only way the SHA could
            // differ is disk corruption in the milliseconds between PUT and Commit.
            // The real Steam server also doesn't re-verify SHA at commit time; it
            // trusts the uploaded data. Removing this check fixes spurious commit
            // rejections for volatile files (e.g. Player.log).
            auto blobData = HttpServer::ReadBlob(accountId, appId, cleanName);
            LOG("[NS-UP]   committed: %s (%zu bytes)", cleanName.c_str(), blobData.size());

            {
                // CloudStorage::StoreBlob writes to the local cache (same dir as
                // LocalStorage) and enqueues a cloud upload. Empty files are valid
                // and must be preserved as zero-byte blobs.
                const uint8_t* blobPtr = blobData.empty() ? nullptr : blobData.data();
                if (!CloudStorage::StoreBlob(accountId, appId, cleanName,
                        blobPtr, blobData.size())) {
                    LOG("[NS-UP]   ERROR: failed to store blob for %s", cleanName.c_str());
                    committed = false;
                }
            }

            // Record which root token this file was uploaded under.
            // The changelist will only present files under their upload token,
            // preventing Steam's rootoverrides from seeing cross-platform
            // duplicates and issuing spurious deletes.
            std::string rootToken = ExtractRootToken(filename);
            RecordFileToken(accountId, appId, cleanName, rootToken);
            MarkFileTokensDirty(accountId, appId);
        } else {
            LOG("[NS-UP]   WARNING: blob not found after PUT for %s (clean=%s)", filename.c_str(), cleanName.c_str());
        }

        // Cloud upload already enqueued by CloudStorage::StoreBlob above
    }

    PB::Writer body;
    body.WriteVarint(1, committed ? 1 : 0);          // file_committed
    return body;
}

// CompleteAppUploadBatchBlocking
PB::Writer HandleCompleteBatch(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    // Persist file tokens once per batch (deferred from per-file commits/deletes).
    // This replaces N redundant file_tokens.dat cloud uploads with a single one.
    {
        std::unordered_set<uint64_t> dirtyApps;
        {
            std::lock_guard<std::mutex> lock(g_fileTokensDirtyMutex);
            dirtyApps.swap(g_fileTokensDirtyApps);
        }
        for (uint64_t dirty : dirtyApps) {
            uint32_t dirtyAccountId = static_cast<uint32_t>(dirty >> 32);
            uint32_t dirtyAppId = static_cast<uint32_t>(dirty & 0xFFFFFFFFu);
            PersistFileTokens(dirtyAccountId, dirtyAppId);
        }
    }

    // Increment CN once per batch (not per file) to match real Steam behavior.
    // This prevents the CN from climbing rapidly and causing conflict dialogs
    // when Steam restarts with clientCN=0.
    uint32_t accountId = 0;
    if (!RequireAccountId("CompleteAppUploadBatchBlocking", appId, accountId)) {
        return PB::Writer();
    }
    uint64_t newCN = LocalStorage::IncrementChangeNumber(accountId, appId);
    LOG("[NS] CompleteBatch app=%u CN=%llu", appId, newCN);

    // Push updated CN to cloud provider
    CloudStorage::PushCNToCloud(accountId, appId, newCN);

    // Drain cloud sync queue -- ensure all blobs are pushed before we tell Steam "batch done"
    CloudStorage::DrainQueueForApp(accountId, appId);
    PB::Writer body; // empty response
    return body;
}

// ClientFileDownload
// Tell Steam to GET the file from our local HTTP server.
PB::Writer HandleFileDownload(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    std::string filename;
    for (auto& f : reqBody) {
        if (f.fieldNum == 2 && f.wireType == PB::LengthDelimited)
            filename.assign(reinterpret_cast<const char*>(f.data), f.dataLen);
    }

    uint32_t accountId = 0;
    if (!RequireAccountId("ClientFileDownload", appId, accountId)) {
        return PB::Writer();
    }
    uint16_t port = HttpServer::GetPort();
    std::string urlHost = "127.0.0.1:" + std::to_string(port);
    std::string cleanName = StripRootToken(filename);
    std::string urlPath = "/download/" + std::to_string(accountId) + "/" + std::to_string(appId)
        + "/" + HttpUtil::UrlEncode(cleanName, true);

    // get file metadata from local storage (single-file lookup, no full dir scan)
    uint64_t fileSize = 0;    uint64_t timestamp = 0;
    std::vector<uint8_t> sha;

    auto entry = LocalStorage::GetFileEntry(accountId, appId, cleanName);
    if (entry) {
        fileSize = entry->rawSize;
        timestamp = entry->timestamp;
        sha = entry->sha;
    }

    // fall back to blob store if not in local storage metadata
    if (fileSize == 0) {
        fileSize = HttpServer::GetBlobSize(accountId, appId, cleanName);
    }

    LOG("[NS-DL] FileDownload app=%u file=%s (clean=%s) size=%llu -> %s%s",
        appId, filename.c_str(), cleanName.c_str(), fileSize, urlHost.c_str(), urlPath.c_str());

    PB::Writer body;
    body.WriteVarint(1, appId);                      // appid
    body.WriteVarint(2, fileSize);                   // file_size (compressed = same)
    body.WriteVarint(3, fileSize);                   // raw_file_size
    if (!sha.empty())
        body.WriteBytes(4, sha.data(), sha.size());  // sha_file
    body.WriteVarint(5, timestamp);                  // time_stamp
    body.WriteVarint(6, 0);                          // is_explicit_delete = false
    body.WriteString(7, urlHost);                    // url_host
    body.WriteString(8, urlPath);                    // url_path
    body.WriteVarint(9, 0);                          // use_https = false
    // no request_headers (field 10)
    body.WriteVarint(11, 0);                         // encrypted = false

    return body;
}

// ClientDeleteFile
PB::Writer HandleDeleteFile(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    std::string filename;
    for (auto& f : reqBody) {
        if (f.fieldNum == 2 && f.wireType == PB::LengthDelimited)
            filename.assign(reinterpret_cast<const char*>(f.data), f.dataLen);
    }

    std::string cleanName = StripRootToken(filename);
    LOG("[NS] DeleteFile app=%u file=%s (clean=%s)", appId, filename.c_str(), cleanName.c_str());

    if (IsInternalMetadataFile(cleanName)) {
        LOG("[NS] DeleteFile app=%u ignored for internal metadata %s", appId, cleanName.c_str());
        return PB::Writer();
    }

    uint32_t accountId = 0;
    if (!RequireAccountId("ClientDeleteFile", appId, accountId)) {
        return PB::Writer();
    }
    // CloudStorage::DeleteBlob removes from local cache and cloud, and
    // increments the change number so Steam re-downloads the file list.
    HttpServer::DeleteBlob(accountId, appId, cleanName);

    // Delete from cloud provider (async -- enqueues delete if provider active)
    CloudStorage::DeleteBlob(accountId, appId, cleanName);

    // Remove file-token mapping and mark dirty (persist deferred to CompleteBatch)
    RemoveFileToken(accountId, appId, cleanName);
    MarkFileTokensDirty(accountId, appId);

    PB::Writer body; // empty response
    return body;
}

} // namespace CloudIntercept

#include "rpc_handlers.h"
#include "cloud_intercept.h"
#include "local_storage.h"
#include "http_server.h"
#include "http_util.h"
#include "cloud_storage.h"
#include "log.h"
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <atomic>
#include <cstring>

namespace CloudIntercept {


// per-app upload batch tracking
static std::atomic<uint64_t> g_nextBatchId{1};

// per-app root tokens extracted from upload filenames (e.g., "%GameInstall%")
// populated when HandleBeginBatch or HandleBeginFileUpload sees a %Token% prefix.
// Used to know which tokens exist for an app; the changelist only presents each
// file under the specific token it was uploaded with (tracked in g_fileTokens).
static std::unordered_map<uint32_t, std::unordered_set<std::string>> g_appRootTokens;
static std::mutex g_rootTokenMutex;

// per-app file-to-token mapping: which root token each file was uploaded under.
// Key: appId -> { cleanName -> rootToken }
// This prevents the changelist from duplicating files across ALL tokens, which
// caused Steam's rootoverrides to see the cross-platform copy as stale and
// issue spurious deletes (killing the only actual blob).
static std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>> g_fileTokens;
static std::mutex g_fileTokensMutex;

// Track which apps had file-token changes during the current batch.
// PersistFileTokens is deferred to HandleCompleteBatch instead of being
// called per-file, eliminating redundant file_tokens.dat cloud uploads.
static std::unordered_set<uint32_t> g_fileTokensDirtyApps;
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
static bool TryCaptureRootToken(uint32_t appId, const std::string& token) {
    if (token.empty()) return false;

    bool isNew = false;
    std::unordered_set<std::string> tokensCopy;
    {
        std::lock_guard<std::mutex> lock(g_rootTokenMutex);
        auto& tokenSet = g_appRootTokens[appId];
        auto result = tokenSet.insert(token);
        isNew = result.second;
        if (isNew) {
            LOG("[NS-TOK] Captured root token for app %u: %s (now %zu tokens)",
                appId, token.c_str(), tokenSet.size());
            tokensCopy = tokenSet;  // copy under lock
        }
    }
    // Perform disk I/O + cloud upload outside the lock
    if (isNew) {
        uint32_t accountId = GetAccountId();
        CloudStorage::SaveRootTokens(accountId, appId, tokensCopy);
    }
    return isNew;
}

// Record which root token a file was uploaded under.
// Called from HandleCommitFileUpload after successful commit.
static void RecordFileToken(uint32_t appId, const std::string& cleanName, const std::string& token) {
    if (token.empty() || cleanName.empty()) return;
    std::lock_guard<std::mutex> lock(g_fileTokensMutex);
    g_fileTokens[appId][cleanName] = token;
    LOG("[NS-FT] Recorded file token: app=%u file=%s token=%s", appId, cleanName.c_str(), token.c_str());
}

// Get the root token a file was uploaded under (empty if unknown).
static std::string GetFileToken(uint32_t appId, const std::string& cleanName) {
    std::lock_guard<std::mutex> lock(g_fileTokensMutex);
    auto appIt = g_fileTokens.find(appId);
    if (appIt == g_fileTokens.end()) return "";
    auto fileIt = appIt->second.find(cleanName);
    if (fileIt == appIt->second.end()) return "";
    return fileIt->second;
}

// Remove a file's token mapping (called on delete).
static void RemoveFileToken(uint32_t appId, const std::string& cleanName) {
    std::lock_guard<std::mutex> lock(g_fileTokensMutex);
    auto appIt = g_fileTokens.find(appId);
    if (appIt != g_fileTokens.end()) {
        appIt->second.erase(cleanName);
        LOG("[NS-FT] Removed file token: app=%u file=%s", appId, cleanName.c_str());
    }
}

// Save in-memory file token map to disk and cloud for a given app.
static void PersistFileTokens(uint32_t appId) {
    uint32_t accountId = GetAccountId();
    std::unordered_map<std::string, std::string> snapshot;
    {
        std::lock_guard<std::mutex> lock(g_fileTokensMutex);
        auto it = g_fileTokens.find(appId);
        if (it != g_fileTokens.end()) snapshot = it->second;
    }
    CloudStorage::SaveFileTokens(accountId, appId, snapshot);
}

// Mark an app's file tokens as needing persistence.
// Actual persist is deferred to HandleCompleteBatch to avoid
// redundant file_tokens.dat cloud uploads (one per file).
static void MarkFileTokensDirty(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_fileTokensDirtyMutex);
    g_fileTokensDirtyApps.insert(appId);
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

    uint32_t accountId = GetAccountId();
    // Filenames from GetFileList are generated by filesystem::relative() against a controlled
    // app root directory, so they cannot contain path traversal sequences (e.g. "../").
    auto files = LocalStorage::GetFileList(accountId, appId);
    uint64_t serverChangeNumber = LocalStorage::GetChangeNumber(accountId, appId);

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
        auto it = g_appRootTokens.find(appId);
        if (it != g_appRootTokens.end()) {
            rootTokens = it->second;
        }
    }
    // If not in memory, try loading from disk (persisted from previous session)
    if (rootTokens.empty()) {
        rootTokens = CloudStorage::LoadRootTokens(accountId, appId);
        if (!rootTokens.empty()) {
            std::lock_guard<std::mutex> lock(g_rootTokenMutex);
            g_appRootTokens[appId] = rootTokens;
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
        if (g_fileTokens.find(appId) == g_fileTokens.end()) {
            auto loaded = CloudStorage::LoadFileTokens(accountId, appId);
            if (!loaded.empty()) {
                g_fileTokens[appId] = std::move(loaded);
                LOG("[NS-CL] Loaded %zu file-token mappings for app %u",
                    g_fileTokens[appId].size(), appId);
            }
        }
        auto it = g_fileTokens.find(appId);
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

// SignalAppLaunchIntent
// Steam calls this before sync. We respond with empty pending_remote_operations.
PB::Writer HandleLaunchIntent(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    LOG("[NS] SignalAppLaunchIntent app=%u", appId);

    // Pull latest data from cloud provider (if active) before game starts.
    // This downloads CN, root tokens, metadata, and any missing blobs.
    uint32_t accountId = GetAccountId();
    if (CloudStorage::IsCloudActive()) {
        LOG("[NS] Syncing app %u from cloud (%s) before launch...",
            appId, CloudStorage::ProviderName());
        bool hadNewer = CloudStorage::SyncFromCloud(accountId, appId);
        LOG("[NS] Cloud sync complete for app %u (hadNewer=%d)", appId, hadNewer);
    }

    PB::Writer body; // empty = no pending remote operations
    return body;
}

// ClientGetAppQuotaUsage
PB::Writer HandleQuotaUsage(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    uint32_t accountId = GetAccountId();
    auto files = LocalStorage::GetFileList(accountId, appId);
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
    uint32_t accountId = GetAccountId();
    uint64_t changeNumber = LocalStorage::GetChangeNumber(accountId, appId);

    // log files to upload/delete and capture root tokens from filenames
    int uploadCount = 0, deleteCount = 0;
    for (auto& f : reqBody) {
        if (f.fieldNum == 3 && f.wireType == PB::LengthDelimited) {
            std::string name(reinterpret_cast<const char*>(f.data), f.dataLen);
            LOG("[NS-BATCH]   upload: %s", name.c_str());
            TryCaptureRootToken(appId, ExtractRootToken(name));
            ++uploadCount;
        }
        if (f.fieldNum == 4 && f.wireType == PB::LengthDelimited) {
            std::string name(reinterpret_cast<const char*>(f.data), f.dataLen);
            LOG("[NS-BATCH]   delete: %s", name.c_str());
            TryCaptureRootToken(appId, ExtractRootToken(name));
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
    std::string urlHost = "127.0.0.1:" + std::to_string(port);
    std::string rootToken = ExtractRootToken(filename);
    std::string cleanName = StripRootToken(filename);
    std::string urlPath = "/upload/" + std::to_string(appId) + "/" + HttpUtil::UrlEncode(cleanName, true);

    // Remember the root token for this app (used for default fallback in changelist).
    // The per-file token mapping (g_fileTokens) is set in HandleCommitFileUpload
    // after the upload succeeds.
    TryCaptureRootToken(appId, rootToken);

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
    if (transferSucceeded) {
        // the file was PUT to HttpServer's blob store already -- verify it exists
        if (HttpServer::HasBlob(appId, cleanName)) {
            committed = true;
            uint32_t accountId = GetAccountId();

            // Read blob for cloud upload. No SHA re-verification: Steam sent the
            // data over localhost TCP and told us the transfer succeeded. Re-reading
            // from disk and re-hashing is redundant -- the only way the SHA could
            // differ is disk corruption in the milliseconds between PUT and Commit.
            // The real Steam server also doesn't re-verify SHA at commit time; it
            // trusts the uploaded data. Removing this check fixes spurious commit
            // rejections for volatile files (e.g. Player.log).
            auto blobData = HttpServer::ReadBlob(appId, cleanName);
            LOG("[NS-UP]   committed: %s (%zu bytes)", cleanName.c_str(), blobData.size());

            if (!blobData.empty()) {
                // After storage/blob unification, the HTTP PUT handler already
                // wrote this file to storage/. We intentionally do NOT call
                // LocalStorage::WriteFile() here because it would redundantly
                // overwrite the same data AND increment the change number (CN).
                // CN must NOT be incremented by client-initiated uploads -- otherwise
                // Steam sees serverCN > clientCN after exit sync and triggers a
                // spurious download loop.

                // Push blob to cloud provider (async -- enqueues upload if provider active)
                CloudStorage::StoreBlob(accountId, appId, cleanName,
                    blobData.data(), blobData.size());
            }

            // Record which root token this file was uploaded under.
            // The changelist will only present files under their upload token,
            // preventing Steam's rootoverrides from seeing cross-platform
            // duplicates and issuing spurious deletes.
            std::string rootToken = ExtractRootToken(filename);
            RecordFileToken(appId, cleanName, rootToken);
            MarkFileTokensDirty(appId);
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
    LOG("[NS] CompleteBatch app=%u", appId);

    // Persist file tokens once per batch (deferred from per-file commits/deletes).
    // This replaces N redundant file_tokens.dat cloud uploads with a single one.
    {
        std::unordered_set<uint32_t> dirtyApps;
        {
            std::lock_guard<std::mutex> lock(g_fileTokensDirtyMutex);
            dirtyApps.swap(g_fileTokensDirtyApps);
        }
        for (uint32_t dirty : dirtyApps) {
            PersistFileTokens(dirty);
        }
    }

    // Drain cloud sync queue -- ensure all blobs are pushed before we tell Steam "batch done"
    CloudStorage::DrainQueue();
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

    uint16_t port = HttpServer::GetPort();
    std::string urlHost = "127.0.0.1:" + std::to_string(port);
    std::string cleanName = StripRootToken(filename);
    std::string urlPath = "/download/" + std::to_string(appId) + "/" + HttpUtil::UrlEncode(cleanName, true);

    // get file metadata from local storage (single-file lookup, no full dir scan)
    uint32_t accountId = GetAccountId();
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
        fileSize = HttpServer::GetBlobSize(appId, cleanName);
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

    std::string rootToken = ExtractRootToken(filename);
    std::string cleanName = StripRootToken(filename);
    LOG("[NS] DeleteFile app=%u file=%s (clean=%s)", appId, filename.c_str(), cleanName.c_str());

    uint32_t accountId = GetAccountId();
    // After storage/blob unification, LocalStorage and HttpServer point to the
    // same directory. We use HttpServer::DeleteBlob() to remove the file, and
    // intentionally do NOT call LocalStorage::DeleteFile() because it increments
    // the change number (CN). CN must NOT be incremented by client-initiated deletes
    // -- otherwise Steam sees serverCN > clientCN after exit sync and triggers a
    // spurious download loop.
    HttpServer::DeleteBlob(appId, cleanName);

    // Delete from cloud provider (async -- enqueues delete if provider active)
    CloudStorage::DeleteBlob(accountId, appId, cleanName);

    // Remove file-token mapping and mark dirty (persist deferred to CompleteBatch)
    RemoveFileToken(appId, cleanName);
    MarkFileTokensDirty(appId);

    PB::Writer body; // empty response
    return body;
}

} // namespace CloudIntercept

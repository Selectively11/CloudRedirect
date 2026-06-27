#include "app_state.h"
#include "cloud_storage.h"
#include "cloud_metadata_paths.h"
#include "file_util.h"
#include "json.h"
#include "local_storage.h"
#include "log.h"
#include "manifest_store.h"

#include <ctime>

using CloudIntercept::IsReservedBlobFilename;

namespace CloudStorage {

static ICloudProvider* g_stateProvider = nullptr;

void AppState_Init(ICloudProvider* provider) {
    g_stateProvider = provider;
}

void AppState_Shutdown() {
    g_stateProvider = nullptr;
}

bool CloudAppState::hasActiveSession() const {
    return session.clientId != 0 && !session.operation.empty();
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
    if (hex.size() > kMaxShaHexLength) return {};
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

std::string SerializeState(const CloudAppState& state) {
    Json::Value root = Json::Object();
    root.objVal["v"] = Json::Number((double)state.version);
    root.objVal["cn"] = Json::Number((double)state.cn);
    root.objVal["build_id"] = Json::Number((double)state.appBuildId);

    // Quota (only emit when present so v1 readers see no unknown field)
    if (state.quota.fetchedAtUnix != 0 ||
        state.quota.quotaBytes != 0 ||
        state.quota.maxNumFiles != 0) {
        Json::Value q = Json::Object();
        q.objVal["bytes"] = Json::Number((double)state.quota.quotaBytes);
        q.objVal["files"] = Json::Number((double)state.quota.maxNumFiles);
        q.objVal["at"] = Json::Number((double)state.quota.fetchedAtUnix);
        q.objVal["build"] = Json::Number((double)state.quota.lastSeenBuildId);
        root.objVal["quota"] = std::move(q);
    }

    if (state.hasActiveSession()) {
        Json::Value sess = Json::Object();
        sess.objVal["client_id"] = Json::String(std::to_string(state.session.clientId));
        sess.objVal["machine"] = Json::String(state.session.machineName);
        sess.objVal["time"] = Json::Number((double)state.session.timeLastUpdated);
        sess.objVal["op"] = Json::String(state.session.operation);
        root.objVal["session"] = std::move(sess);
    }

    if (!state.machines.empty()) {
        Json::Value arr = Json::Array();
        for (const auto& m : state.machines)
            arr.arrVal.push_back(Json::String(m));
        root.objVal["machines"] = std::move(arr);
    }

    Json::Value files = Json::Object();
    for (const auto& [name, entry] : state.files) {
        if (IsReservedBlobFilename(name)) continue;
        Json::Value obj = Json::Object();
        obj.objVal["sha"] = Json::String(ShaToHex(entry.sha));
        obj.objVal["ts"] = Json::Number((double)entry.timestamp);
        obj.objVal["size"] = Json::Number((double)entry.size);
        if (entry.persistState != 0)
            obj.objVal["ps"] = Json::Number((double)entry.persistState);
        if (entry.platformsToSync != 0xFFFFFFFFu)
            obj.objVal["pt"] = Json::Number((double)entry.platformsToSync);
        if (entry.rootIndex != 0)
            obj.objVal["root"] = Json::Number((double)entry.rootIndex);
        if (entry.machineIndex != 0)
            obj.objVal["machine"] = Json::Number((double)entry.machineIndex);
        files.objVal[name] = std::move(obj);
    }
    root.objVal["files"] = std::move(files);

    return Json::Stringify(root);
}

bool DeserializeState(const std::string& json, CloudAppState& outState) {
    outState = {};
    if (json.empty()) return false;

    auto root = Json::Parse(json);
    if (root.type != Json::Type::Object) {
        LOG("[AppState] DeserializeState: invalid JSON root type=%d", (int)root.type);
        return false;
    }

    if (root.has("v")) outState.version = (uint32_t)root["v"].integer();
    if (root.has("cn")) outState.cn = (uint64_t)root["cn"].integer();
    if (root.has("build_id")) outState.appBuildId = (uint64_t)root["build_id"].integer();

    // Quota (absent in v1 state files; defaults to zero-initialized struct)
    if (root.has("quota") && root["quota"].type == Json::Type::Object) {
        auto& q = root["quota"];
        if (q.has("bytes")) outState.quota.quotaBytes = (uint64_t)q["bytes"].integer();
        if (q.has("files")) outState.quota.maxNumFiles = (uint32_t)q["files"].integer();
        if (q.has("at")) outState.quota.fetchedAtUnix = (uint64_t)q["at"].integer();
        if (q.has("build")) outState.quota.lastSeenBuildId = (uint64_t)q["build"].integer();
    }

    if (root.has("session") && root["session"].type == Json::Type::Object) {
        auto& sess = root["session"];
        if (sess.has("client_id")) {
            if (sess["client_id"].type == Json::Type::String)
                outState.session.clientId = strtoull(sess["client_id"].str().c_str(), nullptr, 10);
            else
                outState.session.clientId = (uint64_t)sess["client_id"].integer();
        }
        if (sess.has("machine")) outState.session.machineName = sess["machine"].str();
        if (sess.has("time")) outState.session.timeLastUpdated = (uint64_t)sess["time"].integer();
        if (sess.has("op")) outState.session.operation = sess["op"].str();
    }

    if (root.has("machines") && root["machines"].type == Json::Type::Array) {
        for (const auto& m : root["machines"].arrVal) {
            outState.machines.push_back(m.str());
        }
    }

    constexpr size_t MAX_FILES = 100000;
    if (root.has("files") && root["files"].type == Json::Type::Object) {
        for (const auto& [name, val] : root["files"].objVal) {
            if (outState.files.size() >= MAX_FILES) {
                LOG("[AppState] DeserializeState: entry limit reached (%zu), rejecting",
                    MAX_FILES);
                outState.files.clear();
                return false;
            }
            if (val.type != Json::Type::Object) continue;

            FileEntry fe;
            if (val.has("sha")) fe.sha = HexToSha(val["sha"].str());
            if (val.has("ts")) fe.timestamp = (uint64_t)val["ts"].integer();
            if (val.has("size")) fe.size = (uint64_t)val["size"].integer();
            if (val.has("ps")) fe.persistState = (uint32_t)val["ps"].integer();
            if (val.has("pt")) fe.platformsToSync = (uint32_t)val["pt"].integer();
            if (val.has("root")) fe.rootIndex = (uint32_t)val["root"].integer();
            if (val.has("machine")) fe.machineIndex = (uint32_t)val["machine"].integer();
            outState.files[name] = std::move(fe);
        }
    }

    return true;
}

static constexpr const char* kStateFilename = "state.cloudredirect";
static constexpr size_t MAX_STATE_SIZE = 16 * 1024 * 1024; // 16 MB

StateFetchResult FetchCloudState(uint32_t accountId, uint32_t appId) {
    InflightSyncScope guard;
    if (!guard) return { StateFetchStatus::FetchFailed, {}, {} };
    if (!g_stateProvider || !g_stateProvider->IsAuthenticated())
        return { StateFetchStatus::FetchFailed, {}, {} };

    std::string statePath = CloudMetadataPath(accountId, appId, kStateFilename);
    std::vector<uint8_t> data;
    if (g_stateProvider->Download(statePath, data)) {
        if (data.size() > MAX_STATE_SIZE) {
            LOG("[AppState] FetchCloudState app %u: state file too large (%zu bytes)",
                appId, data.size());
            return { StateFetchStatus::ParseFailed, {}, {} };
        }
        std::string json(data.begin(), data.end());
        CloudAppState state;
        if (!DeserializeState(json, state)) {
            LOG("[AppState] FetchCloudState app %u: parse failed", appId);
            return { StateFetchStatus::ParseFailed, {}, {} };
        }
        // cn>0 with empty files is valid (user deleted all saves).
        // AutoCloudImport repopulates from disk if local files exist.
        LOG("[AppState] FetchCloudState app %u: loaded state CN=%llu, %zu files",
            appId, state.cn, state.files.size());
        return { StateFetchStatus::Ok, std::move(state), {} };
    }

    auto existsStatus = g_stateProvider->CheckExists(statePath);
    if (existsStatus == ICloudProvider::ExistsStatus::Missing) {
        auto legacyResult = FetchCloudManifest(accountId, appId);
        uint64_t legacyCN = 0;

        std::vector<uint8_t> cnData;
        std::string cnPath = CloudMetadataPath(accountId, appId,
            CloudIntercept::kCNFilename);
        if (g_stateProvider->Download(cnPath, cnData)) {
            std::string cnStr(cnData.begin(), cnData.end());
            try { legacyCN = std::stoull(cnStr); } catch (...) {}
        }

        if (legacyResult.status == ManifestFetchStatus::Ok || legacyCN > 0) {
            CloudAppState state;
            state.cn = legacyCN;
            if (legacyResult.status == ManifestFetchStatus::Ok) {
                for (const auto& [name, me] : legacyResult.manifest) {
                    // Heal CAS-corrupted legacy keys: builds <= 2.0.4 wrote the
                    // blob path "<file>/<sha40>" as the manifest key, which makes
                    // restore land at "<file>/<sha40>" (a directory) instead of
                    // the real save file. Strip a 40-hex-char leaf so the
                    // migrated state uses the true filename.
                    std::string clean = name;
                    size_t lastSlash = clean.rfind('/');
                    if (lastSlash != std::string::npos && lastSlash != 0 &&
                        lastSlash + 1 < clean.size()) {
                        std::string leaf = clean.substr(lastSlash + 1);
                        if (leaf.size() == 40 &&
                            leaf.find_first_not_of("0123456789abcdef") == std::string::npos) {
                            clean = clean.substr(0, lastSlash);
                        }
                    }
                    if (clean.empty()) continue;
                    FileEntry fe;
                    fe.sha = me.sha;
                    fe.timestamp = me.timestamp;
                    fe.size = me.size;
                    // CAS dedup: if multiple SHAs collapsed to one name, keep largest.
                    auto it = state.files.find(clean);
                    if (it != state.files.end() && it->second.size >= fe.size) continue;
                    state.files[clean] = std::move(fe);
                }
            }
            if (state.cn > 0 && state.files.empty() && g_stateProvider) {
                std::string blobPrefix = std::to_string(accountId) + "/" +
                                         std::to_string(appId) + "/blobs/";
                std::vector<ICloudProvider::FileInfo> remoteBlobs;
                bool complete = false;
                if (g_stateProvider->ListChecked(blobPrefix, remoteBlobs, &complete) && complete) {
                    for (const auto& fi : remoteBlobs) {
                        std::string filename = fi.path.substr(blobPrefix.size());
                        if (filename.empty() || CloudIntercept::IsReservedBlobFilename(filename))
                            continue;
                        // Strip CAS SHA leaf: "subdir/file.sav/a1b2c3..." -> "subdir/file.sav"
                        size_t lastSlash = filename.rfind('/');
                        if (lastSlash != std::string::npos && lastSlash + 1 < filename.size()) {
                            std::string leaf = filename.substr(lastSlash + 1);
                            if (leaf.size() == 40 &&
                                leaf.find_first_not_of("0123456789abcdef") == std::string::npos) {
                                filename = filename.substr(0, lastSlash);
                            }
                        }
                        if (filename.empty()) continue;
                        FileEntry fe;
                        fe.size = fi.size;
                        fe.timestamp = fi.modifiedTime;
                        // CAS dedup: if multiple SHAs exist for same file, keep largest (latest upload).
                        auto it = state.files.find(filename);
                        if (it != state.files.end() && it->second.timestamp >= fe.timestamp)
                            continue;
                        state.files[filename] = std::move(fe);
                    }
                }
                if (!state.files.empty()) {
                    LOG("[AppState] FetchCloudState app %u: migration repair from cloud (%zu files)",
                        appId, state.files.size());
                }
            }
            LOG("[AppState] FetchCloudState app %u: migrated from legacy (CN=%llu, %zu files)",
                appId, state.cn, state.files.size());

            if (PublishCloudState(accountId, appId, state)) {
                g_stateProvider->Remove(cnPath);
                std::string manifestPath = CloudMetadataPath(accountId, appId,
                    CloudIntercept::kManifestFilename);
                g_stateProvider->Remove(manifestPath);
                std::string legacyCnPath = CloudMetadataPath(accountId, appId,
                    CloudIntercept::kLegacyCNFilename);
                std::string legacyManifestPath = CloudMetadataPath(accountId, appId,
                    CloudIntercept::kLegacyManifestFilename);
                g_stateProvider->Remove(legacyCnPath);
                g_stateProvider->Remove(legacyManifestPath);
                LOG("[AppState] FetchCloudState app %u: legacy files cleaned up", appId);
            }

            return { StateFetchStatus::Ok, std::move(state), {} };
        }

        LOG("[AppState] FetchCloudState app %u: no state file and no legacy data", appId);
        return { StateFetchStatus::NotFound, {}, {} };
    }

    LOG("[AppState] FetchCloudState app %u: download failed", appId);
    return { StateFetchStatus::FetchFailed, {}, {} };
}

bool PublishCloudState(uint32_t accountId, uint32_t appId,
                       const CloudAppState& state,
                       const std::string& /*etag*/) {
    InflightSyncScope guard;
    if (!guard) return false;
    if (!g_stateProvider || !g_stateProvider->IsAuthenticated()) {
        LOG("[AppState] PublishCloudState app %u: provider unavailable", appId);
        return false;
    }

    std::string json = SerializeState(state);
    std::string statePath = CloudMetadataPath(accountId, appId, kStateFilename);

    if (!g_stateProvider->Upload(statePath,
            reinterpret_cast<const uint8_t*>(json.data()), json.size())) {
        LOG("[AppState] PublishCloudState app %u: upload failed", appId);
        return false;
    }

    // Keep cn.cloudredirect in sync for lightweight CN probes.
    if (state.cn > 0) {
        std::string cnStr = std::to_string(state.cn);
        std::string cnPath = CloudMetadataPath(accountId, appId,
            CloudIntercept::kCNFilename);
        g_stateProvider->Upload(cnPath,
            reinterpret_cast<const uint8_t*>(cnStr.data()), cnStr.size());
    }

    LOG("[AppState] PublishCloudState app %u: published CN=%llu, %zu files",
        appId, state.cn, state.files.size());
    return true;
}

void ReleaseCloudSession(uint32_t accountId, uint32_t appId, uint64_t clientId) {
    // Sync mutex: serialize state RMW to prevent interleaved publishes.
    auto syncMtx = AcquireAppSyncMutex(accountId, appId);
    std::lock_guard<std::mutex> syncLock(*syncMtx);

    auto result = FetchCloudState(accountId, appId);
    if (result.status != StateFetchStatus::Ok) return;

    auto& state = result.state;
    if (state.session.clientId == clientId || clientId == 0) {
        // Reconcile stale file list from local manifest if previous publish failed.
        uint64_t localCN = LocalStorage::GetChangeNumber(accountId, appId);
        if (localCN > state.cn) {
            LOG("[AppState] ReleaseCloudSession app %u: local CN %llu > cloud CN %llu, reconciling file list",
                appId, (unsigned long long)localCN, (unsigned long long)state.cn);
            state.files.clear();
            auto localManifest = LoadLocalManifest(accountId, appId);
            for (const auto& [name, me] : localManifest) {
                FileEntry fe;
                fe.sha = me.sha;
                fe.timestamp = me.timestamp;
                fe.size = me.size;
                state.files[name] = std::move(fe);
            }
            state.cn = localCN;
        }

        state.session = {};
        if (!PublishCloudState(accountId, appId, state, result.etag)) {
            LOG("[AppState] ReleaseCloudSession app %u: publish failed (best-effort)", appId);
        }
        LOG("[AppState] ReleaseCloudSession app %u: session cleared (client=%llu)",
            appId, clientId);
    }
}

CloudAppState MigrateFromLegacy(uint64_t cn,
                                 const std::unordered_map<std::string, FileEntry>& legacyFiles) {
    CloudAppState state;
    state.cn = cn;
    state.files = legacyFiles;
    return state;
}

} // namespace CloudStorage

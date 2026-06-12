#include "app_state.h"
#include "cloud_storage.h"
#include "cloud_metadata_paths.h"
#include "file_util.h"
#include "json.h"
#include "local_storage.h"
#include "log.h"
#include "manifest_store.h"

#include <atomic>
#include <chrono>
#include <ctime>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>

using CloudIntercept::IsReservedBlobFilename;

namespace CloudStorage {

static ICloudProvider* g_stateProvider = nullptr;

// ---- Serve-path cloud-state cache -------------------------------------------
// Backs FetchCloudStateForServe only. FetchCloudState never reads it; it only
// refreshes it on each live fetch.
namespace {

// Staleness ceiling. Covers a download burst (serve runs right after the
// GetChangelist that warmed the cache) while bounding cross-machine staleness.
constexpr int64_t kServeCacheMaxAgeMs = 3000;

struct ServeCacheEntry {
    uint64_t cn = 0;
    int64_t  fetchedAtMs = 0;
    bool     foreignSession = false; // active session in the fetched state
    StateFetchResult result;
};

// Leaked, never-destructed: a detached bounded-fetch worker can still touch these
// during static destruction at exit, so heap-backing them (no destructor) avoids a
// UAF on a destroyed mutex/map.
std::mutex& g_serveCacheMtx = *new std::mutex();
std::unordered_map<uint64_t, ServeCacheEntry>& g_serveCache =
    *new std::unordered_map<uint64_t, ServeCacheEntry>(); // key = (acct<<32)|app

// This client's id (set by NoteOwnClientId). Used to tell our own session from a
// foreign one: only a foreign session is contention. Counting ours would disable
// the cache during the very download burst it exists for. Not latched from
// PublishCloudState -- RMW paths can republish a foreign machine's session.
std::atomic<uint64_t> g_ownClientId{0};

inline uint64_t ServeCacheKey(uint32_t accountId, uint32_t appId) {
    return (static_cast<uint64_t>(accountId) << 32) | appId;
}

inline int64_t NowMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

} // namespace

// See g_ownClientId.
void NoteOwnClientId(uint64_t clientId) {
    if (clientId != 0)
        g_ownClientId.store(clientId, std::memory_order_relaxed);
}

// Drop the cached entry for an app. Called on every local state mutation so a
// stale snapshot can never outlive a change CR itself made.
static void InvalidateServeCache(uint32_t accountId, uint32_t appId) {
    std::lock_guard<std::mutex> lk(g_serveCacheMtx);
    g_serveCache.erase(ServeCacheKey(accountId, appId));
}

// Record a live fetch for the serve path. Latest good parse normally wins (even a
// lower cn -- a legitimate rewind), but concurrent bounded fetches can finish out of
// order, so reject a lower-cn write while the existing entry is still fresh; a real
// rewind re-asserts once the duplicates quiesce.
static constexpr int64_t kConcurrentFetchWindowMs = 10000;
static void RefreshServeCache(uint32_t accountId, uint32_t appId,
                              const StateFetchResult& result) {
    if (result.status != StateFetchStatus::Ok) return; // only cache good reads
    std::lock_guard<std::mutex> lk(g_serveCacheMtx);
    uint64_t key = ServeCacheKey(accountId, appId);
    auto existing = g_serveCache.find(key);
    if (existing != g_serveCache.end() &&
        existing->second.result.status == StateFetchStatus::Ok &&
        result.state.cn < existing->second.cn &&
        (NowMs() - existing->second.fetchedAtMs) < kConcurrentFetchWindowMs) {
        return;  // older out-of-order completion -- keep the fresher higher-CN entry
    }
    ServeCacheEntry e;
    e.cn = result.state.cn;
    e.fetchedAtMs = NowMs();
    // Unknown own id (0) -> any session counts as foreign (conservative).
    uint64_t own = g_ownClientId.load(std::memory_order_relaxed);
    e.foreignSession = result.state.hasActiveSession() &&
                       result.state.session.clientId != own;
    e.result = result;
    g_serveCache[key] = std::move(e);
}

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

static StateFetchResult FetchCloudStateLive(uint32_t accountId, uint32_t appId) {
    InflightSyncScope guard;
    if (!guard) return { StateFetchStatus::FetchFailed, {} };
    if (!g_stateProvider || !g_stateProvider->IsAuthenticated())
        return { StateFetchStatus::FetchFailed, {} };

    std::string statePath = CloudMetadataPath(accountId, appId, kStateFilename);
    std::vector<uint8_t> data;
    if (g_stateProvider->Download(statePath, data)) {
        if (data.size() > MAX_STATE_SIZE) {
            LOG("[AppState] FetchCloudState app %u: state file too large (%zu bytes)",
                appId, data.size());
            return { StateFetchStatus::ParseFailed, {} };
        }
        std::string json(data.begin(), data.end());
        CloudAppState state;
        if (!DeserializeState(json, state)) {
            LOG("[AppState] FetchCloudState app %u: parse failed", appId);
            return { StateFetchStatus::ParseFailed, {} };
        }
        // cn>0 with empty files is valid (user deleted all saves).
        // AutoCloudImport repopulates from disk if local files exist.
        LOG("[AppState] FetchCloudState app %u: loaded state CN=%llu, %zu files",
            appId, state.cn, state.files.size());
        return { StateFetchStatus::Ok, std::move(state) };
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
                    FileEntry fe;
                    fe.sha = me.sha;
                    fe.timestamp = me.timestamp;
                    fe.size = me.size;
                    state.files[name] = std::move(fe);
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

            return { StateFetchStatus::Ok, std::move(state) };
        }

        LOG("[AppState] FetchCloudState app %u: no state file and no legacy data", appId);
        return { StateFetchStatus::NotFound, {} };
    }

    LOG("[AppState] FetchCloudState app %u: download failed", appId);
    return { StateFetchStatus::FetchFailed, {} };
}

// Public always-fresh fetch. Performs the live read AND refreshes the serve
// cache so the serve path always sees CR's most recent observation.
StateFetchResult FetchCloudState(uint32_t accountId, uint32_t appId) {
    StateFetchResult result = FetchCloudStateLive(accountId, appId);
    RefreshServeCache(accountId, appId, result);
    return result;
}

// Bounded-fetch coordination. The changelist RPC runs sequentially per app on the
// main-loop thread, so N timeouts would sum past the 15s watchdog -- the circuit
// breaker serves local immediately after the first timeout. Per-app dedup + a worker
// cap bound the thread count.
// Leaked, never-destructed (same reason as g_serveCache*): the detached worker
// re-locks g_boundedMtx on completion, possibly during static destruction.
static std::mutex& g_boundedMtx = *new std::mutex();
static std::unordered_set<uint64_t>& g_boundedInflightKeys =
    *new std::unordered_set<uint64_t>();                     // apps with a live worker
static std::atomic<int> g_boundedWorkerCount{0};
static std::atomic<int64_t> g_providerSlowUntilMs{0};       // circuit-breaker deadline
static constexpr int kMaxBoundedWorkers = 4;
static constexpr int kCircuitCooldownMs = 30000;            // serve-local window after a timeout

StateFetchResult FetchCloudStateBounded(uint32_t accountId, uint32_t appId,
                                        int deadlineMs) {
    uint64_t key = ((uint64_t)accountId << 32) | appId;
    bool spawn = true;
    // Circuit open: provider recently timed out -> don't wait, serve local now.
    if (NowMs() < g_providerSlowUntilMs.load(std::memory_order_relaxed)) {
        return { StateFetchStatus::Timeout, {} };
    }
    {
        std::lock_guard<std::mutex> lk(g_boundedMtx);
        // Coalesce duplicate fetches and cap total workers; either way, don't block.
        if (g_boundedInflightKeys.count(key) ||
            g_boundedWorkerCount.load(std::memory_order_relaxed) >= kMaxBoundedWorkers) {
            spawn = false;
        } else {
            g_boundedInflightKeys.insert(key);
            g_boundedWorkerCount.fetch_add(1, std::memory_order_relaxed);
        }
    }
    if (!spawn) return { StateFetchStatus::Timeout, {} };

    // Run the blocking live fetch on a detached worker; wait up to deadlineMs. The
    // shared state outlives this call so a late completion still warms the serve
    // cache for the next changelist -- it just doesn't hold Steam's thread.
    auto promise = std::make_shared<std::promise<StateFetchResult>>();
    auto future = promise->get_future();
    std::thread([accountId, appId, key, promise]() {
            // RAII so the inflight slot is always released even if the fetch throws
            // (e.g. bad_alloc): otherwise the key/count leak wedges the worker cap, and
            // an exception escaping a std::thread entry calls std::terminate.
        struct SlotGuard {
            uint64_t key;
            ~SlotGuard() {
                std::lock_guard<std::mutex> lk(g_boundedMtx);
                g_boundedInflightKeys.erase(key);
                g_boundedWorkerCount.fetch_sub(1, std::memory_order_relaxed);
            }
        } slotGuard{key};
        try {
            StateFetchResult r = FetchCloudStateLive(accountId, appId);
            RefreshServeCache(accountId, appId, r);   // warm cache regardless of timeout
            promise->set_value(std::move(r));         // ignored if caller abandoned
        } catch (...) {
            try { promise->set_value({ StateFetchStatus::FetchFailed, {} }); } catch (...) {}
        }
    }).detach();

    if (future.wait_for(std::chrono::milliseconds(deadlineMs)) ==
        std::future_status::ready) {
        return future.get();
    }
    // Timed out: open the circuit so the rest of this changelist burst serves local
    // immediately instead of each waiting another full deadline.
    g_providerSlowUntilMs.store(NowMs() + kCircuitCooldownMs, std::memory_order_relaxed);
    LOG("[AppState] FetchCloudStateBounded app %u: provider exceeded %dms -- serving "
        "local, circuit open %dms, background fetch continues",
        appId, deadlineMs, kCircuitCooldownMs);
    return { StateFetchStatus::Timeout, {} };
}

// Serve-path accessor: reuse a recent snapshot when provably safe, else live.
StateFetchResult FetchCloudStateForServe(uint32_t accountId, uint32_t appId) {
    {
        std::lock_guard<std::mutex> lk(g_serveCacheMtx);
        auto it = g_serveCache.find(ServeCacheKey(accountId, appId));
        if (it != g_serveCache.end()) {
            const ServeCacheEntry& e = it->second;
            int64_t ageMs = NowMs() - e.fetchedAtMs;
            // Reuse only when fresh and the snapshot had no foreign session;
            // otherwise go live (under contention another machine may publish a
            // newer state at any moment).
            if (ageMs >= 0 && ageMs < kServeCacheMaxAgeMs && !e.foreignSession) {
                LOG("[AppState] FetchCloudStateForServe app %u: cache hit (CN=%llu, age=%lldms)",
                    appId, (unsigned long long)e.cn, (long long)ageMs);
                return e.result;
            }
        }
    }
    // Miss / stale / contention -> authoritative live fetch (also refreshes cache).
    return FetchCloudState(accountId, appId);
}

bool PublishCloudState(uint32_t accountId, uint32_t appId,
                       const CloudAppState& state, bool lockOnly) {
    InflightSyncScope guard;
    if (!guard) return false;
    if (!g_stateProvider || !g_stateProvider->IsAuthenticated()) {
        LOG("[AppState] PublishCloudState app %u: provider unavailable", appId);
        return false;
    }

    // Heal or drop any manifest entry whose blob isn't durable on the provider, so
    // we never publish a state pointing at blobs that 404 elsewhere. lockOnly skips
    // it: a session-release publish reuses the manifest CompleteBatch just verified.
    CloudAppState verified = state;
    if (!lockOnly && !VerifyAndHealManifestForPublish(accountId, appId, verified)) {
        LOG("[AppState] PublishCloudState app %u: cannot verify blobs, deferring publish", appId);
        return false;
    }

    // Refuse to move the changenumber backward, like the real server. Re-fetch the
    // cloud CN and reject a stale RMW (e.g. the session lock republish) that would
    // clobber a newer CN another machine published in the window. Equal CN is fine.
    {
        auto current = FetchCloudStateLive(accountId, appId);
        if (current.status == StateFetchStatus::Ok && current.state.cn > verified.cn) {
            LOG("[AppState] PublishCloudState app %u: REFUSED -- cloud CN=%llu is newer than "
                "publish CN=%llu (would regress changelist); leaving cloud state intact",
                appId, (unsigned long long)current.state.cn,
                (unsigned long long)verified.cn);
            return false;
        }
    }

    std::string json = SerializeState(verified);
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

    // A local mutation just landed: the serve cache's snapshot is now stale.
    // Drop it so the next serve read re-fetches (and re-warms with the new cn).
    InvalidateServeCache(accountId, appId);

    LOG("[AppState] PublishCloudState app %u: published CN=%llu, %zu files",
        appId, verified.cn, verified.files.size());
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
        // Only release the lock; the file list and CN were already committed by the
        // upload batch. Don't rebuild the manifest from local blobs here -- that
        // advertises files before their blobs are durably uploaded.
        state.session = {};
        if (!PublishCloudState(accountId, appId, state, /*lockOnly=*/true)) {
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

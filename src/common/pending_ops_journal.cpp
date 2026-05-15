#include "pending_ops_journal.h"

#include "file_util.h"
#include "json.h"
#include "log.h"

#include <algorithm>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>

namespace PendingOpsJournal {
namespace {

std::string g_root;
std::mutex g_mutex;

std::string WithTrailingSep(std::string path) {
    if (path.empty()) return path;
#ifdef _WIN32
    if (path.back() != '\\') path.push_back('\\');
#else
    if (path.back() != '/') path.push_back('/');
#endif
    return path;
}

std::string PendingPath(uint32_t accountId, uint32_t appId) {
    return g_root + std::to_string(accountId) + "/" + std::to_string(appId) + "/pending_ops.cloudredirect";
}

Json::Value EntryToJson(const Entry& entry) {
    Json::Value obj = Json::Object();
    obj.objVal["operation"] = Json::Number(static_cast<double>(static_cast<uint32_t>(entry.operation)));
    obj.objVal["machine_name"] = Json::String(entry.machineName);
    obj.objVal["client_id"] = Json::String(std::to_string(entry.clientId));
    obj.objVal["time_last_updated"] = Json::Number(static_cast<double>(entry.timeLastUpdated));
    obj.objVal["os_type"] = Json::Number(static_cast<double>(entry.osType));
    obj.objVal["device_type"] = Json::Number(static_cast<double>(entry.deviceType));
    return obj;
}

Entry EntryFromJson(const Json::Value& value) {
    Entry entry;
    if (value.type != Json::Type::Object) return entry;
    if (value.has("operation")) entry.operation = static_cast<Operation>(value["operation"].integer());
    if (value.has("machine_name")) entry.machineName = value["machine_name"].str();
    if (value.has("client_id")) {
        try {
            entry.clientId = std::stoull(value["client_id"].str());
        } catch (...) {
            entry.clientId = 0;
        }
    }
    if (value.has("time_last_updated")) entry.timeLastUpdated = static_cast<uint32_t>(value["time_last_updated"].integer());
    if (value.has("os_type")) entry.osType = static_cast<uint32_t>(value["os_type"].integer());
    if (value.has("device_type")) entry.deviceType = static_cast<uint32_t>(value["device_type"].integer());
    return entry;
}

bool IsRemotePendingOperation(Operation operation) {
    return operation != Operation::AppSessionActive;
}

bool IsUploadOperation(Operation operation) {
    return operation == Operation::UploadInProgress ||
           operation == Operation::UploadPending;
}

Json::Value BuildRootValue(const std::vector<Entry>& entries,
                          const std::optional<Entry>& currentSession) {
    Json::Value root = Json::Object();
    Json::Value arr = Json::Array();
    for (const auto& entry : entries) arr.arrVal.push_back(EntryToJson(entry));
    root.objVal["pending_remote_operations"] = std::move(arr);
    if (currentSession.has_value()) {
        root.objVal["current_session"] = EntryToJson(*currentSession);
    }
    return root;
}

std::vector<Entry> LoadEntriesUnlocked(uint32_t accountId, uint32_t appId,
                                       std::optional<Entry>* currentSession = nullptr) {
    std::ifstream in(FileUtil::Utf8ToPath(PendingPath(accountId, appId)), std::ios::binary);
    if (!in) return {};

    std::string json((std::istreambuf_iterator<char>(in)), {});
    auto parsed = Json::Parse(json);
    if (parsed.type != Json::Type::Object) return {};
    if (currentSession && parsed.has("current_session")) {
        *currentSession = EntryFromJson(parsed["current_session"]);
    }
    if (!parsed.has("pending_remote_operations")) return {};
    const auto& arr = parsed["pending_remote_operations"];
    if (arr.type != Json::Type::Array) return {};

    std::vector<Entry> out;
    for (const auto& item : arr.arrVal) out.push_back(EntryFromJson(item));
    return out;
}

bool SaveStateUnlocked(uint32_t accountId, uint32_t appId,
                       const std::vector<Entry>& entries,
                       const std::optional<Entry>& currentSession) {
    if (entries.empty() && !currentSession.has_value()) {
        std::error_code ec;
        std::filesystem::remove(FileUtil::Utf8ToPath(PendingPath(accountId, appId)), ec);
        return true;
    }

    std::string path = PendingPath(accountId, appId);
    std::error_code ec;
    std::filesystem::create_directories(FileUtil::Utf8ToPath(path).parent_path(), ec);
    if (ec) {
        LOG("[Journal] Cannot create directory for %s: %s",
            path.c_str(), ec.message().c_str());
        return false;
    }
    return FileUtil::AtomicWriteText(path,
        Json::Stringify(BuildRootValue(entries, currentSession)));
}

void ReplaceOrAppendOperation(std::vector<Entry>& entries, const Entry& entry) {
    for (auto& existing : entries) {
        if (existing.operation == entry.operation) {
            existing = entry;
            return;
        }
    }
    entries.push_back(entry);
}

void RemoveOperation(std::vector<Entry>& entries, Operation operation) {
    entries.erase(std::remove_if(entries.begin(), entries.end(),
        [operation](const Entry& entry) {
            return entry.operation == operation;
        }), entries.end());
}

void RemoveUploadOperations(std::vector<Entry>& entries) {
    entries.erase(std::remove_if(entries.begin(), entries.end(),
        [](const Entry& entry) {
            return IsUploadOperation(entry.operation);
        }), entries.end());
}

Entry BuildDerivedEntry(const Entry& base, Operation operation) {
    Entry entry = base;
    entry.operation = operation;
    entry.timeLastUpdated = static_cast<uint32_t>(std::time(nullptr));
    return entry;
}

bool SaveEntries(uint32_t accountId, uint32_t appId, const std::vector<Entry>& entries) {
    return SaveStateUnlocked(accountId, appId, entries, std::nullopt);
}

} // namespace

void Init(const std::string& root) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_root = WithTrailingSep(root);
}

void RecordPending(uint32_t accountId, uint32_t appId,
                   const std::vector<Entry>& entries) {
    std::lock_guard<std::mutex> lock(g_mutex);
    SaveEntries(accountId, appId, entries);
}

std::vector<Entry> RecordLaunchIntent(uint32_t accountId, uint32_t appId,
                                      const Entry& currentSession,
                                      bool ignorePendingOperations) {
    std::lock_guard<std::mutex> lock(g_mutex);
    std::optional<Entry> previousSession;
    auto entries = LoadEntriesUnlocked(accountId, appId, &previousSession);

    std::vector<Entry> returnedPending;
    if (previousSession.has_value() &&
        previousSession->operation == Operation::AppSessionActive) {
        returnedPending.push_back(*previousSession);
    }
    std::vector<Entry> persistedPending;
    persistedPending.reserve(entries.size());
    for (const auto& entry : entries) {
        if (IsRemotePendingOperation(entry.operation)) {
            if (!ignorePendingOperations) {
                returnedPending.push_back(entry);
                persistedPending.push_back(entry);
            }
        }
    }

    std::optional<Entry> nextSession = currentSession;
    nextSession->operation = Operation::AppSessionActive;
    nextSession->timeLastUpdated = static_cast<uint32_t>(std::time(nullptr));

    SaveStateUnlocked(accountId, appId, persistedPending, nextSession);
    return returnedPending;
}

void RecordUploadBatchStart(uint32_t accountId, uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_mutex);
    std::optional<Entry> currentSession;
    auto entries = LoadEntriesUnlocked(accountId, appId, &currentSession);
    if (!currentSession.has_value()) {
        currentSession = Entry{};
        LOG("[Journal] WARNING: RecordUploadBatchStart app %u with no current session -- synthesizing",
            appId);
    }

    // Only clear upload operations belonging to this session's clientId.
    if (currentSession.has_value()) {
        if (currentSession->clientId != 0) {
            entries.erase(std::remove_if(entries.begin(), entries.end(),
                [cid = currentSession->clientId](const Entry& e) {
                    return IsUploadOperation(e.operation) && e.clientId == cid;
                }), entries.end());
        } else {
            // Synthesized session has no clientId to scope to; clear all upload ops.
            RemoveUploadOperations(entries);
        }
    }
    ReplaceOrAppendOperation(entries,
        BuildDerivedEntry(*currentSession, Operation::UploadInProgress));
    SaveStateUnlocked(accountId, appId, entries, currentSession);
}

void RecordUploadBatchInterrupted(uint32_t accountId, uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_mutex);
    std::optional<Entry> currentSession;
    auto entries = LoadEntriesUnlocked(accountId, appId, &currentSession);

    std::optional<Entry> pendingSeed;
    for (const auto& entry : entries) {
        if (entry.operation == Operation::UploadInProgress) {
            pendingSeed = entry;
            break;
        }
    }
    if (!pendingSeed.has_value()) {
        for (const auto& entry : entries) {
            if (entry.operation == Operation::UploadPending) {
                pendingSeed = entry;
                break;
            }
        }
    }
    if (!pendingSeed.has_value() && currentSession.has_value()) {
        pendingSeed = *currentSession;
    }

    RemoveOperation(entries, Operation::UploadInProgress);
    if (pendingSeed.has_value()) {
        ReplaceOrAppendOperation(entries,
            BuildDerivedEntry(*pendingSeed, Operation::UploadPending));
    }
    SaveStateUnlocked(accountId, appId, entries, currentSession);
}

void RecordUploadBatchEnd(uint32_t accountId, uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_mutex);
    std::optional<Entry> currentSession;
    auto entries = LoadEntriesUnlocked(accountId, appId, &currentSession);
    RemoveOperation(entries, Operation::UploadInProgress);
    SaveStateUnlocked(accountId, appId, entries, currentSession);
}

void RecordSuspendState(uint32_t accountId, uint32_t appId,
                        const Entry& session, bool uploadsCompleted) {
    std::lock_guard<std::mutex> lock(g_mutex);
    std::optional<Entry> currentSession = session;
    currentSession->operation = Operation::AppSessionSuspended;
    currentSession->timeLastUpdated = static_cast<uint32_t>(std::time(nullptr));

    auto entries = LoadEntriesUnlocked(accountId, appId);
    RemoveOperation(entries, Operation::AppSessionSuspended);
    RemoveOperation(entries, Operation::AppSessionActive);
    // Only clear upload operations belonging to this session's clientId.
    entries.erase(std::remove_if(entries.begin(), entries.end(),
        [&session](const Entry& e) {
            return IsUploadOperation(e.operation) && e.clientId == session.clientId;
        }), entries.end());
    ReplaceOrAppendOperation(entries,
        BuildDerivedEntry(*currentSession, Operation::AppSessionSuspended));
    if (!uploadsCompleted) {
        // Use the original session's clientId so resume can find and clear this entry.
        Entry uploadPendingEntry = session;
        uploadPendingEntry.operation = Operation::UploadPending;
        uploadPendingEntry.timeLastUpdated = static_cast<uint32_t>(std::time(nullptr));
        ReplaceOrAppendOperation(entries, uploadPendingEntry);
    }
    SaveStateUnlocked(accountId, appId, entries, currentSession);
}

void RecordResumeState(uint32_t accountId, uint32_t appId,
                       uint64_t clientId) {
    std::lock_guard<std::mutex> lock(g_mutex);
    std::optional<Entry> currentSession;
    auto entries = LoadEntriesUnlocked(accountId, appId, &currentSession);
    if (!currentSession.has_value()) {
        currentSession = Entry{};
        currentSession->machineName = "(recovered)";
    }
    // Capture old clientId before updating — suspend writes UploadPending
    // entries with the pre-suspend clientId, so resume must clear both.
    uint64_t oldClientId = currentSession->clientId;
    if (clientId != 0) currentSession->clientId = clientId;
    currentSession->operation = Operation::AppSessionActive;
    currentSession->timeLastUpdated = static_cast<uint32_t>(std::time(nullptr));
    RemoveOperation(entries, Operation::AppSessionSuspended);
    // Resume clears upload-pending entries for THIS session (old or new clientId).
    entries.erase(std::remove_if(entries.begin(), entries.end(),
        [clientId, oldClientId](const Entry& e) {
            return IsUploadOperation(e.operation) &&
                   (e.clientId == clientId || e.clientId == oldClientId);
        }), entries.end());
    RemoveOperation(entries, Operation::UploadInProgress);
    SaveStateUnlocked(accountId, appId, entries, currentSession);
}

void RecordExitSyncState(uint32_t accountId, uint32_t appId,
                         bool uploadsCompleted, bool uploadsRequired,
                         uint64_t clientId) {
    std::lock_guard<std::mutex> lock(g_mutex);
    std::optional<Entry> currentSession;
    auto entries = LoadEntriesUnlocked(accountId, appId, &currentSession);

    RemoveOperation(entries, Operation::AppSessionSuspended);
    RemoveOperation(entries, Operation::AppSessionActive);
    RemoveOperation(entries, Operation::UploadInProgress);
    RemoveOperation(entries, Operation::UploadPending);

    if (uploadsCompleted || !uploadsRequired) {
        SaveStateUnlocked(accountId, appId, entries, std::nullopt);
        return;
    }

    Entry seed = currentSession.value_or(Entry{});
    seed.clientId = clientId != 0 ? clientId : seed.clientId;
    ReplaceOrAppendOperation(entries, BuildDerivedEntry(seed, Operation::UploadPending));
    SaveStateUnlocked(accountId, appId, entries, std::nullopt);
}

std::vector<Entry> LoadPending(uint32_t accountId, uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_mutex);
    return LoadEntriesUnlocked(accountId, appId);
}

std::optional<Entry> LoadCurrentSession(uint32_t accountId, uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_mutex);
    std::optional<Entry> currentSession;
    LoadEntriesUnlocked(accountId, appId, &currentSession);
    return currentSession;
}

void ClearPending(uint32_t accountId, uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_mutex);
    SaveStateUnlocked(accountId, appId, {}, std::nullopt);
}

} // namespace PendingOpsJournal

#include "cloud_staging.h"

#include "cloud_metadata_paths.h"
#include "pending_ops_journal.h"

#include <limits>

namespace CloudStorage {
namespace {

bool ParseU32Strict(const std::string& s, uint32_t& out) {
    if (s.empty()) return false;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
    }
    try {
        unsigned long long v = std::stoull(s);
        if (v > (std::numeric_limits<uint32_t>::max)()) return false;
        out = static_cast<uint32_t>(v);
        return true;
    } catch (...) {
        return false;
    }
}

bool IsStagingBlobPath(uint32_t accountId, const std::string& path) {
    size_t p1 = path.find('/');
    if (p1 == std::string::npos || p1 == 0) return false;
    uint32_t parsedAccount = 0;
    if (!ParseU32Strict(path.substr(0, p1), parsedAccount)) return false;
    if (parsedAccount != accountId) return false;

    size_t p2 = path.find('/', p1 + 1);
    if (p2 == std::string::npos || p2 == p1 + 1) return false;
    uint32_t parsedApp = 0;
    if (!ParseU32Strict(path.substr(p1 + 1, p2 - p1 - 1), parsedApp)) return false;

    const std::string staging = "/staging/";
    if (path.compare(p2, staging.size(), staging) != 0) return false;
    size_t batchStart = p2 + staging.size();
    size_t batchEnd = path.find('/', batchStart);
    if (batchEnd == std::string::npos || batchEnd == batchStart) return false;
    uint32_t parsedBatch = 0;
    if (!ParseU32Strict(path.substr(batchStart, batchEnd - batchStart), parsedBatch)) return false;

    const std::string blobs = "/blobs/";
    if (path.compare(batchEnd, blobs.size(), blobs) != 0) return false;
    return batchEnd + blobs.size() < path.size();
}

bool HasInterruptedUploadState(uint32_t accountId, uint32_t appId) {
    auto pending = PendingOpsJournal::LoadPending(accountId, appId);
    for (const auto& entry : pending) {
        if (entry.operation == PendingOpsJournal::Operation::UploadInProgress ||
            entry.operation == PendingOpsJournal::Operation::UploadPending) {
            return true;
        }
    }
    return false;
}

bool ManifestsMatch(const Manifest& lhs, const Manifest& rhs) {
    if (lhs.size() != rhs.size()) return false;
    for (const auto& [filename, leftEntry] : lhs) {
        auto it = rhs.find(filename);
        if (it == rhs.end()) return false;
        const auto& rightEntry = it->second;
        if (leftEntry.timestamp != rightEntry.timestamp ||
            leftEntry.size != rightEntry.size ||
            leftEntry.sha != rightEntry.sha) {
            return false;
        }
    }
    return true;
}

} // namespace

std::vector<std::string> ClassifyStaleStagingBlobs(
    uint32_t accountId,
    const std::vector<ICloudProvider::FileInfo>& files,
    uint64_t nowUnix,
    uint64_t minAgeSeconds) {
    std::vector<std::string> stale;
    for (const auto& file : files) {
        if (!IsStagingBlobPath(accountId, file.path)) continue;
        if (file.modifiedTime == 0) continue;
        if (file.modifiedTime > nowUnix) continue;
        if (nowUnix - file.modifiedTime < minAgeSeconds) continue;
        stale.push_back(file.path);
    }
    return stale;
}

bool TryBuildCommittedInventoryForInterruptedUpload(
    uint32_t accountId,
    uint32_t appId,
    std::vector<LocalStorage::FileEntry>& outFiles,
    uint64_t& outChangeNumber) {
    outFiles.clear();
    outChangeNumber = 0;

    if (!HasInterruptedUploadState(accountId, appId)) return false;

    // Atomically transition UploadInProgress→UploadPending before any
    // filesystem work so another thread cannot clear UploadInProgress
    // underneath us.
    PendingOpsJournal::RecordUploadBatchInterrupted(accountId, appId);

    Manifest committedManifest;
    if (!TryLoadLocalManifest(accountId, appId, committedManifest)) {
        return false;
    }

    Manifest currentManifest = BuildManifestFromLocalBlobs(accountId, appId);
    if (ManifestsMatch(currentManifest, committedManifest)) {
        // No actual divergence — the journal transition was premature.
        // UploadPending created by RecordUploadBatchInterrupted has no
        // UploadInProgress to pair with; clear it to break the recovery loop.
        PendingOpsJournal::ClearPending(accountId, appId);
        return false;
    }

    outChangeNumber = LocalStorage::GetChangeNumber(accountId, appId);
    for (const auto& [filename, entry] : committedManifest) {
        if (CloudIntercept::IsInternalMetadataFile(filename)) continue;

        LocalStorage::FileEntry fe;
        fe.filename = filename;
        fe.sha = entry.sha;
        fe.timestamp = entry.timestamp;
        fe.rawSize = entry.size;
        fe.deleted = false;
        outFiles.push_back(std::move(fe));
    }

    return true;
}

} // namespace CloudStorage

#include "batch_merge.h"
#include "cloud_metadata_paths.h"

namespace CloudIntercept {

std::unordered_map<std::string, CloudStorage::FileEntry> MergeBatchIntoPublishState(
    std::unordered_map<std::string, CloudStorage::FileEntry> cloudFiles,
    const BatchMergeInputs& in) {
    // Keep local-only files when local is ahead, without overwriting cloud.
    if (in.cloudCn < in.localCn) {
        for (const auto& [name, me] : in.localManifest) {
            if (cloudFiles.count(name)) continue;
            CloudStorage::FileEntry fe;
            fe.sha = me.sha;
            fe.timestamp = me.timestamp;
            fe.size = me.size;
            cloudFiles[name] = std::move(fe);
        }
    }
    for (const auto& filename : in.deletes)
        cloudFiles.erase(filename);
    for (const auto& filename : in.uploads) {
        if (IsReservedBlobFilename(filename)) continue;
        CloudStorage::FileEntry fe;
        auto metaIt = in.uploadMeta.find(filename);
        if (metaIt != in.uploadMeta.end()) {
            fe.sha = metaIt->second.sha;
            fe.timestamp = metaIt->second.timestamp;
            fe.size = metaIt->second.size;
        }
        auto ptIt = in.filePlatforms.find(filename);
        fe.platformsToSync = (ptIt != in.filePlatforms.end())
            ? ptIt->second : 0xFFFFFFFFu;
        cloudFiles[filename] = std::move(fe);
    }
    return cloudFiles;
}

} // namespace CloudIntercept

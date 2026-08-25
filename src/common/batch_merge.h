#pragma once
// Applies a batch's upload/delete operations onto the cloud file map.

#include "app_state.h"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace CloudIntercept {

// Platform-free subset of ManifestEntry for merge inputs.
struct BatchFileMeta {
    std::vector<uint8_t> sha;
    uint64_t timestamp = 0;
    uint64_t size = 0;
};

struct BatchMergeInputs {
    uint64_t cloudCn = 0;
    uint64_t localCn = 0;
    std::unordered_map<std::string, BatchFileMeta> localManifest;
    std::vector<std::string> deletes;
    std::vector<std::string> uploads;
    // filename -> {sha,timestamp,size} for uploads (authoritative upload meta).
    std::unordered_map<std::string, BatchFileMeta> uploadMeta;
    // filename -> platform bitmask for uploads (absent => 0xFFFFFFFF).
    std::unordered_map<std::string, uint32_t> filePlatforms;
};

std::unordered_map<std::string, CloudStorage::FileEntry> MergeBatchIntoPublishState(
    std::unordered_map<std::string, CloudStorage::FileEntry> cloudFiles,
    const BatchMergeInputs& in);

} // namespace CloudIntercept

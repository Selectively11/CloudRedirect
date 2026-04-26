#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace CloudIntercept {

// One synthesized remotecache.vdf row.
struct RemotecacheCandidate {
    std::string cleanName;     // e.g. "UnderTheIsland/save_data_01.ini"
    std::string token;         // e.g. "%WinAppDataLocal%" or empty for default
    std::vector<uint8_t> sha;  // 20 bytes SHA1 of the cloud blob (may be empty)
    uint64_t timestamp = 0;
    uint64_t rawSize = 0;
};

// Map a wire root token like "%WinAppDataLocal%" to Steam's
// ERemoteStorageFileRoot numeric id. Returns 0 (k_eFileRootDefault) for empty
// or unknown tokens.
uint32_t TokenToRootId(const std::string& token);

// Pure transform: given existing remotecache.vdf text and a candidate list for
// `appId`, return the rewritten text and how many new entries were added.
// Existing entries are never modified -- Steam owns their lifecycle. Returns
// false if `original` lacks the expected top-level "<appId>" section, in which
// case `outRepaired` is left equal to `original` and `outAdded == 0`.
bool ApplyRemotecacheRepair(const std::string& original,
                            uint32_t appId,
                            const std::vector<RemotecacheCandidate>& candidates,
                            std::string& outRepaired,
                            size_t& outAdded);

} // namespace CloudIntercept

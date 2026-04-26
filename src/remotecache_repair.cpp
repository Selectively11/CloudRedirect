#include "remotecache_repair.h"
#include "steam_root_ids.h"
#include "vdf.h"

#include <unordered_set>

namespace CloudIntercept {

uint32_t TokenToRootId(const std::string& token) {
    if (token.empty()) return 0;
    for (const auto& e : SteamRootIds::kEntries) {
        if (token == e.token) return e.rootId;
    }
    return 0;  // k_eFileRootDefault
}

static std::string ShaToHex(const std::vector<uint8_t>& sha) {
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(sha.size() * 2);
    for (size_t i = 0; i < sha.size(); ++i) {
        out[2 * i]     = kHex[(sha[i] >> 4) & 0xF];
        out[2 * i + 1] = kHex[sha[i] & 0xF];
    }
    return out;
}

bool ApplyRemotecacheRepair(const std::string& original,
                            uint32_t appId,
                            const std::vector<RemotecacheCandidate>& candidates,
                            std::string& outRepaired,
                            size_t& outAdded) {
    outRepaired = original;
    outAdded = 0;
    if (candidates.empty()) return true;

    std::string appIdStr = std::to_string(appId);
    const char* topSection = appIdStr.c_str();
    size_t sectionStart = 0;
    size_t sectionEnd = 0;
    if (!VdfUtil::FindVdfSectionRange(outRepaired, &topSection, 1, sectionStart, sectionEnd)) {
        return false;
    }

    // Enumerate every direct child of the appid section: both scalar fields
    // ("ChangeNumber" "42") AND sub-section headers ("<filename>" { ... }).
    // File entries in remotecache.vdf are sub-sections, so ForEachChildInSection
    // (which reports both kinds) is the primitive we need here --
    // ForEachFieldInSection would skip file headers entirely.
    std::unordered_set<std::string> existing;
    VdfUtil::ForEachChildInSection(outRepaired, &topSection, 1,
        [&](std::string_view name) {
            existing.emplace(name);
            return true;
        });

    std::string insertions;
    for (const auto& c : candidates) {
        if (existing.count(c.cleanName)) continue;
        if (c.cleanName.empty()) continue;

        uint32_t rootId = TokenToRootId(c.token);
        std::string shaHex = c.sha.size() == 20 ? ShaToHex(c.sha) : std::string();

        // Match Steam's own field formatting: tab indent, double tab between
        // key and value, LF line endings. Steam reads CRLF too but writes LF;
        // matching its style avoids gratuitous diff churn on the file.
        insertions += "\t\"" + c.cleanName + "\"\n";
        insertions += "\t{\n";
        insertions += "\t\t\"root\"\t\t\"" + std::to_string(rootId) + "\"\n";
        insertions += "\t\t\"size\"\t\t\"" + std::to_string(c.rawSize) + "\"\n";
        insertions += "\t\t\"localtime\"\t\t\"" + std::to_string(c.timestamp) + "\"\n";
        insertions += "\t\t\"time\"\t\t\"" + std::to_string(c.timestamp) + "\"\n";
        insertions += "\t\t\"remotetime\"\t\t\"" + std::to_string(c.timestamp) + "\"\n";
        if (!shaHex.empty()) {
            insertions += "\t\t\"sha\"\t\t\"" + shaHex + "\"\n";
        }
        insertions += "\t\t\"syncstate\"\t\t\"1\"\n";          // synced
        insertions += "\t\t\"persiststate\"\t\t\"0\"\n";       // persisted
        insertions += "\t\t\"platformstosync2\"\t\t\"-1\"\n";  // all
        insertions += "\t}\n";
        ++outAdded;
    }

    if (outAdded == 0) return true;
    outRepaired.insert(sectionEnd, insertions);
    return true;
}

} // namespace CloudIntercept

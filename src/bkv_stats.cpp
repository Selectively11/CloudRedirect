// Upload-side predicate: rejects empty cache{crc,PendingChanges}+END skeletons
// and all-zero-data blobs so UploadStatsOnExit can't clobber a richer cloud copy.
// Reader mirrors BkvRead in rpc_handlers.cpp; keep them in sync.

#include "rpc_handlers.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace CloudIntercept {
namespace {

enum BkvType : uint8_t {
    BKV_SECTION = 0x00,
    BKV_STRING  = 0x01,
    BKV_INT     = 0x02,
    BKV_FLOAT   = 0x03,
    BKV_UINT64  = 0x07,
    BKV_END     = 0x08,
    BKV_INT64   = 0x0A,
};

struct BkvNode {
    BkvType type;
    std::string name;
    uint32_t intVal = 0;
    float floatVal = 0.0f;
    uint64_t uint64Val = 0;
    int64_t int64Val = 0;
    std::string strVal;
    std::vector<BkvNode> children;
};

constexpr int    BKV_MAX_DEPTH = 128;
constexpr size_t BKV_MAX_NODES = 100000;

bool BkvRead(const uint8_t* data, size_t len, size_t& pos,
             std::vector<BkvNode>& out, int depth, size_t& totalNodes) {
    if (depth > BKV_MAX_DEPTH) return false;
    while (pos < len) {
        uint8_t tag = data[pos++];
        if (tag == BKV_END) return true;

        BkvNode node;
        node.type = static_cast<BkvType>(tag);

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
                std::memcpy(&node.intVal, data + pos, 4);
            else
                std::memcpy(&node.floatVal, data + pos, 4);
            pos += 4;
            break;
        case BKV_UINT64:
            if (pos + 8 > len) return false;
            std::memcpy(&node.uint64Val, data + pos, 8);
            pos += 8;
            break;
        case BKV_INT64:
            if (pos + 8 > len) return false;
            std::memcpy(&node.int64Val, data + pos, 8);
            pos += 8;
            break;
        default:
            return false;
        }
        if (++totalNodes > BKV_MAX_NODES) return false;
        out.push_back(std::move(node));
    }
    return depth == 0;
}

bool HasNonZeroStatsData(const std::vector<BkvNode>& nodes) {
    for (const auto& n : nodes) {
        if (n.name == "data") {
            if (n.type == BKV_INT && n.intVal != 0) return true;
            if (n.type == BKV_FLOAT && n.floatVal != 0.0f) return true;
            if (n.type == BKV_UINT64 && n.uint64Val != 0) return true;
            if (n.type == BKV_INT64 && n.int64Val != 0) return true;
        }
        if (!n.children.empty() && HasNonZeroStatsData(n.children)) return true;
    }
    return false;
}

} // namespace

bool StatsBlobHasUnlocks(const uint8_t* data, size_t len) {
    if (!data || len == 0) return false;
    size_t pos = 0;
    size_t nodeCount = 0;
    std::vector<BkvNode> nodes;
    if (!BkvRead(data, len, pos, nodes, 0, nodeCount)) return false;
    return HasNonZeroStatsData(nodes);
}

} // namespace CloudIntercept

#include "vdf.h"

namespace VdfUtil {

bool ForEachFieldInSection(const std::string& vdfContent,
                           const char* const* sectionPath, int pathLen,
                           FieldCallback cb) {
    int targetDepth = 0;
    int depth = 0;
    bool inTarget = false;
    int targetBase = 0;

    size_t pos = 0;
    while (pos < vdfContent.size()) {
        size_t lineEnd = vdfContent.find('\n', pos);
        if (lineEnd == std::string::npos) lineEnd = vdfContent.size();

        std::string_view lineView(vdfContent.data() + pos, lineEnd - pos);
        size_t ls = lineView.find_first_not_of(" \t\r\n");
        if (ls != std::string_view::npos) {
            std::string_view trimmed = lineView.substr(ls);

            if (trimmed == "{") {
                depth++;
            } else if (trimmed == "}") {
                if (inTarget && depth == targetBase) return true;
                depth--;
                if (!inTarget && targetDepth > 0 && depth < targetDepth)
                    targetDepth = depth;
            } else if (trimmed.size() >= 3 && trimmed[0] == '"') {
                size_t keyEnd = trimmed.find('"', 1);
                if (keyEnd != std::string_view::npos) {
                    std::string_view key = trimmed.substr(1, keyEnd - 1);

                    if (inTarget) {
                        size_t vq1 = trimmed.find('"', keyEnd + 1);
                        if (vq1 != std::string_view::npos) {
                            size_t vq2 = trimmed.find('"', vq1 + 1);
                            if (vq2 != std::string_view::npos) {
                                std::string_view val = trimmed.substr(vq1 + 1, vq2 - vq1 - 1);
                                size_t trimStart = pos + ls;
                                size_t valAbsStart = trimStart + vq1 + 1;
                                size_t valAbsEnd = trimStart + vq2;

                                FieldInfo fi{key, val, valAbsStart, valAbsEnd};
                                if (!cb(fi)) return true;
                            }
                        }
                    } else if (targetDepth < pathLen && key == sectionPath[targetDepth]) {
                        targetDepth++;
                        if (targetDepth == pathLen) {
                            inTarget = true;
                            targetBase = depth + 1;
                        }
                    }
                }
            }
        }

        pos = lineEnd + 1;
    }

    return inTarget;
}

} // namespace VdfUtil

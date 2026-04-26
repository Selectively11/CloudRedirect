#include "vdf.h"

namespace VdfUtil {

// Strip a single trailing '\r' from a line-slice so downstream literal
// comparisons (e.g. trimmed == "{") don't spuriously fail on CRLF input. Our
// ifstream reads use text mode which would normally translate CRLF->LF, but
// callers of the pure APIs (unit tests, in-memory fixtures, third-party
// readers) may pass raw CRLF; tolerating it here keeps the parser contract
// uniform.
static std::string_view StripCR(std::string_view s) {
    if (!s.empty() && s.back() == '\r') s.remove_suffix(1);
    return s;
}

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
            std::string_view trimmed = StripCR(lineView.substr(ls));

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
                    } else if (targetDepth < pathLen && depth == targetDepth && key == sectionPath[targetDepth]) {
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

bool FindVdfSectionRange(const std::string& vdfContent,
                         const char* const* sectionPath, size_t pathLen,
                         size_t& sectionStart, size_t& sectionEnd) {
    if (pathLen == 0) return false;

    size_t searchPos = 0;
    for (size_t i = 0; i < pathLen; ++i) {
        const std::string needle = std::string("\"") + sectionPath[i] + "\"";

        // Anchored header search: require the needle to start at column 0 or
        // immediately after a line-ending byte. Without this, a value like
        // "version" "1583520" earlier in the file could spuriously match the
        // "1583520" section header, shifting sectionStart/sectionEnd onto an
        // unrelated brace pair.
        size_t namePos = std::string::npos;
        size_t scan = searchPos;
        while (scan < vdfContent.size()) {
            size_t hit = vdfContent.find(needle, scan);
            if (hit == std::string::npos) break;
            if (hit == 0 || vdfContent[hit - 1] == '\n' || vdfContent[hit - 1] == '\r') {
                namePos = hit;
                break;
            }
            scan = hit + 1;
        }
        if (namePos == std::string::npos) return false;

        size_t openBrace = vdfContent.find('{', namePos + needle.size());
        if (openBrace == std::string::npos) return false;

        searchPos = openBrace + 1;
        if (i + 1 == pathLen) {
            sectionStart = openBrace + 1;
            int depth = 1;
            for (size_t p = openBrace + 1; p < vdfContent.size(); ++p) {
                if (vdfContent[p] == '{') ++depth;
                else if (vdfContent[p] == '}') {
                    --depth;
                    if (depth == 0) {
                        sectionEnd = p;
                        return true;
                    }
                }
            }
            return false;
        }
    }
    return false;
}

bool ForEachChildInSection(const std::string& vdfContent,
                           const char* const* sectionPath, size_t pathLen,
                           ChildCallback cb) {
    size_t sectionStart = 0;
    size_t sectionEnd = 0;
    if (!FindVdfSectionRange(vdfContent, sectionPath, pathLen, sectionStart, sectionEnd)) {
        return false;
    }

    int depth = 0;
    std::string pendingKey;  // armed by a header-only line, consumed by '{'.
    size_t pos = sectionStart;
    while (pos < sectionEnd) {
        size_t lineEnd = vdfContent.find('\n', pos);
        if (lineEnd == std::string::npos || lineEnd > sectionEnd) lineEnd = sectionEnd;

        std::string_view line(vdfContent.data() + pos, lineEnd - pos);
        size_t ls = line.find_first_not_of(" \t\r\n");
        if (ls != std::string_view::npos) {
            std::string_view trimmed = StripCR(line.substr(ls));

            if (trimmed == "{") {
                if (depth == 0 && !pendingKey.empty()) {
                    if (!cb(pendingKey)) return true;
                    pendingKey.clear();
                }
                ++depth;
            } else if (trimmed == "}") {
                --depth;
                pendingKey.clear();
            } else if (depth == 0 && trimmed.size() >= 3 && trimmed[0] == '"') {
                size_t keyEnd = trimmed.find('"', 1);
                if (keyEnd != std::string_view::npos) {
                    std::string_view key = trimmed.substr(1, keyEnd - 1);
                    size_t vq1 = trimmed.find('"', keyEnd + 1);
                    if (vq1 != std::string_view::npos) {
                        // Scalar field at the target depth: report the key.
                        if (!cb(key)) return true;
                        pendingKey.clear();
                    } else {
                        // Header-only line. If a previous header is still
                        // pending without an intervening '{', the file is
                        // malformed (Steam never emits two headers in a row);
                        // report the previous one anyway so callers don't
                        // silently duplicate its downstream row.
                        if (!pendingKey.empty()) {
                            if (!cb(pendingKey)) return true;
                        }
                        pendingKey.assign(key);
                    }
                }
            }
        }

        pos = lineEnd + 1;
    }

    return true;
}

} // namespace VdfUtil

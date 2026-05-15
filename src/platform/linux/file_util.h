#pragma once
// Linux file_util.h - matches Windows API surface for common/ code

#include <string>
#include <filesystem>
#include <cstdint>
#include <cstring>

namespace FileUtil {

// On Linux, paths are already UTF-8. These are identity operations.
inline std::filesystem::path Utf8ToPath(const std::string& utf8) {
    return std::filesystem::path(utf8);
}

inline std::string PathToUtf8(const std::filesystem::path& p) {
    return p.string();
}

// WideToUtf8 - no-op stubs for Linux (no wchar_t paths)
inline std::string WideToUtf8(const wchar_t* w) {
    if (!w || !*w) return {};
    std::wstring ws(w);
    return std::string(ws.begin(), ws.end()); // lossy but unused on Linux
}

inline std::string WideToUtf8(const wchar_t* w, size_t len) {
    if (!w || len == 0) return {};
    std::wstring ws(w, len);
    return std::string(ws.begin(), ws.end());
}

// Path containment check (case-sensitive on Linux)
inline bool IsPathWithin(const std::string& root, const std::string& fullPath) {
    std::error_code ec;
    auto canonRoot = std::filesystem::weakly_canonical(Utf8ToPath(root), ec);
    if (ec) return false;
    auto canonPath = std::filesystem::weakly_canonical(Utf8ToPath(fullPath), ec);
    if (ec) return false;
    std::string rootStr = canonRoot.string();
    std::string pathStr = canonPath.string();
    if (pathStr.size() < rootStr.size()) return false;
    if (strncmp(pathStr.c_str(), rootStr.c_str(), rootStr.size()) != 0) return false;
    return pathStr.size() == rootStr.size() || pathStr[rootStr.size()] == '/';
}

// Walk up from startDir removing empty dirs, bounded above by stopAt
inline void CleanupEmptyDirsUpTo(const std::string& startDir,
                                 const std::string& stopAt) {
    if (startDir.empty() || stopAt.empty()) return;
    std::error_code ec;
    auto canonStop = std::filesystem::weakly_canonical(Utf8ToPath(stopAt), ec);
    if (ec) return;
    auto cur = std::filesystem::weakly_canonical(Utf8ToPath(startDir), ec);
    if (ec) return;

    const std::string stopStr = canonStop.string();

    for (int i = 0; i < 256; ++i) {
        const std::string curStr = cur.string();
        if (curStr.size() <= stopStr.size()) break;
        if (strncmp(curStr.c_str(), stopStr.c_str(), stopStr.size()) != 0) break;
        if (curStr[stopStr.size()] != '/') break;

        ec.clear();
        bool removed = std::filesystem::remove(cur, ec);
        if (ec || !removed) break;

        if (!cur.has_parent_path()) break;
        auto parent = cur.parent_path();
        if (parent == cur) break;
        cur = std::move(parent);
    }
}

// No reparse points on Linux - always returns false
inline bool IsPathRedirectingReparsePoint(const std::string& /*path*/) {
    return false;
}

// Atomic write: write to .tmp, fsync, rename over target
bool AtomicWriteBinary(const std::string& path, const void* data, size_t len);
bool AtomicWriteText(const std::string& path, const std::string& content);

} // namespace FileUtil

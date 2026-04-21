#pragma once
// Shared file utilities: atomic writes, path traversal validation.

#include <string>
#include <fstream>
#include <filesystem>
#include <cstdint>

namespace FileUtil {

// Path containment check: returns true if `fullPath` resolves to a location
// within `root` after canonicalization. Case-insensitive on Windows.
// Used to prevent path traversal attacks across blob storage modules.
inline bool IsPathWithin(const std::string& root, const std::string& fullPath) {
    std::error_code ec;
    auto canonRoot = std::filesystem::weakly_canonical(root, ec);
    if (ec) return false;
    auto canonPath = std::filesystem::weakly_canonical(fullPath, ec);
    if (ec) return false;
    std::string rootStr = canonRoot.string();
    std::string pathStr = canonPath.string();
    if (pathStr.size() < rootStr.size()) return false;
    if (_strnicmp(pathStr.c_str(), rootStr.c_str(), rootStr.size()) != 0) return false;
    // Exact match (path == root) or next char must be a separator
    return pathStr.size() == rootStr.size() ||
           pathStr[rootStr.size()] == '\\' ||
           pathStr[rootStr.size()] == '/';
}

inline bool AtomicWriteBinary(const std::string& path, const void* data, size_t len) {
    std::string tmpPath = path + ".tmp";
    std::ofstream f(tmpPath, std::ios::binary);
    if (!f) return false;
    if (len != 0) {
        f.write(static_cast<const char*>(data), len);
    }
    if (!f.good()) {
        f.close();
        std::error_code ec;
        std::filesystem::remove(tmpPath, ec);
        return false;
    }
    f.close();
    std::error_code ec;
    std::filesystem::rename(tmpPath, path, ec);
    if (ec) {
        std::filesystem::remove(tmpPath, ec);
        return false;
    }
    return true;
}

inline bool AtomicWriteText(const std::string& path, const std::string& content) {
    std::string tmpPath = path + ".tmp";
    std::ofstream f(tmpPath, std::ios::trunc);
    if (!f) return false;
    f << content;
    if (!f.good()) {
        f.close();
        std::error_code ec;
        std::filesystem::remove(tmpPath, ec);
        return false;
    }
    f.close();
    std::error_code ec;
    std::filesystem::rename(tmpPath, path, ec);
    if (ec) {
        std::filesystem::remove(tmpPath, ec);
        return false;
    }
    return true;
}

} // namespace FileUtil

#pragma once
// Shared file utilities: atomic writes, path traversal validation.

#include <string>
#include <fstream>
#include <filesystem>
#include <cstdint>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace FileUtil {

// UTF-8 <-> std::filesystem::path bridges. All std::string paths in this
// codebase are UTF-8; MSVC's path(string)/path.string() use the active code
// page and silently mangle non-ASCII names. Always cross the boundary
// through these helpers.
inline std::string PathToUtf8(const std::filesystem::path& p) {
    const std::wstring& wide = p.native();
    if (wide.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(),
                                  nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string out((size_t)len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(),
                        out.data(), len, nullptr, nullptr);
    return out;
}

// Wide -> UTF-8 for callers holding raw wchar_t* from Win32 APIs.
// WC_ERR_INVALID_CHARS rejects lone surrogates.
inline std::string WideToUtf8(const wchar_t* w) {
    if (!w || !*w) return {};
    int len = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w, -1,
                                  nullptr, 0, nullptr, nullptr);
    if (len <= 1) return {};
    std::string s(static_cast<size_t>(len - 1), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w, -1,
                            s.data(), len, nullptr, nullptr) <= 0) {
        return {};
    }
    return s;
}

// Length-explicit overload for already-trimmed wide buffers.
inline std::string WideToUtf8(const wchar_t* w, size_t len) {
    if (!w || len == 0) return {};
    int outLen = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w, (int)len,
                                     nullptr, 0, nullptr, nullptr);
    if (outLen <= 0) return {};
    std::string s(static_cast<size_t>(outLen), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w, (int)len,
                            s.data(), outLen, nullptr, nullptr) <= 0) {
        return {};
    }
    return s;
}

inline std::filesystem::path Utf8ToPath(const std::string& utf8) {
    if (utf8.empty()) return {};
    int wideLen = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(),
                                      nullptr, 0);
    if (wideLen <= 0) return {};
    std::wstring wide((size_t)wideLen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(),
                        wide.data(), wideLen);
    return std::filesystem::path(std::move(wide));
}

// Returns true if fullPath resolves under root (case-insensitive on Windows).
// Used to block path traversal in blob-storage modules.
inline bool IsPathWithin(const std::string& root, const std::string& fullPath) {
    std::error_code ec;
    auto canonRoot = std::filesystem::weakly_canonical(Utf8ToPath(root), ec);
    if (ec) return false;
    auto canonPath = std::filesystem::weakly_canonical(Utf8ToPath(fullPath), ec);
    if (ec) return false;
    std::string rootStr = PathToUtf8(canonRoot);
    std::string pathStr = PathToUtf8(canonPath);
    if (pathStr.size() < rootStr.size()) return false;
    if (_strnicmp(pathStr.c_str(), rootStr.c_str(), rootStr.size()) != 0) return false;
    // Exact match (path == root) or next char must be a separator
    return pathStr.size() == rootStr.size() ||
           pathStr[rootStr.size()] == '\\' ||
           pathStr[rootStr.size()] == '/';
}

// Walk up from startDir removing empty dirs, bounded above by stopAt
// (exclusive). Stops at the first non-empty dir or any error. Best-effort.
inline void CleanupEmptyDirsUpTo(const std::string& startDir,
                                 const std::string& stopAt) {
    if (startDir.empty() || stopAt.empty()) return;
    std::error_code ec;
    auto canonStop = std::filesystem::weakly_canonical(Utf8ToPath(stopAt), ec);
    if (ec) return;
    auto cur = std::filesystem::weakly_canonical(Utf8ToPath(startDir), ec);
    if (ec) return;

    const std::string stopStr = PathToUtf8(canonStop);

    for (int i = 0; i < 256; ++i) {
        const std::string curStr = PathToUtf8(cur);
        if (curStr.size() <= stopStr.size()) break;
        if (_strnicmp(curStr.c_str(), stopStr.c_str(), stopStr.size()) != 0) break;
        const char sep = curStr[stopStr.size()];
        if (sep != '\\' && sep != '/') break;

        ec.clear();
        bool removed = std::filesystem::remove(cur, ec);
        if (ec || !removed) break;

        if (!cur.has_parent_path()) break;
        auto parent = cur.parent_path();
        if (parent == cur) break;
        cur = std::move(parent);
    }
}

// Returns true only for reparse tags that can redirect a recursive scan
// (NTFS junctions, symlinks). Cloud placeholders / AppExecLink / WSL / WIM
// remain false so legitimate cloud-synced saves still scan. is_symlink()
// is insufficient because MSVC classifies junctions as file_type::junction.
inline bool IsPathRedirectingReparsePoint(const std::string& path) {
    auto wpath = Utf8ToPath(path);
    if (wpath.empty()) return false;
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(wpath.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return false;
    FindClose(h);
    if ((fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0) return false;
    switch (fd.dwReserved0) {
        case IO_REPARSE_TAG_MOUNT_POINT:
        case IO_REPARSE_TAG_SYMLINK:
            return true;
        default:
            return false;
    }
}

// Write to tmp, FlushFileBuffers, then atomic rename over the target.
// FlushFileBuffers is required: a same-volume rename is metadata-only and
// MOVEFILE_WRITE_THROUGH only flushes when the move actually copies.
inline bool WriteFlushAndRename(const std::filesystem::path& pathFs,
                                const std::filesystem::path& tmpPathFs,
                                const void* data, size_t len) {
    HANDLE h = CreateFileW(tmpPathFs.c_str(),
                           GENERIC_WRITE,
                           0,
                           nullptr,
                           CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    const char* p = static_cast<const char*>(data);
    size_t remaining = len;
    while (remaining > 0) {
        DWORD chunk = remaining > 0x40000000u
                          ? 0x40000000u
                          : static_cast<DWORD>(remaining);
        DWORD written = 0;
        if (!WriteFile(h, p, chunk, &written, nullptr) || written == 0) {
            CloseHandle(h);
            std::error_code ec;
            std::filesystem::remove(tmpPathFs, ec);
            return false;
        }
        p += written;
        remaining -= written;
    }

    if (!FlushFileBuffers(h)) {
        CloseHandle(h);
        std::error_code ec;
        std::filesystem::remove(tmpPathFs, ec);
        return false;
    }

    if (!CloseHandle(h)) {
        std::error_code ec;
        std::filesystem::remove(tmpPathFs, ec);
        return false;
    }

    if (!MoveFileExW(tmpPathFs.c_str(), pathFs.c_str(),
                     MOVEFILE_REPLACE_EXISTING)) {
        std::error_code ec;
        std::filesystem::remove(tmpPathFs, ec);
        return false;
    }
    return true;
}

inline bool AtomicWriteBinary(const std::string& path, const void* data, size_t len) {
    auto pathFs = Utf8ToPath(path);
    auto tmpPathFs = Utf8ToPath(path + ".tmp");
    if (pathFs.empty() || tmpPathFs.empty()) return false;
    return WriteFlushAndRename(pathFs, tmpPathFs, data, len);
}

inline bool AtomicWriteText(const std::string& path, const std::string& content) {
    auto pathFs = Utf8ToPath(path);
    auto tmpPathFs = Utf8ToPath(path + ".tmp");
    if (pathFs.empty() || tmpPathFs.empty()) return false;
    return WriteFlushAndRename(pathFs, tmpPathFs, content.data(), content.size());
}

} // namespace FileUtil

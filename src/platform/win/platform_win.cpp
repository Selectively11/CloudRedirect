// Windows platform adapter implementation
#include "platform.h"
#include <cstring>
#include <algorithm>
#include <chrono>
#include <thread>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wincrypt.h>
#include <ShlObj.h>

class WindowsPlatform : public IPlatform {
public:
    std::filesystem::path Utf8ToPath(const std::string& utf8) override {
        if (utf8.empty()) return {};
        int wideLen = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(),
                                          nullptr, 0);
        if (wideLen <= 0) return {};
        std::wstring wide((size_t)wideLen, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(),
                            wide.data(), wideLen);
        return std::filesystem::path(std::move(wide));
    }
    
    std::string PathToUtf8(const std::filesystem::path& p) override {
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
    
    std::string WideToUtf8(const wchar_t* w) override {
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
    
    std::string WideToUtf8(const wchar_t* w, size_t len) override {
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
    
    bool AtomicWriteBinary(const std::string& path, const void* data, size_t len) override {
        auto pathFs = Utf8ToPath(path);
        auto tmpPathFs = Utf8ToPath(path + ".tmp");
        if (pathFs.empty() || tmpPathFs.empty()) return false;
        return WriteFlushAndRename(pathFs, tmpPathFs, data, len);
    }
    
    bool AtomicWriteText(const std::string& path, const std::string& content) override {
        return AtomicWriteBinary(path, content.data(), content.size());
    }
    
    bool IsPathWithin(const std::string& root, const std::string& fullPath) override {
        std::error_code ec;
        auto canonRoot = std::filesystem::weakly_canonical(Utf8ToPath(root), ec);
        if (ec) return false;
        auto canonPath = std::filesystem::weakly_canonical(Utf8ToPath(fullPath), ec);
        if (ec) return false;
        std::string rootStr = PathToUtf8(canonRoot);
        std::string pathStr = PathToUtf8(canonPath);
        if (pathStr.size() < rootStr.size()) return false;
        if (_strnicmp(pathStr.c_str(), rootStr.c_str(), rootStr.size()) != 0) return false;
        return pathStr.size() == rootStr.size() ||
               pathStr[rootStr.size()] == '\\' ||
               pathStr[rootStr.size()] == '/';
    }
    
    void CleanupEmptyDirsUpTo(const std::string& startDir, const std::string& stopAt) override {
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
    
    bool IsPathRedirectingReparsePoint(const std::string& path) override {
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
    
    char PathSeparator() const override { return '\\'; }
    const char* PathSeparatorStr() const override { return "\\"; }
    
    std::string NormalizePath(const std::string& path) const override {
        std::string result = path;
        std::replace(result.begin(), result.end(), '/', '\\');
        return result;
    }
    
    std::vector<uint8_t> SHA1(const void* data, size_t len) override {
        std::vector<uint8_t> hash(20, 0);
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
            return hash;
        if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            return hash;
        }
        CryptHashData(hHash, (const BYTE*)data, len > UINT32_MAX ? 0 : (DWORD)len, 0);
        if (len > UINT32_MAX) { CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); return {}; }
        DWORD hashLen = 20;
        CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return hash;
    }
    
private:
    bool WriteFlushAndRename(const std::filesystem::path& pathFs,
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
};

// Global platform instance management
static WindowsPlatform g_realPlatform;
static IPlatform* g_currentPlatform = &g_realPlatform;

IPlatform& Platform() {
    return *g_currentPlatform;
}

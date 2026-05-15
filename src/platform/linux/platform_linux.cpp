// Linux platform adapter implementation
#include "platform.h"
#include <cstring>
#include <cerrno>
#include <algorithm>
#include <chrono>
#include <thread>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>

class LinuxPlatform : public IPlatform {
public:
    // On Linux, paths are already UTF-8. These are identity operations.
    std::filesystem::path Utf8ToPath(const std::string& utf8) override {
        return std::filesystem::path(utf8);
    }
    
    std::string PathToUtf8(const std::filesystem::path& p) override {
        return p.string();
    }
    
    // WideToUtf8 - proper UTF-32 to UTF-8 conversion for Linux (wchar_t is 32-bit)
    std::string WideToUtf8(const wchar_t* w) override {
        if (!w || !*w) return {};
        std::string result;
        for (; *w; ++w) {
            uint32_t cp = static_cast<uint32_t>(*w);
            if (cp < 0x80) { result += (char)cp; }
            else if (cp < 0x800) { result += (char)(0xC0|(cp>>6)); result += (char)(0x80|(cp&0x3F)); }
            else if (cp < 0x10000) { result += (char)(0xE0|(cp>>12)); result += (char)(0x80|((cp>>6)&0x3F)); result += (char)(0x80|(cp&0x3F)); }
            else if (cp < 0x110000) { result += (char)(0xF0|(cp>>18)); result += (char)(0x80|((cp>>12)&0x3F)); result += (char)(0x80|((cp>>6)&0x3F)); result += (char)(0x80|(cp&0x3F)); }
        }
        return result;
    }
    
    std::string WideToUtf8(const wchar_t* w, size_t len) override {
        if (!w || len == 0) return {};
        std::string result;
        for (size_t i = 0; i < len; ++i) {
            uint32_t cp = static_cast<uint32_t>(w[i]);
            if (cp < 0x80) { result += (char)cp; }
            else if (cp < 0x800) { result += (char)(0xC0|(cp>>6)); result += (char)(0x80|(cp&0x3F)); }
            else if (cp < 0x10000) { result += (char)(0xE0|(cp>>12)); result += (char)(0x80|((cp>>6)&0x3F)); result += (char)(0x80|(cp&0x3F)); }
            else if (cp < 0x110000) { result += (char)(0xF0|(cp>>18)); result += (char)(0x80|((cp>>12)&0x3F)); result += (char)(0x80|((cp>>6)&0x3F)); result += (char)(0x80|(cp&0x3F)); }
        }
        return result;
    }
    
    bool AtomicWriteBinary(const std::string& path, const void* data, size_t len) override {
        std::string tmp = path + ".tmp";

        int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0) return false;

        const uint8_t* p = static_cast<const uint8_t*>(data);
        size_t remaining = len;
        while (remaining > 0) {
            ssize_t written = write(fd, p, remaining);
            if (written < 0) {
                if (errno == EINTR) continue;
                close(fd); unlink(tmp.c_str()); return false;
            }
            p += written;
            remaining -= written;
        }

        if (fsync(fd) != 0) { close(fd); unlink(tmp.c_str()); return false; }
        close(fd);

        if (rename(tmp.c_str(), path.c_str()) != 0) {
            unlink(tmp.c_str());
            return false;
        }
        return true;
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
        std::string rootStr = canonRoot.string();
        std::string pathStr = canonPath.string();
        if (pathStr.size() < rootStr.size()) return false;
        if (strncmp(pathStr.c_str(), rootStr.c_str(), rootStr.size()) != 0) return false;
        return pathStr.size() == rootStr.size() || pathStr[rootStr.size()] == '/';
    }
    
    void CleanupEmptyDirsUpTo(const std::string& startDir, const std::string& stopAt) override {
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
    
    // No reparse points on Linux
    bool IsPathRedirectingReparsePoint(const std::string& /*path*/) override {
        return false;
    }
    
    char PathSeparator() const override { return '/'; }
    const char* PathSeparatorStr() const override { return "/"; }
    
    std::string NormalizePath(const std::string& path) const override {
        // On Linux, paths already use '/', no normalization needed.
        return path;
    }
    
    std::vector<uint8_t> SHA1(const void* data, size_t len) override {
        // Minimal SHA1 implementation (no external dependency)
        std::vector<uint8_t> hash(20, 0);
        
        uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE,
                 h3 = 0x10325476, h4 = 0xC3D2E1F0;
        
        uint64_t totalBits = (uint64_t)len * 8;
        
        // Pad message
        std::vector<uint8_t> msg((const uint8_t*)data, (const uint8_t*)data + len);
        msg.push_back(0x80);
        while (msg.size() % 64 != 56) msg.push_back(0x00);
        for (int i = 7; i >= 0; --i) msg.push_back((uint8_t)(totalBits >> (i * 8)));
        
        auto rotl = [](uint32_t x, int n) -> uint32_t { return (x << n) | (x >> (32 - n)); };
        
        for (size_t chunk = 0; chunk < msg.size(); chunk += 64) {
            uint32_t w[80];
            for (int i = 0; i < 16; ++i) {
                w[i] = ((uint32_t)msg[chunk + i*4] << 24) |
                        ((uint32_t)msg[chunk + i*4+1] << 16) |
                        ((uint32_t)msg[chunk + i*4+2] << 8) |
                        ((uint32_t)msg[chunk + i*4+3]);
            }
            for (int i = 16; i < 80; ++i)
                w[i] = rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
            
            uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
            for (int i = 0; i < 80; ++i) {
                uint32_t f, k;
                if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
                else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
                else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
                else { f = b ^ c ^ d; k = 0xCA62C1D6; }
                uint32_t temp = rotl(a, 5) + f + e + k + w[i];
                e = d; d = c; c = rotl(b, 30); b = a; a = temp;
            }
            h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
        }
        
        auto store = [&hash](int off, uint32_t v) {
            hash[off] = (uint8_t)(v >> 24); hash[off+1] = (uint8_t)(v >> 16);
            hash[off+2] = (uint8_t)(v >> 8); hash[off+3] = (uint8_t)v;
        };
        store(0, h0); store(4, h1); store(8, h2); store(12, h3); store(16, h4);
        return hash;
    }
};

// Global platform instance management
static LinuxPlatform g_realPlatform;
static IPlatform* g_currentPlatform = &g_realPlatform;

IPlatform& Platform() {
    return *g_currentPlatform;
}

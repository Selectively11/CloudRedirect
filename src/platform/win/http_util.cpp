#include "http_util.h"
#include <cstdio>
#include <ctime>
#include <windows.h>

namespace HttpUtil {

std::wstring Widen(const std::string& s) {
    if (s.empty()) return {};
    // Try strict UTF-8 decoding first
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.c_str(), (int)s.size(), nullptr, 0);
    DWORD flags = MB_ERR_INVALID_CHARS;
    if (n == 0) {
        // Fallback: lenient mode (invalid UTF-8 bytes produce replacement chars)
        flags = 0;
        n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
        if (n == 0) return {};
    }
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, flags, s.c_str(), (int)s.size(), w.data(), n);
    return w;
}

std::string UrlEncode(const std::string& s, bool preserveSlash) {
    std::string out;
    for (unsigned char c : s) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' ||
            (preserveSlash && c == '/')) {
            out += (char)c;
        } else {
            char hex[4];
            snprintf(hex, sizeof(hex), "%%%02X", c);
            out += hex;
        }
    }
    return out;
}

std::string UrlDecode(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            char hi = s[i + 1], lo = s[i + 2];
            auto hexVal = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                return -1;
            };
            int h = hexVal(hi), l = hexVal(lo);
            if (h >= 0 && l >= 0) {
                out += (char)((h << 4) | l);
                i += 2;
                continue;
            }
        }
        out += s[i];
    }
    return out;
}

int64_t Iso8601ToUnix(const std::string& iso) {
    if (iso.size() < 19) return 0;
    struct tm tm = {};
    int matched = sscanf(iso.c_str(), "%d-%d-%dT%d:%d:%d",
           &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
           &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
    if (matched != 6) return 0;
    tm.tm_year -= 1900;
    tm.tm_mon -= 1;
    // _mkgmtime -> -1 on unrepresentable input. A signed -> unsigned cast in
    // callers would become UINT64_MAX and break tombstone mtime gating, so
    // normalize to 0 here ("missing mtime").
    time_t t = _mkgmtime(&tm);
    if (t == static_cast<time_t>(-1)) return 0;
    return static_cast<int64_t>(t);
}

std::string UnixToIso8601(int64_t ts) {
    time_t t = (time_t)ts;
    struct tm tm;
    gmtime_s(&tm, &t);
    char buf[32];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
    return buf;
}

} // namespace HttpUtil

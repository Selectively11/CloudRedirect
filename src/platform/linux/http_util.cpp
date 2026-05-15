#include "http_util.h"
#include <ctime>
#include <cstdio>
#include <cctype>
#include <sstream>
#include <iomanip>

namespace HttpUtil {

std::string UrlEncode(const std::string& s, bool preserveSlash) {
    std::string result;
    result.reserve(s.size() * 1.2);
    for (unsigned char c : s) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            result += (char)c;
        } else if (preserveSlash && c == '/') {
            result += '/';
        } else {
            char hex[4];
            snprintf(hex, sizeof(hex), "%%%02X", c);
            result += hex;
        }
    }
    return result;
}

std::string UrlDecode(const std::string& s) {
    std::string result;
    result.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            unsigned char c1 = (unsigned char)s[i+1], c2 = (unsigned char)s[i+2];
            if (((c1 >= '0' && c1 <= '9') || (c1 >= 'A' && c1 <= 'F') || (c1 >= 'a' && c1 <= 'f')) &&
                ((c2 >= '0' && c2 <= '9') || (c2 >= 'A' && c2 <= 'F') || (c2 >= 'a' && c2 <= 'f'))) {
                int hi = (c1 >= 'a') ? c1 - 'a' + 10 :
                         (c1 >= 'A') ? c1 - 'A' + 10 : c1 - '0';
                int lo = (c2 >= 'a') ? c2 - 'a' + 10 :
                         (c2 >= 'A') ? c2 - 'A' + 10 : c2 - '0';
                result += (char)((hi << 4) | lo);
                i += 2;
            } else {
                result += s[i];
            }
        } else if (s[i] == '+') {
            result += ' ';
        } else {
            result += s[i];
        }
    }
    return result;
}

int64_t Iso8601ToUnix(const std::string& iso) {
    struct tm t{};
    if (sscanf(iso.c_str(), "%d-%d-%dT%d:%d:%d",
               &t.tm_year, &t.tm_mon, &t.tm_mday,
               &t.tm_hour, &t.tm_min, &t.tm_sec) < 6) {
        return 0;
    }
    t.tm_year -= 1900;
    t.tm_mon -= 1;
    time_t raw = timegm(&t);
    if (raw == static_cast<time_t>(-1)) return 0;
    return static_cast<int64_t>(raw);
}

std::string UnixToIso8601(int64_t ts) {
    time_t t = (time_t)ts;
    struct tm tm;
    gmtime_r(&t, &tm);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
}

} // namespace HttpUtil

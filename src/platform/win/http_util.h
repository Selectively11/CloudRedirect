#pragma once
#include <string>
#include <cstdint>

namespace HttpUtil {

// convert UTF-8 string to wide string (for WinHTTP APIs)
std::wstring Widen(const std::string& s);

// percent-encode a string per RFC 3986 (unreserved chars pass through).
// if preserveSlash is true, '/' is not encoded (useful for URL paths).
std::string UrlEncode(const std::string& s, bool preserveSlash = false);

// decode percent-encoded sequences (%XX -> byte)
std::string UrlDecode(const std::string& s);

// parse ISO 8601 datetime (e.g. "2024-01-15T12:30:00Z") to Unix timestamp
int64_t Iso8601ToUnix(const std::string& iso);

// format Unix timestamp as ISO 8601 datetime (e.g. "2024-01-15T12:30:00Z")
std::string UnixToIso8601(int64_t ts);

// generic HTTPS response
struct HttpResp {
    int status = 0;
    std::string body;
};

} // namespace HttpUtil

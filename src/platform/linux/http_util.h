#pragma once
// Linux http_util.h - matches Windows API surface for common/ code

#include <string>
#include <cstdint>

namespace HttpUtil {

// percent-encode a string per RFC 3986 (unreserved chars pass through).
// if preserveSlash is true, '/' is not encoded.
std::string UrlEncode(const std::string& s, bool preserveSlash = false);

// decode percent-encoded sequences (%XX -> byte)
std::string UrlDecode(const std::string& s);

// parse ISO 8601 datetime to Unix timestamp
int64_t Iso8601ToUnix(const std::string& iso);

// format Unix timestamp as ISO 8601 datetime
std::string UnixToIso8601(int64_t ts);

// generic HTTPS response
struct HttpResp {
    int status = 0;
    std::string body;
};

} // namespace HttpUtil

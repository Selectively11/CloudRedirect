#pragma once

#include <string>
#include <vector>

namespace sigv4 {

struct SigHeader {
    std::string name;
    std::string value;
};

struct SignInput {
    std::string method;
    std::string canonicalUri;
    std::string canonicalQuery;
    std::vector<SigHeader> headers;
    std::string payloadHash;

    std::string region = "auto";
    std::string service = "s3";
    std::string accessKey;
    std::string secretKey;
    std::string amzDate;
    std::string dateStamp;
};

struct SignResult {
    std::string canonicalRequest;
    std::string stringToSign;
    std::string signedHeaders;
    std::string signature;
    std::string authorization;
};

SignResult Sign(const SignInput& in);

void FormatSigV4Time(int64_t unixSeconds, std::string& outAmzDate,
                     std::string& outDateStamp);

} // namespace sigv4

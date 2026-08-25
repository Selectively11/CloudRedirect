#include "sigv4.h"
#include "sha256_hmac.h"

#include <algorithm>
#include <cctype>
#include <ctime>

namespace sigv4 {

namespace {

std::string ToLower(std::string s) {
    for (auto& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

// Trim leading/trailing ASCII whitespace and collapse internal runs of spaces
// to a single space (SigV4 header-value normalization).
std::string TrimValue(const std::string& in) {
    size_t b = 0, e = in.size();
    while (b < e && std::isspace((unsigned char)in[b])) b++;
    while (e > b && std::isspace((unsigned char)in[e - 1])) e--;
    std::string out;
    out.reserve(e - b);
    bool prevSpace = false;
    for (size_t i = b; i < e; i++) {
        char c = in[i];
        if (c == ' ') {
            if (prevSpace) continue;
            prevSpace = true;
        } else {
            prevSpace = false;
        }
        out.push_back(c);
    }
    return out;
}

std::string HexMac(const std::array<uint8_t, 32>& m) {
    return crypto::ToHex(m.data(), m.size());
}

} // namespace

SignResult Sign(const SignInput& in) {
    SignResult r;

    // Canonical headers: lowercase names, trimmed values, sorted by name.
    struct H { std::string name; std::string value; };
    std::vector<H> hs;
    hs.reserve(in.headers.size());
    for (const auto& h : in.headers)
        hs.push_back({ToLower(h.name), TrimValue(h.value)});
    std::sort(hs.begin(), hs.end(),
              [](const H& a, const H& b) { return a.name < b.name; });

    std::string canonicalHeaders;
    std::string signedHeaders;
    for (size_t i = 0; i < hs.size(); i++) {
        canonicalHeaders += hs[i].name;
        canonicalHeaders += ':';
        canonicalHeaders += hs[i].value;
        canonicalHeaders += '\n';
        if (i) signedHeaders += ';';
        signedHeaders += hs[i].name;
    }
    r.signedHeaders = signedHeaders;

    // Canonical request.
    r.canonicalRequest =
        in.method + "\n" +
        in.canonicalUri + "\n" +
        in.canonicalQuery + "\n" +
        canonicalHeaders + "\n" +
        signedHeaders + "\n" +
        in.payloadHash;

    // String to sign.
    std::string credentialScope =
        in.dateStamp + "/" + in.region + "/" + in.service + "/aws4_request";
    r.stringToSign =
        std::string("AWS4-HMAC-SHA256\n") +
        in.amzDate + "\n" +
        credentialScope + "\n" +
        crypto::Sha256Hex(r.canonicalRequest);

    // Derive signing key: HMAC chain seeded with "AWS4"+secret.
    std::string kSecret = "AWS4" + in.secretKey;
    auto kDate = crypto::HmacSha256(kSecret, in.dateStamp);
    auto kRegion = crypto::HmacSha256(
        std::vector<uint8_t>(kDate.begin(), kDate.end()), in.region);
    auto kService = crypto::HmacSha256(
        std::vector<uint8_t>(kRegion.begin(), kRegion.end()), in.service);
    auto kSigning = crypto::HmacSha256(
        std::vector<uint8_t>(kService.begin(), kService.end()),
        std::string("aws4_request"));
    auto sig = crypto::HmacSha256(
        std::vector<uint8_t>(kSigning.begin(), kSigning.end()), r.stringToSign);
    r.signature = HexMac(sig);

    r.authorization =
        "AWS4-HMAC-SHA256 Credential=" + in.accessKey + "/" + credentialScope +
        ", SignedHeaders=" + signedHeaders +
        ", Signature=" + r.signature;

    return r;
}

void FormatSigV4Time(int64_t unixSeconds, std::string& outAmzDate,
                     std::string& outDateStamp) {
    time_t t = (time_t)unixSeconds;
    struct tm g;
#ifdef _WIN32
    gmtime_s(&g, &t);
#else
    gmtime_r(&t, &g);
#endif
    char amz[32], ds[16];
    std::strftime(amz, sizeof(amz), "%Y%m%dT%H%M%SZ", &g);
    std::strftime(ds, sizeof(ds), "%Y%m%d", &g);
    outAmzDate = amz;
    outDateStamp = ds;
}

} // namespace sigv4

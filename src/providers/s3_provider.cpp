#include "s3_provider.h"
#include "sigv4.h"
#include "sha256_hmac.h"
#include "http_util.h"

#include <ctime>
#include <cstdio>
#include <algorithm>
#include <chrono>
#include <random>
#include <thread>

static std::string ExtractJsonString(const std::string& json, const char* key) {
    std::string needle = std::string("\"") + key + "\"";
    size_t k = json.find(needle);
    if (k == std::string::npos) return {};
    size_t colon = json.find(':', k + needle.size());
    if (colon == std::string::npos) return {};
    size_t q1 = json.find('"', colon + 1);
    if (q1 == std::string::npos) return {};
    std::string out;
    for (size_t i = q1 + 1; i < json.size(); ++i) {
        char c = json[i];
        if (c == '\\' && i + 1 < json.size()) { out.push_back(json[++i]); continue; }
        if (c == '"') break;
        out.push_back(c);
    }
    return out;
}

static bool ExtractJsonBool(const std::string& json, const char* key, bool dflt) {
    std::string needle = std::string("\"") + key + "\"";
    size_t k = json.find(needle);
    if (k == std::string::npos) return dflt;
    size_t colon = json.find(':', k + needle.size());
    if (colon == std::string::npos) return dflt;
    size_t v = colon + 1;
    while (v < json.size() && (json[v] == ' ' || json[v] == '\t')) ++v;
    return json.compare(v, 4, "true") == 0;
}

static bool ExtractXmlTag(const std::string& xml, const char* tag,
                          size_t& from, std::string& out) {
    std::string open = std::string("<") + tag + ">";
    std::string close = std::string("</") + tag + ">";
    size_t o = xml.find(open, from);
    if (o == std::string::npos) return false;
    size_t start = o + open.size();
    size_t c = xml.find(close, start);
    if (c == std::string::npos) return false;
    out = xml.substr(start, c - start);
    from = c + close.size();
    return true;
}

static std::string XmlUnescape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '&') {
            if (s.compare(i, 5, "&amp;") == 0) { out.push_back('&'); i += 4; continue; }
            if (s.compare(i, 4, "&lt;") == 0)  { out.push_back('<'); i += 3; continue; }
            if (s.compare(i, 4, "&gt;") == 0)  { out.push_back('>'); i += 3; continue; }
            if (s.compare(i, 6, "&quot;") == 0){ out.push_back('"'); i += 5; continue; }
            if (s.compare(i, 6, "&apos;") == 0){ out.push_back('\''); i += 5; continue; }
        }
        out.push_back(s[i]);
    }
    return out;
}

bool S3Provider::Init(const std::string& configPath) {
    auto store = CreateTokenStore();
    if (!store) return false;
    std::string json = store->Read(configPath);
    if (json.empty()) return false;

    m_accessKey = ExtractJsonString(json, "access_key_id");
    m_secretKey = ExtractJsonString(json, "secret_access_key");
    m_bucket    = ExtractJsonString(json, "bucket");
    m_keyPrefix = ExtractJsonString(json, "key_prefix");

    if (!ParseExtraCredentials(json)) return false;

    if (m_accessKey.empty() || m_secretKey.empty() || m_bucket.empty())
        return false;

    m_scheme = "https";
    std::string endpoint = ExtractJsonString(json, "endpoint");
    if (!endpoint.empty()) {
        size_t s = endpoint.find("://");
        if (s != std::string::npos) {
            std::string scheme = endpoint.substr(0, s);
            if (scheme == "http" || scheme == "https") m_scheme = scheme;
            endpoint = endpoint.substr(s + 3);
        }
        size_t slash = endpoint.find('/');
        if (slash != std::string::npos) endpoint = endpoint.substr(0, slash);
        m_host = endpoint;
    } else {
        m_host = DefaultEndpoint();
    }
    if (m_host.empty()) return false;

    m_region = ExtractJsonString(json, "region");
    if (m_region.empty()) m_region = DefaultRegion();

    m_signPayload = !ForceUnsignedPayload() && ExtractJsonBool(json, "sign_payload", false);

    {
        std::string thr = ExtractJsonString(json, "multipart_threshold");
        std::string ps  = ExtractJsonString(json, "part_size");
        if (!thr.empty()) m_multipartThreshold = (size_t)strtoull(thr.c_str(), nullptr, 10);
        if (!ps.empty())  m_partSize = (size_t)strtoull(ps.c_str(), nullptr, 10);
        if (m_partSize < 5ull * 1024 * 1024) m_partSize = 5ull * 1024 * 1024;
    }

    m_sendChecksum = ExtractJsonBool(json, "checksum_integrity", true);

    if (!m_keyPrefix.empty()) {
        while (!m_keyPrefix.empty() && m_keyPrefix.front() == '/')
            m_keyPrefix.erase(m_keyPrefix.begin());
        if (!m_keyPrefix.empty() && m_keyPrefix.back() != '/')
            m_keyPrefix.push_back('/');
    }

    m_transport = CreateHttpTransport(LogTag());
    if (!m_transport || !m_transport->Init()) return false;

    TransportOptions opts;
    opts.allowInsecureHttp = (m_scheme == "http") ||
                             ExtractJsonBool(json, "allow_insecure_http", false);
    opts.allowInsecureTls = ExtractJsonBool(json, "allow_insecure_tls", false);
    opts.caCertPath = ExtractJsonString(json, "ca_cert_path");
    m_transport->SetOptions(opts);

    m_ready = true;

    if (ProbeVersioningAtInit())
        m_versioningEnabled = GetBucketVersioning();

    return true;
}

void S3Provider::Shutdown() {
    if (m_transport) m_transport->Shutdown();
    m_transport.reset();
    m_ready = false;
}

bool S3Provider::IsAuthenticated() const {
    return m_ready;
}

std::string S3Provider::ToObjectKey(const std::string& relPath) const {
    return m_keyPrefix + relPath;
}

std::string S3Provider::CanonicalUri(const std::string& objectKey) const {
    std::string uri = "/" + HttpUtil::UrlEncode(m_bucket, /*preserveSlash=*/false);
    if (!objectKey.empty())
        uri += "/" + HttpUtil::UrlEncode(objectKey, /*preserveSlash=*/true);
    return uri;
}

HttpUtil::HttpResp S3Provider::SignedRequest(
        const char* method, const std::string& objectKey,
        const std::string& canonicalQuery, const std::string& body,
        const std::vector<std::pair<std::string, std::string>>& extraHeaders) {
    HttpUtil::HttpResp resp;
    if (!m_ready || !m_transport) return resp;

    const std::string canonicalUri = CanonicalUri(objectKey);

    std::string payloadHash;
    if (m_signPayload)
        payloadHash = crypto::Sha256Hex(body);
    else
        payloadHash = "UNSIGNED-PAYLOAD";

    static constexpr int kMaxAttempts = 5;
    static thread_local std::mt19937 rng{std::random_device{}()};

    std::string url = m_scheme + "://" + m_host + canonicalUri;
    if (!canonicalQuery.empty()) url += "?" + canonicalQuery;

    for (int attempt = 0; attempt < kMaxAttempts; ++attempt) {
        if (attempt > 0) {
            int baseMs = 1000 * (1 << (attempt - 1));
            int jitter = std::uniform_int_distribution<int>(0, baseMs / 2)(rng);
            std::this_thread::sleep_for(std::chrono::milliseconds(baseMs + jitter));
        }

        std::string amzDate, dateStamp;
        sigv4::FormatSigV4Time((int64_t)time(nullptr), amzDate, dateStamp);

        sigv4::SignInput in;
        in.method = method;
        in.canonicalUri = canonicalUri;
        in.canonicalQuery = canonicalQuery;
        in.payloadHash = payloadHash;
        in.region = m_region;
        in.accessKey = m_accessKey;
        in.secretKey = m_secretKey;
        in.amzDate = amzDate;
        in.dateStamp = dateStamp;
        in.headers = {
            { "host", m_host },
            { "x-amz-content-sha256", payloadHash },
            { "x-amz-date", amzDate },
        };
        for (const auto& h : extraHeaders)
            in.headers.push_back({ h.first, h.second });

        sigv4::SignResult sig = sigv4::Sign(in);

        std::vector<std::string> headers = {
            "Host: " + m_host,
            std::string("x-amz-content-sha256: ") + payloadHash,
            "x-amz-date: " + amzDate,
            "Authorization: " + sig.authorization,
        };
        for (const auto& h : extraHeaders)
            headers.push_back(h.first + ": " + h.second);

        resp = m_transport->RequestUrl(method, url, body, headers);

        bool shouldRetry = (resp.status == 429 || resp.status == 500 ||
                             resp.status == 502 || resp.status == 503 ||
                             resp.status == 0);
        if (!shouldRetry) return resp;

        if (resp.status == 429)
            g_rateLimitHits.fetch_add(1, std::memory_order_relaxed);
    }

    return resp;
}

std::vector<std::pair<std::string, std::string>>
S3Provider::ChecksumHeader(const uint8_t* data, size_t len) const {
    if (!m_sendChecksum) return {};
    return {{ "x-amz-checksum-sha256", crypto::Sha256Base64(data, len) }};
}

bool S3Provider::Upload(const std::string& path, const uint8_t* data, size_t len) {
    const std::string objectKey = ToObjectKey(path);

    if (len > m_multipartThreshold)
        return UploadMultipart(objectKey, data, len);

    std::string body(reinterpret_cast<const char*>(data), len);
    HttpUtil::HttpResp r = SignedRequest("PUT", objectKey, "", body,
                                         ChecksumHeader(data, len));
    if (r.status != 200) {
        m_lastUploadVersionId.clear();
        return false;
    }
    auto it = r.headers.find("x-amz-version-id");
    m_lastUploadVersionId = (it != r.headers.end()) ? it->second : std::string();
    return true;
}

bool S3Provider::Download(const std::string& path, std::vector<uint8_t>& outData) {
    HttpUtil::HttpResp r = SignedRequest("GET", ToObjectKey(path), "", "");
    if (r.status != 200) return false;
    outData.assign(r.body.begin(), r.body.end());
    return true;
}

bool S3Provider::Remove(const std::string& path) {
    HttpUtil::HttpResp r = SignedRequest("DELETE", ToObjectKey(path), "", "");
    return r.status == 204 || r.status == 200 || r.status == 404;
}

ICloudProvider::ExistsStatus S3Provider::CheckExists(const std::string& path) {
    HttpUtil::HttpResp r = SignedRequest("HEAD", ToObjectKey(path), "", "");
    if (r.status == 200) return ExistsStatus::Exists;
    if (r.status == 404) return ExistsStatus::Missing;
    return ExistsStatus::Error;
}

bool S3Provider::ListPage(const std::string& prefix, const std::string& continuationToken,
                          std::vector<FileInfo>& outFiles, bool& outTruncated,
                          std::string& outNextToken) {
    outTruncated = false;
    outNextToken.clear();

    std::string query;
    auto append = [&](const std::string& k, const std::string& v) {
        if (!query.empty()) query += "&";
        query += HttpUtil::UrlEncode(k, false) + "=" + HttpUtil::UrlEncode(v, false);
    };
    if (!continuationToken.empty())
        append("continuation-token", continuationToken);
    append("list-type", "2");
    if (!prefix.empty())
        append("prefix", ToObjectKey(prefix));

    HttpUtil::HttpResp r = SignedRequest("GET", "", query, "");
    if (r.status != 200) return false;

    const std::string& xml = r.body;

    {
        size_t p = 0;
        std::string trunc;
        if (ExtractXmlTag(xml, "IsTruncated", p, trunc))
            outTruncated = (trunc == "true");
        size_t p2 = 0;
        std::string next;
        if (ExtractXmlTag(xml, "NextContinuationToken", p2, next))
            outNextToken = next;
    }

    size_t pos = 0;
    for (;;) {
        std::string contents;
        if (!ExtractXmlTag(xml, "Contents", pos, contents)) break;

        size_t cp = 0;
        std::string key, size, lastMod;
        ExtractXmlTag(contents, "Key", cp, key);
        cp = 0; ExtractXmlTag(contents, "Size", cp, size);
        cp = 0; ExtractXmlTag(contents, "LastModified", cp, lastMod);
        if (key.empty()) continue;

        std::string relKey = XmlUnescape(key);
        if (!m_keyPrefix.empty() && relKey.compare(0, m_keyPrefix.size(), m_keyPrefix) == 0)
            relKey = relKey.substr(m_keyPrefix.size());

        FileInfo fi;
        fi.path = relKey;
        fi.size = size.empty() ? 0 : (uint64_t)strtoull(size.c_str(), nullptr, 10);
        fi.modifiedTime = lastMod.empty() ? 0 : (uint64_t)HttpUtil::Iso8601ToUnix(lastMod);
        outFiles.push_back(std::move(fi));
    }
    return true;
}

bool S3Provider::ListChecked(const std::string& prefix, std::vector<FileInfo>& outFiles,
                             bool* outComplete) {
    if (outComplete) *outComplete = false;
    outFiles.clear();

    std::string token;
    for (;;) {
        bool truncated = false;
        std::string next;
        if (!ListPage(prefix, token, outFiles, truncated, next))
            return false;
        if (!truncated) break;
        if (next.empty()) return false;
        token = next;
    }

    if (outComplete) *outComplete = true;
    return true;
}

std::vector<ICloudProvider::FileInfo> S3Provider::List(const std::string& prefix) {
    std::vector<FileInfo> files;
    ListChecked(prefix, files, nullptr);
    return files;
}

bool S3Provider::GetBucketVersioning() {
    HttpUtil::HttpResp r = SignedRequest("GET", "", "versioning=", "");
    if (r.status != 200) return false;
    size_t p = 0;
    std::string status;
    if (!ExtractXmlTag(r.body, "Status", p, status)) return false;
    return status == "Enabled";
}

bool S3Provider::ListVersionsPage(const std::string& objectKey,
                                  const std::string& keyMarker,
                                  const std::string& versionIdMarker,
                                  std::vector<FileInfo>& outVersions, bool& outTruncated,
                                  std::string& outNextKeyMarker,
                                  std::string& outNextVersionIdMarker) {
    outTruncated = false;
    outNextKeyMarker.clear();
    outNextVersionIdMarker.clear();

    std::string query;
    auto append = [&](const std::string& k, const std::string& v) {
        if (!query.empty()) query += "&";
        query += HttpUtil::UrlEncode(k, false) + "=" + HttpUtil::UrlEncode(v, false);
    };
    if (!keyMarker.empty())       append("key-marker", keyMarker);
    if (!objectKey.empty())       append("prefix", objectKey);
    if (!versionIdMarker.empty()) append("version-id-marker", versionIdMarker);
    if (!query.empty()) query += "&";
    query += "versions=";

    HttpUtil::HttpResp r = SignedRequest("GET", "", query, "");
    if (r.status != 200) return false;

    const std::string& xml = r.body;

    {
        size_t p = 0; std::string trunc;
        if (ExtractXmlTag(xml, "IsTruncated", p, trunc))
            outTruncated = (trunc == "true");
        size_t p2 = 0; ExtractXmlTag(xml, "NextKeyMarker", p2, outNextKeyMarker);
        size_t p3 = 0; ExtractXmlTag(xml, "NextVersionIdMarker", p3, outNextVersionIdMarker);
    }

    size_t pos = 0;
    while (pos < xml.size()) {
        size_t v = xml.find("<Version>", pos);
        size_t d = xml.find("<DeleteMarker>", pos);
        if (v == std::string::npos && d == std::string::npos) break;

        bool isDelete = (d != std::string::npos && (v == std::string::npos || d < v));
        const char* tag = isDelete ? "DeleteMarker" : "Version";

        std::string entry;
        if (!ExtractXmlTag(xml, tag, pos, entry)) break;

        size_t cp = 0; std::string key, verId, isLatest, lastMod, size;
        ExtractXmlTag(entry, "Key", cp, key);
        cp = 0; ExtractXmlTag(entry, "VersionId", cp, verId);
        cp = 0; ExtractXmlTag(entry, "IsLatest", cp, isLatest);
        cp = 0; ExtractXmlTag(entry, "LastModified", cp, lastMod);
        if (!isDelete) { cp = 0; ExtractXmlTag(entry, "Size", cp, size); }
        if (key.empty()) continue;

        std::string relKey = XmlUnescape(key);
        if (!m_keyPrefix.empty() && relKey.compare(0, m_keyPrefix.size(), m_keyPrefix) == 0)
            relKey = relKey.substr(m_keyPrefix.size());

        FileInfo fi;
        fi.path = relKey;
        fi.size = size.empty() ? 0 : (uint64_t)strtoull(size.c_str(), nullptr, 10);
        fi.modifiedTime = lastMod.empty() ? 0 : (uint64_t)HttpUtil::Iso8601ToUnix(lastMod);
        fi.versionId = XmlUnescape(verId);
        fi.isLatest = (isLatest == "true");
        fi.isDeleteMarker = isDelete;
        outVersions.push_back(std::move(fi));
    }
    return true;
}

bool S3Provider::ListVersions(const std::string& path,
                              std::vector<FileInfo>& outVersions) {
    outVersions.clear();
    if (!m_versioningEnabled) return false;

    const std::string objectKey = ToObjectKey(path);
    std::string keyMarker, versionIdMarker;
    for (;;) {
        bool truncated = false;
        std::string nextKey, nextVer;
        if (!ListVersionsPage(objectKey, keyMarker, versionIdMarker,
                              outVersions, truncated, nextKey, nextVer))
            return false;
        if (!truncated) break;
        if (nextKey.empty() && nextVer.empty()) return false;
        keyMarker = nextKey;
        versionIdMarker = nextVer;
    }

    outVersions.erase(std::remove_if(outVersions.begin(), outVersions.end(),
        [&](const FileInfo& fi) { return fi.path != path; }), outVersions.end());
    return true;
}

bool S3Provider::DownloadVersion(const std::string& path, const std::string& versionId,
                                 std::vector<uint8_t>& outData) {
    if (versionId.empty()) return Download(path, outData);
    if (!m_versioningEnabled) return false;
    std::string query = "versionId=" + HttpUtil::UrlEncode(versionId, false);
    HttpUtil::HttpResp r = SignedRequest("GET", ToObjectKey(path), query, "");
    if (r.status != 200) return false;
    outData.assign(r.body.begin(), r.body.end());
    return true;
}

bool S3Provider::RemoveVersion(const std::string& path, const std::string& versionId) {
    if (versionId.empty() || !m_versioningEnabled) return false;
    std::string query = "versionId=" + HttpUtil::UrlEncode(versionId, false);
    HttpUtil::HttpResp r = SignedRequest("DELETE", ToObjectKey(path), query, "");
    return r.status == 204 || r.status == 200 || r.status == 404;
}

std::string S3Provider::MultipartCreate(const std::string& objectKey) {
    HttpUtil::HttpResp r = SignedRequest("POST", objectKey, "uploads=", "");
    if (r.status != 200) return {};
    size_t p = 0;
    std::string uploadId;
    if (!ExtractXmlTag(r.body, "UploadId", p, uploadId)) return {};
    return XmlUnescape(uploadId);
}

std::string S3Provider::MultipartUploadPart(const std::string& objectKey,
                                            const std::string& uploadId, int partNumber,
                                            const uint8_t* data, size_t len) {
    std::string query = "partNumber=" + std::to_string(partNumber) +
                        "&uploadId=" + HttpUtil::UrlEncode(uploadId, false);
    std::string body(reinterpret_cast<const char*>(data), len);
    HttpUtil::HttpResp r = SignedRequest("PUT", objectKey, query, body,
                                         ChecksumHeader(data, len));
    if (r.status != 200) return {};
    auto it = r.headers.find("etag");
    return (it != r.headers.end()) ? it->second : std::string();
}

bool S3Provider::MultipartComplete(const std::string& objectKey, const std::string& uploadId,
                                   const std::vector<std::string>& etags) {
    std::string body = "<CompleteMultipartUpload>";
    for (size_t i = 0; i < etags.size(); ++i) {
        body += "<Part><PartNumber>" + std::to_string((int)i + 1) +
                "</PartNumber><ETag>" + etags[i] + "</ETag></Part>";
    }
    body += "</CompleteMultipartUpload>";

    std::string query = "uploadId=" + HttpUtil::UrlEncode(uploadId, false);
    HttpUtil::HttpResp r = SignedRequest("POST", objectKey, query, body);
    if (r.status != 200) { m_lastUploadVersionId.clear(); return false; }
    if (r.body.find("<Error>") != std::string::npos) {
        m_lastUploadVersionId.clear();
        return false;
    }
    auto it = r.headers.find("x-amz-version-id");
    m_lastUploadVersionId = (it != r.headers.end()) ? it->second : std::string();
    return true;
}

void S3Provider::MultipartAbort(const std::string& objectKey, const std::string& uploadId) {
    if (uploadId.empty()) return;
    std::string query = "uploadId=" + HttpUtil::UrlEncode(uploadId, false);
    SignedRequest("DELETE", objectKey, query, "");
}

bool S3Provider::UploadMultipart(const std::string& objectKey, const uint8_t* data, size_t len) {
    std::string uploadId = MultipartCreate(objectKey);
    if (uploadId.empty()) { m_lastUploadVersionId.clear(); return false; }

    std::vector<std::string> etags;
    etags.reserve(len / m_partSize + 1);

    int partNumber = 1;
    for (size_t off = 0; off < len; off += m_partSize, ++partNumber) {
        size_t chunk = std::min(m_partSize, len - off);
        std::string etag = MultipartUploadPart(objectKey, uploadId, partNumber,
                                               data + off, chunk);
        if (etag.empty()) {
            MultipartAbort(objectKey, uploadId);
            m_lastUploadVersionId.clear();
            return false;
        }
        etags.push_back(std::move(etag));
    }

    if (!MultipartComplete(objectKey, uploadId, etags)) {
        MultipartAbort(objectKey, uploadId);
        return false;
    }
    return true;
}

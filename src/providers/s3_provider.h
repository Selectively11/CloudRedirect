#pragma once
#include "cloud_provider.h"
#include "cloud_provider_base.h"

#include <string>
#include <vector>
#include <utility>
#include <cstdint>
#include <memory>

class S3Provider : public ICloudProvider {
public:
    const char* Name() const override { return "S3"; }

    bool Init(const std::string& configPath) override;
    void Shutdown() override;
    bool IsAuthenticated() const override;

    bool Upload(const std::string& path, const uint8_t* data, size_t len) override;
    bool Download(const std::string& path, std::vector<uint8_t>& outData) override;
    bool Remove(const std::string& path) override;
    ExistsStatus CheckExists(const std::string& path) override;
    std::vector<FileInfo> List(const std::string& prefix) override;
    bool ListChecked(const std::string& prefix, std::vector<FileInfo>& outFiles,
                     bool* outComplete = nullptr) override;

    bool SupportsVersioning() const override { return m_versioningEnabled; }
    bool ListVersions(const std::string& path,
                      std::vector<FileInfo>& outVersions) override;
    bool DownloadVersion(const std::string& path, const std::string& versionId,
                         std::vector<uint8_t>& outData) override;
    bool RemoveVersion(const std::string& path,
                       const std::string& versionId) override;

    const std::string& LastUploadVersionId() const { return m_lastUploadVersionId; }

protected:
    virtual bool ParseExtraCredentials(const std::string& /*json*/) { return true; }
    virtual std::string DefaultEndpoint() const { return {}; }
    virtual std::string DefaultRegion() const { return "us-east-1"; }
    virtual bool ForceUnsignedPayload() const { return false; }
    virtual bool ProbeVersioningAtInit() const { return true; }
    virtual const char* LogTag() const { return "[S3]"; }

    std::string m_accessKey;
    std::string m_secretKey;
    std::string m_bucket;
    std::string m_host;
    std::string m_region;
    std::string m_scheme;
    std::string m_keyPrefix;
    bool m_signPayload = false;
    bool m_versioningEnabled = false;
    bool m_ready = false;
    std::string m_lastUploadVersionId;

    size_t m_multipartThreshold = 64ull * 1024 * 1024;
    size_t m_partSize          = 16ull * 1024 * 1024;
    bool m_sendChecksum = true;

    std::unique_ptr<IHttpTransport> m_transport;

private:
    std::string ToObjectKey(const std::string& relPath) const;
    std::string CanonicalUri(const std::string& objectKey) const;

    HttpUtil::HttpResp SignedRequest(const char* method,
                                     const std::string& objectKey,
                                     const std::string& canonicalQuery,
                                     const std::string& body,
                                     const std::vector<std::pair<std::string, std::string>>&
                                         extraHeaders = {});

    bool ListPage(const std::string& prefix, const std::string& continuationToken,
                  std::vector<FileInfo>& outFiles, bool& outTruncated,
                  std::string& outNextToken);

    std::vector<std::pair<std::string, std::string>>
    ChecksumHeader(const uint8_t* data, size_t len) const;

    bool GetBucketVersioning();

    bool ListVersionsPage(const std::string& objectKey,
                          const std::string& keyMarker,
                          const std::string& versionIdMarker,
                          std::vector<FileInfo>& outVersions, bool& outTruncated,
                          std::string& outNextKeyMarker,
                          std::string& outNextVersionIdMarker);

    bool UploadMultipart(const std::string& objectKey, const uint8_t* data, size_t len);
    std::string MultipartCreate(const std::string& objectKey);
    std::string MultipartUploadPart(const std::string& objectKey,
                                    const std::string& uploadId, int partNumber,
                                    const uint8_t* data, size_t len);
    bool MultipartComplete(const std::string& objectKey, const std::string& uploadId,
                           const std::vector<std::string>& etags);
    void MultipartAbort(const std::string& objectKey, const std::string& uploadId);
};

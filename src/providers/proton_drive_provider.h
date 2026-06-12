#pragma once
#include "cloud_provider_base.h"
#include "proton_pgp.h"
#include <unordered_map>
#include <chrono>
#include <optional>

// Proton Drive provider.
// Unlike Google Drive / OneDrive, Proton Drive uses Proton SRP auth (not OAuth2)
// and end-to-end encrypts all file names and content using OpenPGP node keys.
//
// Token file fields (JSON, DPAPI-encrypted on Windows):
//   access_token, refresh_token, expires_at   — standard
//   uid                   — Proton user UID (sent as x-pm-uid header)
//   volume_id             — Drive volume ID
//   share_id              — Main share ID
//   root_link_id          — Root folder link ID
//   address_email         — User's Proton email (used as SignatureAddress)
//   address_key_n, _e, _d, _p, _q, _dp, _dq, _qi
//                         — Base64-encoded big-endian MPI bytes of the address RSA key
//
// Paths map to: Proton Drive root / CloudRedirect / {accountId} / {appId} / filename

class ProtonDriveProvider : public CloudProviderBase {
public:
    const char* Name() const override { return "Proton Drive"; }

    bool Init(const std::string& configPath) override;

    bool Upload(const std::string& path, const uint8_t* data, size_t len) override;
    bool UploadBatch(const std::vector<UploadItem>& items) override;
    bool Download(const std::string& path, std::vector<uint8_t>& outData) override;
    bool Remove(const std::string& path) override;
    ExistsStatus CheckExists(const std::string& path) override;
    std::vector<FileInfo> List(const std::string& prefix) override;
    std::vector<std::string> ListSubfolders(const std::string& prefix) override;
    bool ListChecked(const std::string& prefix, std::vector<FileInfo>& outFiles,
                     bool* outComplete = nullptr) override;

protected:
    // ── CloudProviderBase hooks ────────────────────────────────────────────────
    const char* LogTag()            const override { return "[Proton]"; }
    const char* ProviderTag()       const override { return "[ProtonProvider]"; }
    const char* ApiHost()           const override { return "api.proton.me"; }
    const char* TokenEndpointHost() const override { return "api.proton.me"; }
    const char* TokenEndpointPath() const override { return "/auth/v4/refresh"; }
    const char* AuthFailureName()   const override { return "Proton Drive"; }
    const char* RefreshContentType() const override { return "application/json"; }

    std::string BuildRefreshBody(const std::string& refreshToken) const override;
    std::vector<std::string> ExtraRefreshHeaders() const override;
    std::string ParseRefreshAccessToken(const std::string& body) const override;
    std::string ParseRefreshRefreshToken(const std::string& body) const override;
    int64_t ParseRefreshExpiresIn(const std::string& body) const override;
    std::vector<std::string> ExtraApiHeaders() const override;
    bool IsRateLimited(int status, const std::string& body) const override;

private:
    // ── Proton-specific fields (loaded from token file) ────────────────────────
    std::string m_uid;
    std::string m_volumeId;
    std::string m_shareId;
    std::string m_rootLinkId;
    std::string m_addressEmail;

    // ── Address key and share key (lazily loaded/decrypted) ───────────────────
    // m_addressKey is populated directly from raw RSA component fields in the token
    // file (address_key_n/e/d/p/q/dp/dq/qi, base64 big-endian MPI bytes).
    bool m_keysLoaded = false;
    ProtonPGP::RsaKeyPair m_addressKey;

    bool m_shareKeyLoaded = false;
    ProtonPGP::RsaKeyPair m_shareKeyPair;
    std::string m_revisionId; // scratch: set during UploadFile, consumed by CommitFileUpload

    // ── Folder node cache ──────────────────────────────────────────────────────
    // Key: logical path relative to drive root, e.g. "cloudredirect",
    //      "cloudredirect/123456789", "cloudredirect/123456789/570001200"
    struct FolderNode {
        std::string linkId;
        ProtonPGP::RsaKeyPair keyPair;
        std::vector<uint8_t> hashKey; // 32-byte HMAC key for child name hashing
    };
    std::unordered_map<std::string, FolderNode> m_folderCache;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> m_missingFolders;
    mutable std::recursive_mutex m_folderMtx;
    mutable std::recursive_mutex m_folderCreateMtx;

    // ── File node cache ────────────────────────────────────────────────────────
    // Key: "{folderId}:{encryptedName-hash}" — derived from folder link ID + HMAC name hash
    struct FileNode {
        std::string linkId;
        std::vector<uint8_t> contentSessionKey; // AES-256 session key
        int64_t modifiedTime = 0;
        int64_t size = 0;
    };
    std::unordered_map<std::string, FileNode> m_fileCache;
    mutable std::mutex m_fileMtx;

    // ── Raw link data (as returned by /children endpoints) ────────────────────
    struct LinkInfo {
        std::string linkId;
        std::string parentLinkId;
        int         type = 0;         // 1 = folder, 2 = file
        int64_t     modifyTime = 0;
        int64_t     size = 0;
        std::string nameEncrypted;    // base64-encoded PGP message (encrypted with parent key)
        std::string hash;             // hex HMAC-SHA256 of plaintext name
        std::string nodeKey;          // armored PGP secret key (passphrase-protected)
        std::string nodePassphrase;   // base64 PGP message: passphrase encrypted with parent key
        std::string nodeHashKey;      // base64 PGP message: hash-key encrypted with node's own key
        std::string contentKeyPacket; // base64 PGP message: AES session key encrypted with node key (files only)
    };

    // ── Init / token loading ───────────────────────────────────────────────────
    bool LoadProtonFields();
    bool EnsureKeysLoaded();

    // ── Node key helpers ───────────────────────────────────────────────────────

    // Decrypt a node's passphrase using parentKey, then unlock its armored nodeKey.
    bool DecryptNodeKey(const std::string& nodePassphraseMsg,
                        const std::string& nodeKeyArmored,
                        const ProtonPGP::RsaKeyPair& parentKey,
                        ProtonPGP::RsaKeyPair& outKeyPair);

    // Decrypt a node's 32-byte hash key from nodeHashKeyMsg using the node's own key.
    bool DecryptHashKey(const std::string& nodeHashKeyMsg,
                        const ProtonPGP::RsaKeyPair& nodeKey,
                        std::vector<uint8_t>& outHashKey);

    // Decrypt a file's AES session key from contentKeyPacket using the file's node key.
    bool DecryptContentKey(const std::string& contentKeyPacket,
                           const ProtonPGP::RsaKeyPair& fileNodeKey,
                           std::vector<uint8_t>& outSessionKey);

    // Build node key material for a newly created node (folder or file).
    struct NewNodeKey {
        ProtonPGP::RsaKeyPair keyPair;
        std::vector<uint8_t>  hashKey;       // raw 32-byte hash key
        std::string nodeKeyArmored;          // ArmorSecretKey result
        std::string nodePassphraseMsg;       // base64: passphrase encrypted with parent public key
        std::string nodeHashKeyMsg;          // base64: hashKey encrypted with node's own public key
        std::string nodeKeySignature;        // armored PGP signature of nodeKeyArmored by addressKey
        std::string nodePassphraseSignature; // armored PGP signature of nodePassphrase by addressKey
    };
    bool GenerateNodeKey(const FolderNode& parent, NewNodeKey& out);

    // ── API: folder navigation ─────────────────────────────────────────────────

    enum class LookupStatus { Missing, Exists, Error };
    enum class UploadStatus { Success, MissingTarget, Error };

    // Returns the FolderNode for the root link (bootstraps key hierarchy from address key).
    LookupStatus GetRootFolderNode(FolderNode& out);

    // Find or create "CloudRedirect" under drive root.
    LookupStatus GetOrCreateCloudRedirectFolder(FolderNode& out);

    // Find or create accountId subfolder.
    LookupStatus GetOrCreateAccountFolder(uint32_t accountId, FolderNode& out);

    // Find or create appId subfolder.
    LookupStatus GetOrCreateAppFolder(uint32_t accountId, uint32_t appId, FolderNode& out);

    // Resolve (optionally creating) the full folder path for (accountId, appId, relDir).
    // relDir may be empty or "sub/dir" for multi-level relative paths.
    LookupStatus ResolveFolder(uint32_t accountId, uint32_t appId,
                               const std::string& relDir,
                               FolderNode& outFolder, bool create);

    // ── API: children listing ──────────────────────────────────────────────────

    // Fetch raw link list from GET /drive/v2/shares/{shareId}/folders/{linkId}/children.
    bool FetchFolderChildren(const std::string& linkId, std::vector<LinkInfo>& out);

    // Find a child in a folder by HMAC name hash (returns first match).
    LookupStatus FindChildByHash(const FolderNode& parent,
                                 const std::string& nameHash,
                                 LinkInfo* outLink);

    // Find a child folder by plaintext name (hashes internally).
    LookupStatus FindChildFolder(const FolderNode& parent, const std::string& name,
                                 LinkInfo* outLink);

    // Find a child file by plaintext name (hashes internally).
    LookupStatus FindChildFile(const FolderNode& parent, const std::string& name,
                               LinkInfo* outLink);

    // ── API: folder creation ───────────────────────────────────────────────────

    bool CreateFolder(const std::string& name, const FolderNode& parent,
                      FolderNode& outNew);

    std::string BuildCreateFolderBody(const std::string& parentLinkId,
                                      const std::string& nameEncrypted,
                                      const std::string& nameHash,
                                      const NewNodeKey& nk);

    // ── API: file upload ───────────────────────────────────────────────────────

    UploadStatus UploadFile(const std::string& name, const FolderNode& parentFolder,
                            const uint8_t* data, size_t len, int64_t timestamp);

    std::string BuildCreateFileBody(const std::string& parentLinkId,
                                    const std::string& nameEncrypted,
                                    const std::string& nameHash,
                                    const NewNodeKey& nk,
                                    const std::string& contentKeyPacketB64,
                                    const std::string& clientUID);

    // Upload encrypted block data to a block URL obtained from the file create response.
    bool UploadBlock(const std::string& uploadUrl, const std::vector<uint8_t>& ciphertext);

    // Commit a finished file upload (notify Proton the blocks are done).
    bool CommitFileUpload(const std::string& linkId,
                          const std::string& blockToken,
                          int64_t timestamp);

    // ── API: file download ─────────────────────────────────────────────────────

    bool DownloadFile(const LinkInfo& link, const FolderNode& parent,
                      std::vector<uint8_t>& outData);

    // Fetch the block download URL for a file link.
    bool GetDownloadUrl(const std::string& linkId, std::string& outUrl);

    // ── API: delete ────────────────────────────────────────────────────────────

    bool TrashLink(const std::string& linkId);
    bool DeleteTrashedLink(const std::string& linkId);

    // ── API: list (for ListChecked) ────────────────────────────────────────────

    struct RemoteFile {
        std::string linkId;
        std::string relativePath;
        int64_t modifiedTime = 0;
        int64_t size = 0;
    };

    bool ListFolderRecursive(const FolderNode& folder, const std::string& pathPrefix,
                             std::vector<RemoteFile>& out,
                             bool* outComplete = nullptr, int depth = 0);

    // Fully resolve (decrypt) a LinkInfo's plaintext name given the parent's key.
    std::string DecryptLinkName(const LinkInfo& link,
                                const ProtonPGP::RsaKeyPair& parentKey);

    // Decrypt node key + hash key from a LinkInfo and cache the resulting FolderNode.
    bool LoadAndCacheFolderNode(const std::string& cacheKey,
                                const LinkInfo& link,
                                const FolderNode& parent);
};

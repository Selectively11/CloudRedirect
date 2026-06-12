// Proton Drive cloud provider implementation.
// Authentication: Proton SRP tokens (uid + access_token + refresh_token).
// Encryption: end-to-end OpenPGP node key hierarchy via ProtonPGP::.

#include "proton_drive_provider.h"
#include "log.h"
#include "json.h"

#include <cstring>
#include <ctime>
#include <random>

static const char* kAppVersion = "external-drive-cloudredirect@2.1.8-stable";
static const int   kDefaultTokenExpiry = 3600;
static const int   kMaxFolderDepth = 16;

// ── Helpers ───────────────────────────────────────────────────────────────────

static std::string NewClientUID() {
    std::mt19937_64 rng(std::chrono::steady_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<uint64_t> dist;
    uint64_t a = dist(rng), b = dist(rng);
    char buf[37];
    snprintf(buf, sizeof(buf),
             "%08x-%04x-%04x-%04x-%012llx",
             (uint32_t)(a >> 32),
             (uint32_t)((a >> 16) & 0xffff),
             (uint32_t)(a & 0xffff),
             (uint32_t)(b >> 48),
             (unsigned long long)(b & 0x0000ffff'ffffffffULL));
    return std::string(buf);
}

static std::string HexEncode(const std::vector<uint8_t>& v) {
    return ProtonPGP::ToHex(v);
}

static std::string B64(const std::vector<uint8_t>& v) {
    return ProtonPGP::Base64Encode(v.data(), v.size());
}

static bool B64Dec(const std::string& s, std::vector<uint8_t>& out) {
    return ProtonPGP::Base64Decode(s, out);
}

// JSON-escape a string (only handles what we need: no control chars in our values).
static std::string JStr(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    out += '"';
    for (char c : s) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else out += c;
    }
    out += '"';
    return out;
}

// ── CloudProviderBase hooks ────────────────────────────────────────────────────

std::string ProtonDriveProvider::BuildRefreshBody(const std::string& refreshToken) const {
    // Proton refresh uses JSON, not form-urlencoded.
    std::string body = "{";
    body += "\"ResponseType\":\"token\",";
    body += "\"GrantType\":\"refresh_token\",";
    body += "\"RefreshToken\":" + JStr(refreshToken) + ",";
    body += "\"RedirectURI\":\"http://localhost/\",";
    body += "\"State\":\"\"";
    body += "}";
    return body;
}

std::vector<std::string> ProtonDriveProvider::ExtraRefreshHeaders() const {
    if (m_uid.empty()) return {};
    return {"x-pm-uid: " + m_uid};
}

std::string ProtonDriveProvider::ParseRefreshAccessToken(const std::string& body) const {
    return Json::Parse(body)["AccessToken"].str();
}

std::string ProtonDriveProvider::ParseRefreshRefreshToken(const std::string& body) const {
    return Json::Parse(body)["RefreshToken"].str();
}

int64_t ProtonDriveProvider::ParseRefreshExpiresIn(const std::string& body) const {
    (void)body;
    return kDefaultTokenExpiry;
}

std::vector<std::string> ProtonDriveProvider::ExtraApiHeaders() const {
    std::vector<std::string> hdrs;
    hdrs.push_back(std::string("x-pm-appversion: ") + kAppVersion);
    if (!m_uid.empty())
        hdrs.push_back("x-pm-uid: " + m_uid);
    return hdrs;
}

bool ProtonDriveProvider::IsRateLimited(int status, const std::string& body) const {
    if (status == 429) return true;
    // Proton also uses Code 85 for Too Many Requests.
    if (status == 422 || status == 400) {
        auto j = Json::Parse(body);
        int64_t code = j["Code"].integer();
        return code == 85;
    }
    return false;
}

// ── Init / token loading ───────────────────────────────────────────────────────

bool ProtonDriveProvider::Init(const std::string& configPath) {
    if (!CloudProviderBase::Init(configPath)) return false;
    if (!LoadProtonFields()) {
        LOG("%s Warning: Proton-specific fields missing from token file; "
            "authenticate via the CloudRedirect UI", LogTag());
        // Not fatal: provider still initialized, but operations will fail gracefully.
    }
    return true;
}

bool ProtonDriveProvider::LoadProtonFields() {
    if (!m_tokenStore) return false;
    auto content = m_tokenStore->Read(m_tokenPath);
    if (content.empty()) return false;

    auto j = Json::Parse(content);
    m_uid        = j["uid"].str();
    m_volumeId   = j["volume_id"].str();
    m_shareId    = j["share_id"].str();
    m_rootLinkId = j["root_link_id"].str();
    m_addressEmail = j["address_email"].str();

    // Decode raw RSA MPI components directly into m_addressKey.
    auto decodeComp = [&](const char* field, std::vector<uint8_t>& out) {
        std::string b64 = j[field].str();
        if (b64.empty()) return;
        B64Dec(b64, out);
    };
    decodeComp("address_key_n",  m_addressKey.n);
    decodeComp("address_key_e",  m_addressKey.e);
    decodeComp("address_key_d",  m_addressKey.d);
    decodeComp("address_key_p",  m_addressKey.p);
    decodeComp("address_key_q",  m_addressKey.q);
    decodeComp("address_key_dp", m_addressKey.dp);
    decodeComp("address_key_dq", m_addressKey.dq);
    decodeComp("address_key_qi", m_addressKey.qi);

    if (m_uid.empty() || m_shareId.empty() || m_rootLinkId.empty()) {
        LOG("%s LoadProtonFields: missing required fields (uid/share_id/root_link_id)", LogTag());
        return false;
    }
    return true;
}

bool ProtonDriveProvider::EnsureKeysLoaded() {
    if (m_keysLoaded) return true;
    if (m_addressKey.n.empty() || m_addressKey.d.empty()) {
        LOG("%s EnsureKeysLoaded: address key components not loaded", LogTag());
        return false;
    }
    m_keysLoaded = true;
    return true;
}

// ── Node key helpers ───────────────────────────────────────────────────────────

bool ProtonDriveProvider::DecryptNodeKey(const std::string& nodePassphraseMsg,
                                          const std::string& nodeKeyArmored,
                                          const ProtonPGP::RsaKeyPair& parentKey,
                                          ProtonPGP::RsaKeyPair& outKeyPair) {
    std::vector<uint8_t> passBytes;
    if (!ProtonPGP::DecryptMessage(nodePassphraseMsg, parentKey, passBytes)) {
        LOG("%s DecryptNodeKey: failed to decrypt node passphrase", LogTag());
        return false;
    }
    std::string pass(passBytes.begin(), passBytes.end());
    if (!ProtonPGP::LoadSecretKey(nodeKeyArmored, pass, outKeyPair)) {
        LOG("%s DecryptNodeKey: failed to load node secret key", LogTag());
        return false;
    }
    return true;
}

bool ProtonDriveProvider::DecryptHashKey(const std::string& nodeHashKeyMsg,
                                          const ProtonPGP::RsaKeyPair& nodeKey,
                                          std::vector<uint8_t>& outHashKey) {
    if (!ProtonPGP::DecryptMessage(nodeHashKeyMsg, nodeKey, outHashKey)) {
        LOG("%s DecryptHashKey: failed to decrypt hash key", LogTag());
        return false;
    }
    return true;
}

bool ProtonDriveProvider::DecryptContentKey(const std::string& contentKeyPacket,
                                             const ProtonPGP::RsaKeyPair& fileNodeKey,
                                             std::vector<uint8_t>& outSessionKey) {
    if (!ProtonPGP::DecryptMessage(contentKeyPacket, fileNodeKey, outSessionKey)) {
        LOG("%s DecryptContentKey: failed to decrypt content session key", LogTag());
        return false;
    }
    return true;
}

bool ProtonDriveProvider::GenerateNodeKey(const FolderNode& parent, NewNodeKey& out) {
    // Generate RSA-2048 node key pair.
    if (!ProtonPGP::GenerateRsaKeyPair(out.keyPair)) return false;

    // Random 32-byte passphrase.
    std::vector<uint8_t> passBytes;
    if (!ProtonPGP::GenerateSessionKey(passBytes)) return false;
    std::string pass(passBytes.begin(), passBytes.end());

    // Armor the secret key with that passphrase.
    if (!ProtonPGP::ArmorSecretKey(out.keyPair, pass, out.nodeKeyArmored)) return false;

    // Random 32-byte hash key.
    if (!ProtonPGP::GenerateSessionKey(out.hashKey)) return false;

    // Encrypt passphrase with parent's public key → nodePassphrase (armored PGP).
    std::string passPgp;
    if (!ProtonPGP::EncryptMessage(parent.keyPair.n, parent.keyPair.e,
                                    passBytes.data(), passBytes.size(), passPgp))
        return false;
    out.nodePassphraseMsg = passPgp;

    // Encrypt hash key with node's own public key → nodeHashKey (armored PGP).
    std::string hashKeyPgp;
    if (!ProtonPGP::EncryptMessage(out.keyPair.n, out.keyPair.e,
                                    out.hashKey.data(), out.hashKey.size(), hashKeyPgp))
        return false;
    out.nodeHashKeyMsg = hashKeyPgp;

    // Sign nodeKeyArmored with address key.
    if (!m_keysLoaded) {
        out.nodeKeySignature.clear();
        out.nodePassphraseSignature.clear();
    } else {
        const uint8_t* nkData = reinterpret_cast<const uint8_t*>(out.nodeKeyArmored.data());
        ProtonPGP::SignDetached(m_addressKey, nkData, out.nodeKeyArmored.size(),
                                out.nodeKeySignature);
        ProtonPGP::SignDetached(m_addressKey,
                                passBytes.data(), passBytes.size(),
                                out.nodePassphraseSignature);
    }
    return true;
}

// ── Share key loading ──────────────────────────────────────────────────────────

// Fetch the share's armored key + passphrase, decrypt with address key.
ProtonDriveProvider::LookupStatus ProtonDriveProvider::GetRootFolderNode(FolderNode& out) {
    // Check cache.
    {
        std::lock_guard<std::recursive_mutex> lk(m_folderMtx);
        auto it = m_folderCache.find("root");
        if (it != m_folderCache.end()) { out = it->second; return LookupStatus::Exists; }
    }

    if (!EnsureKeysLoaded()) return LookupStatus::Error;

    // Load share key.
    if (!m_shareKeyLoaded) {
        std::string sharePath = std::string("/drive/v2/shares/") + m_shareId;
        auto resp = ApiGet(sharePath);
        if (resp.status != 200) {
            LOG("%s GetRootFolderNode: failed to fetch share (HTTP %d)", LogTag(), resp.status);
            return LookupStatus::Error;
        }
        auto j = Json::Parse(resp.body);
        std::string shareKey        = j["Share"]["Key"].str();
        std::string sharePassphrase = j["Share"]["Passphrase"].str();

        // Share.Passphrase is an armored PGP message encrypted with the address key.
        // Some older API revisions base64-encode it again — try the direct form first.
        std::vector<uint8_t> decrypted;
        bool ok = ProtonPGP::DecryptMessage(sharePassphrase, m_addressKey, decrypted);
        if (!ok) {
            std::vector<uint8_t> sharePassBytes;
            if (ProtonPGP::Base64Decode(sharePassphrase, sharePassBytes)) {
                std::string inner(sharePassBytes.begin(), sharePassBytes.end());
                ok = ProtonPGP::DecryptMessage(inner, m_addressKey, decrypted);
            }
        }
        if (!ok) {
            LOG("%s GetRootFolderNode: failed to decrypt share passphrase", LogTag());
            return LookupStatus::Error;
        }

        std::string kpass(decrypted.begin(), decrypted.end());
        if (!ProtonPGP::LoadSecretKey(shareKey, kpass, m_shareKeyPair)) {
            LOG("%s GetRootFolderNode: failed to load share key pair", LogTag());
            return LookupStatus::Error;
        }
        m_shareKeyLoaded = true;
    }

    // Fetch root link.
    std::string rootPath = std::string("/drive/v2/shares/") + m_shareId
                         + "/links/" + m_rootLinkId;
    auto resp = ApiGet(rootPath);
    if (resp.status != 200) {
        LOG("%s GetRootFolderNode: failed to fetch root link (HTTP %d)", LogTag(), resp.status);
        return LookupStatus::Error;
    }
    auto jl = Json::Parse(resp.body)["Link"];
    std::string nodeKey        = jl["NodeKey"].str();
    std::string nodePassphrase = jl["NodePassphrase"].str();
    std::string nodeHashKey    = jl["NodeHashKey"].str();

    FolderNode root;
    root.linkId = m_rootLinkId;
    if (!DecryptNodeKey(nodePassphrase, nodeKey, m_shareKeyPair, root.keyPair)) {
        LOG("%s GetRootFolderNode: failed to decrypt root node key", LogTag());
        return LookupStatus::Error;
    }
    if (!DecryptHashKey(nodeHashKey, root.keyPair, root.hashKey)) {
        LOG("%s GetRootFolderNode: failed to decrypt root hash key", LogTag());
        return LookupStatus::Error;
    }

    {
        std::lock_guard<std::recursive_mutex> lk(m_folderMtx);
        m_folderCache["root"] = root;
    }
    out = root;
    return LookupStatus::Exists;
}

// ── API: children listing ──────────────────────────────────────────────────────

bool ProtonDriveProvider::FetchFolderChildren(const std::string& linkId,
                                               std::vector<LinkInfo>& out) {
    int page = 0;
    static const int kPageSize = 150;
    while (true) {
        std::string path = std::string("/drive/v2/shares/") + m_shareId
                         + "/folders/" + linkId
                         + "/children?Page=" + std::to_string(page)
                         + "&PageSize=" + std::to_string(kPageSize);
        auto resp = ApiGet(path);
        if (resp.status != 200) {
            LOG("%s FetchFolderChildren: HTTP %d for link %s",
                LogTag(), resp.status, linkId.c_str());
            return false;
        }
        auto j = Json::Parse(resp.body);
        auto& links = j["Links"];
        int count = 0;
        for (int i = 0; ; ++i) {
            auto lj = links[i];
            std::string lid = lj["LinkID"].str();
            if (lid.empty()) break;
            ++count;
            LinkInfo li;
            li.linkId        = lid;
            li.parentLinkId  = lj["ParentLinkID"].str();
            li.type          = (int)lj["Type"].integer();
            li.modifyTime    = lj["ModifyTime"].integer();
            li.size          = lj["Size"].integer();
            li.nameEncrypted = lj["Name"].str();
            li.hash          = lj["Hash"].str();
            li.nodeKey       = lj["NodeKey"].str();
            li.nodePassphrase = lj["NodePassphrase"].str();
            li.nodeHashKey   = lj["NodeHashKey"].str();
            // File-only content key.
            li.contentKeyPacket = lj["FileProperties"]["ContentKeyPacket"].str();
            // Skip links in Trash state (State == 2).
            int64_t state = lj["State"].integer();
            if (state == 2) continue;
            out.push_back(std::move(li));
        }
        if (count < kPageSize) break;
        ++page;
    }
    return true;
}

ProtonDriveProvider::LookupStatus ProtonDriveProvider::FindChildByHash(
    const FolderNode& parent,
    const std::string& nameHash,
    LinkInfo* outLink)
{
    std::vector<LinkInfo> children;
    if (!FetchFolderChildren(parent.linkId, children)) return LookupStatus::Error;
    for (auto& li : children) {
        if (li.hash == nameHash) {
            if (outLink) *outLink = li;
            return LookupStatus::Exists;
        }
    }
    return LookupStatus::Missing;
}

ProtonDriveProvider::LookupStatus ProtonDriveProvider::FindChildFolder(
    const FolderNode& parent, const std::string& name, LinkInfo* outLink)
{
    auto hash = HexEncode(ProtonPGP::HashNodeName(name, parent.hashKey));
    auto status = FindChildByHash(parent, hash, outLink);
    if (status == LookupStatus::Exists && outLink && outLink->type != 1)
        return LookupStatus::Missing; // hash collision with a file
    return status;
}

ProtonDriveProvider::LookupStatus ProtonDriveProvider::FindChildFile(
    const FolderNode& parent, const std::string& name, LinkInfo* outLink)
{
    auto hash = HexEncode(ProtonPGP::HashNodeName(name, parent.hashKey));
    auto status = FindChildByHash(parent, hash, outLink);
    if (status == LookupStatus::Exists && outLink && outLink->type != 2)
        return LookupStatus::Missing;
    return status;
}

// ── API: folder creation / caching ────────────────────────────────────────────

std::string ProtonDriveProvider::BuildCreateFolderBody(
    const std::string& parentLinkId,
    const std::string& nameEncrypted,
    const std::string& nameHash,
    const NewNodeKey& nk)
{
    std::string body = "{";
    body += "\"Name\":"              + JStr(nameEncrypted) + ",";
    body += "\"Hash\":"              + JStr(nameHash) + ",";
    body += "\"ParentLinkID\":"      + JStr(parentLinkId) + ",";
    body += "\"NodeKey\":"           + JStr(nk.nodeKeyArmored) + ",";
    body += "\"NodePassphrase\":"    + JStr(nk.nodePassphraseMsg) + ",";
    body += "\"NodePassphraseSignature\":" + JStr(nk.nodePassphraseSignature) + ",";
    body += "\"NodeHashKey\":"       + JStr(nk.nodeHashKeyMsg) + ",";
    body += "\"SignatureAddress\":"  + JStr(m_addressEmail);
    body += "}";
    return body;
}

bool ProtonDriveProvider::CreateFolder(const std::string& name, const FolderNode& parent,
                                        FolderNode& outNew) {
    if (!EnsureKeysLoaded()) return false;

    NewNodeKey nk;
    if (!GenerateNodeKey(parent, nk)) {
        LOG("%s CreateFolder: GenerateNodeKey failed for '%s'", LogTag(), name.c_str());
        return false;
    }

    // Encrypt name with parent's public key (armored PGP message).
    std::string encName;
    if (!ProtonPGP::EncryptMessage(parent.keyPair.n, parent.keyPair.e,
                                    reinterpret_cast<const uint8_t*>(name.data()),
                                    name.size(), encName))
        return false;

    std::string hash = HexEncode(ProtonPGP::HashNodeName(name, parent.hashKey));

    std::string reqBody = BuildCreateFolderBody(parent.linkId, encName, hash, nk);
    std::string apiPath = std::string("/drive/v2/shares/") + m_shareId + "/folders";

    auto resp = ApiRequest("POST", apiPath, reqBody, "application/json");
    if (resp.status != 200 && resp.status != 201) {
        LOG("%s CreateFolder: HTTP %d creating '%s'", LogTag(), resp.status, name.c_str());
        return false;
    }

    auto j = Json::Parse(resp.body);
    std::string linkId = j["Folder"]["ID"].str();
    if (linkId.empty()) {
        LOG("%s CreateFolder: no Folder.ID in response", LogTag());
        return false;
    }

    outNew.linkId   = linkId;
    outNew.keyPair  = nk.keyPair;
    outNew.hashKey  = nk.hashKey;
    return true;
}

bool ProtonDriveProvider::LoadAndCacheFolderNode(const std::string& cacheKey,
                                                   const LinkInfo& link,
                                                   const FolderNode& parent) {
    FolderNode fn;
    fn.linkId = link.linkId;
    if (!DecryptNodeKey(link.nodePassphrase, link.nodeKey, parent.keyPair, fn.keyPair))
        return false;
    if (!DecryptHashKey(link.nodeHashKey, fn.keyPair, fn.hashKey))
        return false;
    std::lock_guard<std::recursive_mutex> lk(m_folderMtx);
    m_folderCache[cacheKey] = fn;
    return true;
}

// ── API: folder hierarchy ──────────────────────────────────────────────────────

ProtonDriveProvider::LookupStatus ProtonDriveProvider::GetOrCreateCloudRedirectFolder(
    FolderNode& out)
{
    static const char* kFolderName = "CloudRedirect";
    static const char* kCacheKey   = "cloudredirect";

    {
        std::lock_guard<std::recursive_mutex> lk(m_folderMtx);
        auto it = m_folderCache.find(kCacheKey);
        if (it != m_folderCache.end()) { out = it->second; return LookupStatus::Exists; }
    }

    FolderNode root;
    if (GetRootFolderNode(root) != LookupStatus::Exists) return LookupStatus::Error;

    // Serialize create to prevent duplicates.
    std::lock_guard<std::recursive_mutex> createLk(m_folderCreateMtx);
    {
        std::lock_guard<std::recursive_mutex> lk(m_folderMtx);
        auto it = m_folderCache.find(kCacheKey);
        if (it != m_folderCache.end()) { out = it->second; return LookupStatus::Exists; }
    }

    LinkInfo li;
    auto status = FindChildFolder(root, kFolderName, &li);
    if (status == LookupStatus::Error) return LookupStatus::Error;

    if (status == LookupStatus::Missing) {
        FolderNode newFolder;
        if (!CreateFolder(kFolderName, root, newFolder)) return LookupStatus::Error;
        {
            std::lock_guard<std::recursive_mutex> lk(m_folderMtx);
            m_folderCache[kCacheKey] = newFolder;
        }
        out = newFolder;
        return LookupStatus::Exists;
    }

    if (!LoadAndCacheFolderNode(kCacheKey, li, root)) return LookupStatus::Error;
    {
        std::lock_guard<std::recursive_mutex> lk(m_folderMtx);
        out = m_folderCache[kCacheKey];
    }
    return LookupStatus::Exists;
}

ProtonDriveProvider::LookupStatus ProtonDriveProvider::GetOrCreateAccountFolder(
    uint32_t accountId, FolderNode& out)
{
    std::string name = std::to_string(accountId);
    std::string cacheKey = "cloudredirect/" + name;

    {
        std::lock_guard<std::recursive_mutex> lk(m_folderMtx);
        auto it = m_folderCache.find(cacheKey);
        if (it != m_folderCache.end()) { out = it->second; return LookupStatus::Exists; }
    }

    FolderNode crFolder;
    if (GetOrCreateCloudRedirectFolder(crFolder) != LookupStatus::Exists)
        return LookupStatus::Error;

    std::lock_guard<std::recursive_mutex> createLk(m_folderCreateMtx);
    {
        std::lock_guard<std::recursive_mutex> lk(m_folderMtx);
        auto it = m_folderCache.find(cacheKey);
        if (it != m_folderCache.end()) { out = it->second; return LookupStatus::Exists; }
    }

    LinkInfo li;
    auto status = FindChildFolder(crFolder, name, &li);
    if (status == LookupStatus::Error) return LookupStatus::Error;

    if (status == LookupStatus::Missing) {
        FolderNode newFolder;
        if (!CreateFolder(name, crFolder, newFolder)) return LookupStatus::Error;
        {
            std::lock_guard<std::recursive_mutex> lk(m_folderMtx);
            m_folderCache[cacheKey] = newFolder;
        }
        out = newFolder;
        return LookupStatus::Exists;
    }

    if (!LoadAndCacheFolderNode(cacheKey, li, crFolder)) return LookupStatus::Error;
    {
        std::lock_guard<std::recursive_mutex> lk(m_folderMtx);
        out = m_folderCache[cacheKey];
    }
    return LookupStatus::Exists;
}

ProtonDriveProvider::LookupStatus ProtonDriveProvider::GetOrCreateAppFolder(
    uint32_t accountId, uint32_t appId, FolderNode& out)
{
    std::string appName = std::to_string(appId);
    std::string cacheKey = "cloudredirect/" + std::to_string(accountId) + "/" + appName;

    {
        std::lock_guard<std::recursive_mutex> lk(m_folderMtx);
        auto it = m_folderCache.find(cacheKey);
        if (it != m_folderCache.end()) { out = it->second; return LookupStatus::Exists; }
    }

    FolderNode accFolder;
    if (GetOrCreateAccountFolder(accountId, accFolder) != LookupStatus::Exists)
        return LookupStatus::Error;

    std::lock_guard<std::recursive_mutex> createLk(m_folderCreateMtx);
    {
        std::lock_guard<std::recursive_mutex> lk(m_folderMtx);
        auto it = m_folderCache.find(cacheKey);
        if (it != m_folderCache.end()) { out = it->second; return LookupStatus::Exists; }
    }

    LinkInfo li;
    auto status = FindChildFolder(accFolder, appName, &li);
    if (status == LookupStatus::Error) return LookupStatus::Error;

    if (status == LookupStatus::Missing) {
        FolderNode newFolder;
        if (!CreateFolder(appName, accFolder, newFolder)) return LookupStatus::Error;
        {
            std::lock_guard<std::recursive_mutex> lk(m_folderMtx);
            m_folderCache[cacheKey] = newFolder;
        }
        out = newFolder;
        return LookupStatus::Exists;
    }

    if (!LoadAndCacheFolderNode(cacheKey, li, accFolder)) return LookupStatus::Error;
    {
        std::lock_guard<std::recursive_mutex> lk(m_folderMtx);
        out = m_folderCache[cacheKey];
    }
    return LookupStatus::Exists;
}

ProtonDriveProvider::LookupStatus ProtonDriveProvider::ResolveFolder(
    uint32_t accountId, uint32_t appId, const std::string& relDir,
    FolderNode& outFolder, bool create)
{
    auto status = GetOrCreateAppFolder(accountId, appId, outFolder);
    if (status != LookupStatus::Exists) return status;
    if (relDir.empty()) return LookupStatus::Exists;

    // Walk relDir components (e.g. "sub/dir").
    std::string baseCacheKey = "cloudredirect/" + std::to_string(accountId)
                             + "/" + std::to_string(appId);
    FolderNode cur = outFolder;
    std::string curCache = baseCacheKey;

    std::string remaining = relDir;
    while (!remaining.empty()) {
        if ((int)(curCache.size()) > 256 || m_folderCache.size() > 10000) {
            LOG("%s ResolveFolder: depth/cache limit hit", LogTag()); return LookupStatus::Error;
        }
        size_t slash = remaining.find('/');
        std::string component = (slash != std::string::npos)
                                ? remaining.substr(0, slash) : remaining;
        remaining = (slash != std::string::npos) ? remaining.substr(slash + 1) : "";
        if (component.empty()) continue;

        std::string childCache = curCache + "/" + component;
        {
            std::lock_guard<std::recursive_mutex> lk(m_folderMtx);
            auto it = m_folderCache.find(childCache);
            if (it != m_folderCache.end()) { cur = it->second; curCache = childCache; continue; }
        }

        LinkInfo li;
        auto cs = FindChildFolder(cur, component, &li);
        if (cs == LookupStatus::Error) return LookupStatus::Error;
        if (cs == LookupStatus::Missing) {
            if (!create) return LookupStatus::Missing;
            std::lock_guard<std::recursive_mutex> createLk(m_folderCreateMtx);
            {
                std::lock_guard<std::recursive_mutex> lk(m_folderMtx);
                auto it = m_folderCache.find(childCache);
                if (it != m_folderCache.end()) { cur = it->second; curCache = childCache; continue; }
            }
            FolderNode newF;
            if (!CreateFolder(component, cur, newF)) return LookupStatus::Error;
            {
                std::lock_guard<std::recursive_mutex> lk(m_folderMtx);
                m_folderCache[childCache] = newF;
            }
            cur = newF;
        } else {
            if (!LoadAndCacheFolderNode(childCache, li, cur)) return LookupStatus::Error;
            std::lock_guard<std::recursive_mutex> lk(m_folderMtx);
            cur = m_folderCache[childCache];
        }
        curCache = childCache;
    }
    outFolder = cur;
    return LookupStatus::Exists;
}

// ── API: file upload ───────────────────────────────────────────────────────────

std::string ProtonDriveProvider::BuildCreateFileBody(
    const std::string& parentLinkId,
    const std::string& nameEncrypted,
    const std::string& nameHash,
    const NewNodeKey& nk,
    const std::string& contentKeyPacketB64,
    const std::string& clientUID)
{
    std::string body = "{";
    body += "\"Name\":"                       + JStr(nameEncrypted) + ",";
    body += "\"Hash\":"                       + JStr(nameHash) + ",";
    body += "\"ParentLinkID\":"               + JStr(parentLinkId) + ",";
    body += "\"NodeKey\":"                    + JStr(nk.nodeKeyArmored) + ",";
    body += "\"NodePassphrase\":"             + JStr(nk.nodePassphraseMsg) + ",";
    body += "\"NodePassphraseSignature\":"    + JStr(nk.nodePassphraseSignature) + ",";
    body += "\"SignatureAddress\":"           + JStr(m_addressEmail) + ",";
    body += "\"ContentKeyPacket\":"           + JStr(contentKeyPacketB64) + ",";
    body += "\"ContentKeyPacketSignature\":\"\",";
    body += "\"MIMEType\":\"application/octet-stream\",";
    body += "\"ClientUID\":"                  + JStr(clientUID);
    body += "}";
    return body;
}

bool ProtonDriveProvider::UploadBlock(const std::string& uploadUrl,
                                       const std::vector<uint8_t>& ciphertext) {
    std::string body(ciphertext.begin(), ciphertext.end());
    auto resp = RequestUrl("PUT", uploadUrl, body, {"Content-Type: application/octet-stream"});
    if (resp.status != 200 && resp.status != 204) {
        LOG("%s UploadBlock: HTTP %d", LogTag(), resp.status);
        return false;
    }
    return true;
}

bool ProtonDriveProvider::CommitFileUpload(const std::string& linkId,
                                            const std::string& blockToken,
                                            int64_t timestamp) {
    if (m_revisionId.empty()) {
        LOG("%s CommitFileUpload: no revision ID", LogTag());
        return false;
    }
    std::string path = std::string("/drive/v2/shares/") + m_shareId
                     + "/files/" + linkId
                     + "/revisions/" + m_revisionId;
    std::string body = "{";
    body += "\"BlockList\":[{\"Index\":0,\"Token\":" + JStr(blockToken) + "}],";
    body += "\"State\":1,";
    body += "\"ManifestSignature\":\"\",";
    body += "\"SignatureAddress\":" + JStr(m_addressEmail) + ",";
    body += "\"XAttr\":\"\",";
    body += "\"CreationTime\":" + std::to_string(timestamp);
    body += "}";

    auto resp = ApiRequest("PUT", path, body, "application/json");
    if (resp.status != 200) {
        LOG("%s CommitFileUpload: HTTP %d", LogTag(), resp.status);
        return false;
    }
    m_revisionId.clear();
    return true;
}

ProtonDriveProvider::UploadStatus ProtonDriveProvider::UploadFile(
    const std::string& name, const FolderNode& parentFolder,
    const uint8_t* data, size_t len, int64_t timestamp)
{
    if (!EnsureKeysLoaded()) return UploadStatus::Error;

    // Generate file node key.
    NewNodeKey nk;
    if (!GenerateNodeKey(parentFolder, nk)) return UploadStatus::Error;

    // Generate AES-256 session key for content.
    std::vector<uint8_t> sessionKey;
    if (!ProtonPGP::GenerateSessionKey(sessionKey)) return UploadStatus::Error;

    // Encrypt content.
    std::vector<uint8_t> ciphertext;
    if (!ProtonPGP::AesGcmEncrypt(sessionKey, data, len, ciphertext)) return UploadStatus::Error;

    // Encrypt session key with file node's public key (armored PGP message).
    std::string contentKeyMsg;
    if (!ProtonPGP::EncryptMessage(nk.keyPair.n, nk.keyPair.e,
                                    sessionKey.data(), sessionKey.size(), contentKeyMsg))
        return UploadStatus::Error;

    // Encrypt file name with parent's public key (armored PGP message).
    std::string encName;
    if (!ProtonPGP::EncryptMessage(parentFolder.keyPair.n, parentFolder.keyPair.e,
                                    reinterpret_cast<const uint8_t*>(name.data()),
                                    name.size(), encName))
        return UploadStatus::Error;
    std::string hash = HexEncode(ProtonPGP::HashNodeName(name, parentFolder.hashKey));

    std::string clientUID = NewClientUID();
    std::string body = BuildCreateFileBody(parentFolder.linkId, encName, hash,
                                           nk, contentKeyMsg, clientUID);

    // Step 1: Create file.
    std::string apiPath = std::string("/drive/v2/shares/") + m_shareId + "/files";
    auto resp = ApiRequest("POST", apiPath, body, "application/json");
    if (resp.status != 200 && resp.status != 201) {
        LOG("%s UploadFile: create HTTP %d for '%s'", LogTag(), resp.status, name.c_str());
        return UploadStatus::Error;
    }
    auto jf = Json::Parse(resp.body);
    std::string linkId     = jf["File"]["ID"].str();
    std::string revisionId = jf["File"]["RevisionID"].str();
    if (linkId.empty() || revisionId.empty()) {
        LOG("%s UploadFile: missing File.ID or RevisionID", LogTag());
        return UploadStatus::Error;
    }
    m_revisionId = revisionId;

    // Step 2: Request block upload URLs.
    std::string blockPath = std::string("/drive/v2/shares/") + m_shareId
                          + "/files/" + linkId
                          + "/revisions/" + revisionId + "/blocks";

    // Compute SHA-256 of ciphertext for block hash (Proton requires it).
    // We don't have a standalone SHA-256 here, so leave it empty (accepted by most
    // server versions when signature is also empty).
    std::string blockBody = "{\"BlockList\":[{\"Index\":0,\"Size\":"
                          + std::to_string(ciphertext.size())
                          + ",\"EncSignature\":\"\",\"Hash\":\"\"}]}";
    auto bresp = ApiRequest("POST", blockPath, blockBody, "application/json");
    if (bresp.status != 200 && bresp.status != 201) {
        LOG("%s UploadFile: block URL request HTTP %d", LogTag(), bresp.status);
        return UploadStatus::Error;
    }
    auto jb = Json::Parse(bresp.body);
    std::string uploadUrl  = jb["UploadLinks"][(size_t)0]["URL"].str();
    std::string blockToken = jb["UploadLinks"][(size_t)0]["Token"].str();
    if (uploadUrl.empty()) {
        LOG("%s UploadFile: no UploadLinks[0].URL", LogTag());
        return UploadStatus::Error;
    }

    // Step 3: Upload block.
    if (!UploadBlock(uploadUrl, ciphertext)) return UploadStatus::Error;

    // Step 4: Commit revision.
    if (!CommitFileUpload(linkId, blockToken, timestamp)) return UploadStatus::Error;

    // Update file cache.
    {
        std::lock_guard<std::mutex> lk(m_fileMtx);
        FileNode fn;
        fn.linkId = linkId;
        fn.contentSessionKey = sessionKey;
        fn.modifiedTime = timestamp;
        fn.size = (int64_t)len;
        m_fileCache[parentFolder.linkId + ":" + hash] = fn;
    }
    return UploadStatus::Success;
}

// ── API: file download ─────────────────────────────────────────────────────────

std::string ProtonDriveProvider::DecryptLinkName(const LinkInfo& link,
                                                   const ProtonPGP::RsaKeyPair& parentKey) {
    std::vector<uint8_t> plaintext;
    if (!ProtonPGP::DecryptMessage(link.nameEncrypted, parentKey, plaintext)) return {};
    return std::string(plaintext.begin(), plaintext.end());
}

bool ProtonDriveProvider::GetDownloadUrl(const std::string& linkId, std::string& outUrl) {
    std::string path = std::string("/drive/v2/shares/") + m_shareId
                     + "/files/" + linkId + "/revisions/latest";
    auto resp = ApiGet(path);
    if (resp.status != 200) {
        LOG("%s GetDownloadUrl: HTTP %d for link %s", LogTag(), resp.status, linkId.c_str());
        return false;
    }
    auto j = Json::Parse(resp.body);
    outUrl = j["Revision"]["Blocks"][(size_t)0]["URL"].str();
    if (outUrl.empty()) {
        // Fallback field name used by some API versions.
        outUrl = j["Revision"]["Blocks"][(size_t)0]["DownloadURL"].str();
    }
    return !outUrl.empty();
}

bool ProtonDriveProvider::DownloadFile(const LinkInfo& link, const FolderNode& parent,
                                        std::vector<uint8_t>& outData) {
    // Decrypt the file's node key.
    ProtonPGP::RsaKeyPair fileNodeKey;
    if (!DecryptNodeKey(link.nodePassphrase, link.nodeKey, parent.keyPair, fileNodeKey)) {
        LOG("%s DownloadFile: failed to decrypt file node key", LogTag());
        return false;
    }

    // Decrypt the content session key (contentKeyPacket is an armored PGP message).
    std::vector<uint8_t> sessionKey;
    if (link.contentKeyPacket.empty()) {
        LOG("%s DownloadFile: no contentKeyPacket", LogTag());
        return false;
    }
    if (!DecryptContentKey(link.contentKeyPacket, fileNodeKey, sessionKey)) return false;

    // Get block download URL.
    std::string url;
    if (!GetDownloadUrl(link.linkId, url)) return false;

    // Download the encrypted block.
    auto dresp = RequestUrl("GET", url, {}, {});
    if (dresp.status != 200) {
        LOG("%s DownloadFile: block download HTTP %d", LogTag(), dresp.status);
        return false;
    }

    std::vector<uint8_t> ciphertext(dresp.body.begin(), dresp.body.end());
    if (!ProtonPGP::AesGcmDecrypt(sessionKey, ciphertext.data(), ciphertext.size(), outData)) {
        LOG("%s DownloadFile: AES-GCM decryption failed", LogTag());
        return false;
    }
    return true;
}

// ── API: delete ────────────────────────────────────────────────────────────────

bool ProtonDriveProvider::TrashLink(const std::string& linkId) {
    std::string path = std::string("/drive/v2/shares/") + m_shareId + "/links/trash";
    std::string body = "{\"LinkIDs\":[" + JStr(linkId) + "]}";
    auto resp = ApiRequest("POST", path, body, "application/json");
    if (resp.status != 200) {
        LOG("%s TrashLink: HTTP %d for link %s", LogTag(), resp.status, linkId.c_str());
        return false;
    }
    return true;
}

bool ProtonDriveProvider::DeleteTrashedLink(const std::string& linkId) {
    std::string path = std::string("/drive/v2/shares/") + m_shareId + "/trash/links";
    std::string body = "{\"LinkIDs\":[" + JStr(linkId) + "]}";
    auto resp = ApiRequest("DELETE", path, body, "application/json");
    if (resp.status != 200) {
        LOG("%s DeleteTrashedLink: HTTP %d", LogTag(), resp.status);
        return false;
    }
    return true;
}

// ── List recursive ─────────────────────────────────────────────────────────────

bool ProtonDriveProvider::ListFolderRecursive(const FolderNode& folder,
                                               const std::string& pathPrefix,
                                               std::vector<RemoteFile>& out,
                                               bool* outComplete, int depth) {
    if (depth > kMaxFolderDepth) {
        if (outComplete) *outComplete = false;
        return true;
    }

    std::vector<LinkInfo> children;
    if (!FetchFolderChildren(folder.linkId, children)) return false;

    for (auto& li : children) {
        if (li.type == 1) {
            // Subfolder: recursively list.
            FolderNode childFolder;
            if (!DecryptNodeKey(li.nodePassphrase, li.nodeKey, folder.keyPair, childFolder.keyPair))
                continue;
            if (!DecryptHashKey(li.nodeHashKey, childFolder.keyPair, childFolder.hashKey))
                continue;
            childFolder.linkId = li.linkId;
            std::string childName = DecryptLinkName(li, folder.keyPair);
            std::string childPrefix = pathPrefix.empty() ? childName : pathPrefix + "/" + childName;
            ListFolderRecursive(childFolder, childPrefix, out, outComplete, depth + 1);
        } else if (li.type == 2) {
            // File: add to list.
            std::string fileName = DecryptLinkName(li, folder.keyPair);
            RemoteFile rf;
            rf.linkId = li.linkId;
            rf.relativePath = pathPrefix.empty() ? fileName : pathPrefix + "/" + fileName;
            rf.modifiedTime = li.modifyTime;
            rf.size = li.size;
            out.push_back(std::move(rf));
        }
    }
    return true;
}

// ── ICloudProvider public methods ──────────────────────────────────────────────

bool ProtonDriveProvider::Upload(const std::string& path, const uint8_t* data, size_t len) {
    uint32_t accountId, appId;
    std::string relFilename;
    if (!ParsePath(path, accountId, appId, relFilename) || relFilename.empty()) {
        LOG("%s Upload: bad path '%s'", LogTag(), path.c_str());
        return false;
    }

    // Split relFilename into directory + leaf name.
    size_t lastSlash = relFilename.rfind('/');
    std::string relDir  = (lastSlash != std::string::npos) ? relFilename.substr(0, lastSlash) : "";
    std::string leafName = (lastSlash != std::string::npos) ? relFilename.substr(lastSlash + 1)
                                                             : relFilename;

    FolderNode parentFolder;
    auto status = ResolveFolder(accountId, appId, relDir, parentFolder, true);
    if (status != LookupStatus::Exists) {
        LOG("%s Upload: failed to resolve/create parent folder", LogTag());
        return false;
    }

    int64_t timestamp = (int64_t)std::time(nullptr);
    auto result = UploadFile(leafName, parentFolder, data, len, timestamp);
    return result == UploadStatus::Success;
}

bool ProtonDriveProvider::UploadBatch(const std::vector<UploadItem>& items) {
    bool ok = true;
    for (const auto& item : items) {
        if (!Upload(item.path, item.data.data(), item.data.size())) ok = false;
    }
    return ok;
}

bool ProtonDriveProvider::Download(const std::string& path, std::vector<uint8_t>& outData) {
    uint32_t accountId, appId;
    std::string relFilename;
    if (!ParsePath(path, accountId, appId, relFilename) || relFilename.empty()) {
        LOG("%s Download: bad path '%s'", LogTag(), path.c_str());
        return false;
    }

    size_t lastSlash = relFilename.rfind('/');
    std::string relDir   = (lastSlash != std::string::npos) ? relFilename.substr(0, lastSlash) : "";
    std::string leafName = (lastSlash != std::string::npos) ? relFilename.substr(lastSlash + 1)
                                                            : relFilename;

    FolderNode parentFolder;
    auto status = ResolveFolder(accountId, appId, relDir, parentFolder, false);
    if (status == LookupStatus::Missing) {
        LOG("%s Download: folder not found for '%s'", LogTag(), path.c_str());
        return false;
    }
    if (status == LookupStatus::Error) return false;

    LinkInfo li;
    if (FindChildFile(parentFolder, leafName, &li) != LookupStatus::Exists) {
        LOG("%s Download: file not found '%s'", LogTag(), path.c_str());
        return false;
    }
    return DownloadFile(li, parentFolder, outData);
}

bool ProtonDriveProvider::Remove(const std::string& path) {
    uint32_t accountId, appId;
    std::string relFilename;
    if (!ParsePath(path, accountId, appId, relFilename) || relFilename.empty()) {
        LOG("%s Remove: bad path '%s'", LogTag(), path.c_str());
        return false;
    }

    size_t lastSlash = relFilename.rfind('/');
    std::string relDir   = (lastSlash != std::string::npos) ? relFilename.substr(0, lastSlash) : "";
    std::string leafName = (lastSlash != std::string::npos) ? relFilename.substr(lastSlash + 1)
                                                            : relFilename;

    FolderNode parentFolder;
    auto status = ResolveFolder(accountId, appId, relDir, parentFolder, false);
    if (status == LookupStatus::Missing) return true; // already gone
    if (status == LookupStatus::Error) return false;

    LinkInfo li;
    auto fs = FindChildFile(parentFolder, leafName, &li);
    if (fs == LookupStatus::Missing) return true;
    if (fs == LookupStatus::Error)   return false;

    if (!TrashLink(li.linkId)) return false;

    // Invalidate file cache.
    std::string hash = HexEncode(ProtonPGP::HashNodeName(leafName, parentFolder.hashKey));
    {
        std::lock_guard<std::mutex> lk(m_fileMtx);
        m_fileCache.erase(parentFolder.linkId + ":" + hash);
    }
    return true;
}

ICloudProvider::ExistsStatus ProtonDriveProvider::CheckExists(const std::string& path) {
    uint32_t accountId, appId;
    std::string relFilename;
    if (!ParsePath(path, accountId, appId, relFilename) || relFilename.empty()) {
        return ExistsStatus::Error;
    }

    size_t lastSlash = relFilename.rfind('/');
    std::string relDir   = (lastSlash != std::string::npos) ? relFilename.substr(0, lastSlash) : "";
    std::string leafName = (lastSlash != std::string::npos) ? relFilename.substr(lastSlash + 1)
                                                            : relFilename;

    FolderNode parentFolder;
    auto status = ResolveFolder(accountId, appId, relDir, parentFolder, false);
    if (status == LookupStatus::Missing) return ExistsStatus::Missing;
    if (status == LookupStatus::Error)   return ExistsStatus::Error;

    auto fs = FindChildFile(parentFolder, leafName, nullptr);
    if (fs == LookupStatus::Exists)  return ExistsStatus::Exists;
    if (fs == LookupStatus::Missing) return ExistsStatus::Missing;
    return ExistsStatus::Error;
}

std::vector<ICloudProvider::FileInfo> ProtonDriveProvider::List(const std::string& prefix) {
    std::vector<FileInfo> result;
    bool complete = false;
    ListChecked(prefix, result, &complete);
    return result;
}

std::vector<std::string> ProtonDriveProvider::ListSubfolders(const std::string& prefix) {
    uint32_t accountId, appId;
    std::string relFilename;
    if (!ParsePath(prefix, accountId, appId, relFilename)) return {};

    FolderNode appFolder;
    if (GetOrCreateAppFolder(accountId, appId, appFolder) != LookupStatus::Exists) return {};

    std::vector<LinkInfo> children;
    if (!FetchFolderChildren(appFolder.linkId, children)) return {};

    std::vector<std::string> result;
    for (auto& li : children) {
        if (li.type != 1) continue;
        std::string name = DecryptLinkName(li, appFolder.keyPair);
        if (!name.empty())
            result.push_back(name);
    }
    return result;
}

bool ProtonDriveProvider::ListChecked(const std::string& prefix,
                                       std::vector<FileInfo>& outFiles,
                                       bool* outComplete) {
    uint32_t accountId, appId;
    std::string relFilename;
    if (!ParsePath(prefix, accountId, appId, relFilename)) {
        if (outComplete) *outComplete = false;
        return false;
    }

    FolderNode startFolder;
    LookupStatus status;

    if (appId == kNoAppId) {
        // Account-level list: enumerate all app folders under the account.
        FolderNode accFolder;
        status = GetOrCreateAccountFolder(accountId, accFolder);
        if (status != LookupStatus::Exists) {
            if (outComplete) *outComplete = (status == LookupStatus::Missing);
            return status == LookupStatus::Missing;
        }
        startFolder = accFolder;
    } else {
        status = ResolveFolder(accountId, appId, relFilename, startFolder, false);
        if (status == LookupStatus::Missing) {
            if (outComplete) *outComplete = true;
            return true;
        }
        if (status == LookupStatus::Error) {
            if (outComplete) *outComplete = false;
            return false;
        }
    }

    bool complete = true;
    std::vector<RemoteFile> remoteFiles;
    if (!ListFolderRecursive(startFolder, "", remoteFiles, &complete)) {
        if (outComplete) *outComplete = false;
        return false;
    }

    for (auto& rf : remoteFiles) {
        FileInfo fi;
        fi.path = std::to_string(accountId) + "/" + std::to_string(appId) + "/" + rf.relativePath;
        fi.modifiedTime = rf.modifiedTime;
        fi.size = rf.size;
        outFiles.push_back(std::move(fi));
    }
    if (outComplete) *outComplete = complete;
    return true;
}

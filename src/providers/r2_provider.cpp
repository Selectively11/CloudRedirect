#include "r2_provider.h"
#include "json.h"
#include "log.h"

#include <cctype>

// R2 account IDs are 32 lowercase hex chars; anything else yields a nonexistent
// host that aborts the TLS handshake as an opaque transport error.
static bool IsValidAccountId(const std::string& id) {
    if (id.size() != 32) return false;
    for (char c : id) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
        if (std::isupper(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

static std::string ExtractJsonString(const std::string& json, const char* key) {
    Json::Value root = Json::Parse(json);
    if (root.type != Json::Type::Object || !root.has(key)) return {};
    const Json::Value& v = root[key];
    if (v.type != Json::Type::String) return {};
    return v.str();
}

bool R2Provider::ParseExtraCredentials(const std::string& json) {
    m_accountId = ExtractJsonString(json, "account_id");
    return true;
}

std::string R2Provider::DefaultEndpoint() const {
    if (m_accountId.empty()) {
        LOG("[R2] account_id missing from credentials; set it to your 32-character "
            "Cloudflare account ID, or set \"endpoint\" for a custom host");
        return {};
    }
    if (!IsValidAccountId(m_accountId)) {
        LOG("[R2] account_id is not a 32-character hex Cloudflare account ID "
            "(got %zu chars); check you did not paste an API token or access key",
            m_accountId.size());
        return {};
    }
    return m_accountId + ".r2.cloudflarestorage.com";
}

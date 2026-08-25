#include "r2_provider.h"

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

bool R2Provider::ParseExtraCredentials(const std::string& json) {
    m_accountId = ExtractJsonString(json, "account_id");
    return true;
}

std::string R2Provider::DefaultEndpoint() const {
    if (m_accountId.empty()) return {};
    return m_accountId + ".r2.cloudflarestorage.com";
}

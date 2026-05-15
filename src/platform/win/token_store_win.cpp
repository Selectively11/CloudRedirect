// DPAPI token store adapter for Windows.
// Implements ITokenStore using Windows Data Protection API for encryption.

#include "cloud_provider_base.h"
#include "dpapi_util.h"

#include <memory>

class DpapiTokenStore : public ITokenStore {
public:
    std::string Read(const std::string& path) override {
        return DpapiUtil::ReadTokenFile(path);
    }

    bool Write(const std::string& path, const std::string& json) override {
        return DpapiUtil::WriteTokenFile(path, json);
    }

    bool IsEncryptionAvailable() const override {
        return true;  // DPAPI is always available on Windows
    }
};

// Factory function
std::unique_ptr<ITokenStore> CreateTokenStore() {
    return std::make_unique<DpapiTokenStore>();
}

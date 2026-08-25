#pragma once
#include "s3_provider.h"

#include <string>

class R2Provider : public S3Provider {
public:
    const char* Name() const override { return "Cloudflare R2"; }

protected:
    bool ParseExtraCredentials(const std::string& json) override;
    std::string DefaultEndpoint() const override;
    std::string DefaultRegion() const override { return "auto"; }
    bool ForceUnsignedPayload() const override { return true; }
    bool ProbeVersioningAtInit() const override { return false; }
    const char* LogTag() const override { return "[R2]"; }

private:
    std::string m_accountId;
};

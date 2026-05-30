#pragma once
#include "protobuf.h"
#include <cstdint>
#include <vector>

namespace ParentalBypass {

inline constexpr const char* NOTIFY_SETTINGS_CHANGE = "ParentalClient.NotifySettingsChange#1";
inline constexpr const char* NOTIFY_LOCK            = "ParentalClient.NotifyLock#1";
inline constexpr const char* NOTIFY_UNLOCK          = "ParentalClient.NotifyUnlock#1";
inline constexpr const char* NOTIFY_PLAYTIME_USED   = "ParentalClient.NotifyPlaytimeUsed#1";

namespace Fields {
    inline constexpr uint32_t IS_ENABLED                  = 9;
    inline constexpr uint32_t ENABLED_FEATURES            = 10;
    inline constexpr uint32_t TEMP_ENABLED_FEATURES       = 13;
    inline constexpr uint32_t PLAYTIME_RESTRICTIONS       = 15;
    inline constexpr uint32_t TEMP_PLAYTIME_RESTRICTIONS  = 16;
}

namespace NotifyFields {
    inline constexpr uint32_t SERIALIZED_SETTINGS = 1;
    inline constexpr uint32_t SIGNATURE           = 2;
}

std::vector<uint8_t> StripPlaytimeRestrictions(const uint8_t* data, size_t len, bool fullBypass = true);

bool IsParentalNotification(const char* methodName);
bool ShouldSuppressNotification(const char* methodName);

bool PatchParentalSignatureCheck();
bool PatchPlaytimeEnforcement();
bool InstallParentalSettingsHook(bool fullBypass = false);

} // namespace ParentalBypass

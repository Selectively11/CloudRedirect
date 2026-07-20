#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include <string>
#include <vector>

namespace crypto {

std::array<uint8_t, 32> Sha256(const uint8_t* data, size_t len);

inline std::array<uint8_t, 32> Sha256(const std::string& s) {
    return Sha256(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

std::string ToHex(const uint8_t* data, size_t len);
std::string Base64Encode(const uint8_t* data, size_t len);

inline std::string Sha256Hex(const std::string& s) {
    auto d = Sha256(s);
    return ToHex(d.data(), d.size());
}

inline std::string Sha256Base64(const uint8_t* data, size_t len) {
    auto d = Sha256(data, len);
    return Base64Encode(d.data(), d.size());
}

std::array<uint8_t, 32> HmacSha256(const uint8_t* key, size_t keyLen,
                                   const uint8_t* msg, size_t msgLen);

inline std::array<uint8_t, 32> HmacSha256(const std::vector<uint8_t>& key,
                                          const std::string& msg) {
    return HmacSha256(key.data(), key.size(),
                      reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
}

inline std::array<uint8_t, 32> HmacSha256(const std::string& key,
                                          const std::string& msg) {
    return HmacSha256(reinterpret_cast<const uint8_t*>(key.data()), key.size(),
                      reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
}

} // namespace crypto

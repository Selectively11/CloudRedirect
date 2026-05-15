#pragma once
// DPAPI helpers for encrypting/decrypting token files.
// Uses CryptProtectData/CryptUnprotectData (user-scope, no extra entropy).
// Both the DLL (inside Steam) and the UI run as the same Windows user,
// so tokens encrypted by one can be decrypted by the other.

#include <string>
#include <vector>
#include <fstream>
#include <Windows.h>
#include <wincrypt.h>
#include <sys/stat.h>
#include "file_util.h"
#include "log.h"
#pragma comment(lib, "Crypt32.lib")

namespace DpapiUtil {

inline std::vector<uint8_t> Encrypt(const std::string& plaintext) {
    DATA_BLOB in{};
    in.pbData = (BYTE*)plaintext.data();
    in.cbData = (DWORD)plaintext.size();

    DATA_BLOB out{};
    if (!CryptProtectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out))
        return {};

    std::vector<uint8_t> result(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return result;
}

// Returns empty string on failure (wrong user, corrupted, etc.).
inline std::string Decrypt(const uint8_t* data, size_t len) {
    DATA_BLOB in{};
    in.pbData = (BYTE*)data;
    in.cbData = (DWORD)len;

    DATA_BLOB out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out))
        return {};

    std::string result((char*)out.pbData, out.cbData);
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return result;
}

// Read a token file that may be either DPAPI-encrypted or legacy plaintext JSON.
// Returns the JSON string on success, empty string on failure.
// If legacy plaintext is found and reencrypt==true, re-encrypts in place.
inline std::string ReadTokenFile(const std::string& path, bool reencrypt = true) {
    auto widePath = FileUtil::Utf8ToPath(path);
    if (widePath.empty()) {
        LOG("[TokenStorage] Cannot read %s: invalid path encoding", path.c_str());
        return {};
    }
    struct _stat64i32 st;
    if (_wstat(widePath.c_str(), &st) != 0) {
        LOG("[TokenStorage] Cannot read %s: file does not exist", path.c_str());
        return {};
    }
    if (!(st.st_mode & _S_IFREG)) {
        LOG("[TokenStorage] Cannot read %s: not a regular file", path.c_str());
        return {};
    }
    std::ifstream f(widePath, std::ios::binary);
    if (!f) {
        LOG("[TokenStorage] Cannot read %s: failed to open file", path.c_str());
        return {};
    }
    std::string raw((std::istreambuf_iterator<char>(f)), {});
    f.close();
    if (raw.empty()) {
        LOG("[TokenStorage] Cannot read %s: file is empty", path.c_str());
        return {};
    }

    // Heuristic: if it starts with '{', it's legacy plaintext JSON.
    // DPAPI blobs begin with a fixed binary header (01 00 00 00 D0 8C ...),
    // so a 0x7B ('{') first byte reliably distinguishes plaintext JSON.
    if (raw[0] == '{') {
        if (reencrypt) {
            // Silently upgrade to DPAPI
            auto blob = Encrypt(raw);
            if (!blob.empty()) {
                FileUtil::AtomicWriteBinary(path, blob.data(), blob.size());
            } // else: DPAPI encryption failed — leave plaintext in place (non-critical)
        }
        return raw;
    }

    // Try DPAPI decryption
    auto decrypted = Decrypt((const uint8_t*)raw.data(), raw.size());
    if (decrypted.empty()) {
        LOG("[TokenStorage] Cannot read %s: DPAPI decryption failed (wrong user or corrupted)", path.c_str());
    }
    return decrypted;
}

// Write a JSON string to a token file, DPAPI-encrypted, atomically.
// Returns true on success.
inline bool WriteTokenFile(const std::string& path, const std::string& json) {
    auto blob = Encrypt(json);
    if (blob.empty()) return false;
    return FileUtil::AtomicWriteBinary(path, blob.data(), blob.size());
}

} // namespace DpapiUtil

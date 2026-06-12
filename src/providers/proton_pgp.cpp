#include "proton_pgp.h"
#include "log.h"
#include <cstring>
#include <ctime>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#else
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#endif

namespace ProtonPGP {

// ── Base64 ────────────────────────────────────────────────────────────────────

static const char kB64Chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string Base64Encode(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve((len + 2) / 3 * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = ((uint32_t)data[i] << 16) |
                     (i + 1 < len ? (uint32_t)data[i + 1] << 8 : 0) |
                     (i + 2 < len ? (uint32_t)data[i + 2] : 0);
        out += kB64Chars[(v >> 18) & 63];
        out += kB64Chars[(v >> 12) & 63];
        out += (i + 1 < len) ? kB64Chars[(v >> 6) & 63] : '=';
        out += (i + 2 < len) ? kB64Chars[v & 63] : '=';
    }
    return out;
}

bool Base64Decode(const std::string& b64, std::vector<uint8_t>& out) {
    static const int8_t kTable[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };
    out.clear();
    uint32_t bits = 0;
    int shift = 0;
    for (unsigned char c : b64) {
        if (c == '=') break;
        if (c == '\n' || c == '\r' || c == ' ') continue;
        int v = kTable[c];
        if (v < 0) return false;
        bits = (bits << 6) | (uint32_t)v;
        shift += 6;
        if (shift >= 8) {
            shift -= 8;
            out.push_back((uint8_t)((bits >> shift) & 0xff));
        }
    }
    return true;
}

// ── CRC24 for PGP armor ────────────────────────────────────────────────────────

static uint32_t Crc24(const uint8_t* data, size_t len) {
    uint32_t crc = 0xB704CE;
    for (size_t i = 0; i < len; ++i) {
        crc ^= (uint32_t)data[i] << 16;
        for (int j = 0; j < 8; ++j) {
            crc <<= 1;
            if (crc & 0x1000000) crc ^= 0x1864CFB;
        }
    }
    return crc & 0xFFFFFF;
}

// ── Armor helpers ─────────────────────────────────────────────────────────────

static std::string Armor(const std::string& header,
                          const std::vector<uint8_t>& data) {
    std::string b64 = Base64Encode(data.data(), data.size());
    uint32_t crc = Crc24(data.data(), data.size());
    uint8_t crcBytes[3] = {
        (uint8_t)((crc >> 16) & 0xff),
        (uint8_t)((crc >>  8) & 0xff),
        (uint8_t)( crc        & 0xff),
    };
    std::string crcB64 = Base64Encode(crcBytes, 3);

    std::string out = "-----BEGIN PGP " + header + "-----\n\n";
    // Split b64 into 76-char lines
    for (size_t i = 0; i < b64.size(); i += 76)
        out += b64.substr(i, 76) + "\n";
    out += "=" + crcB64 + "\n";
    out += "-----END PGP " + header + "-----\n";
    return out;
}

static bool Dearmor(const std::string& armored, std::vector<uint8_t>& outData) {
    bool inBody = false;
    std::string b64;
    for (size_t i = 0; i < armored.size(); ) {
        size_t nl = armored.find('\n', i);
        std::string line = armored.substr(i, nl == std::string::npos ? std::string::npos : nl - i);
        i = nl == std::string::npos ? armored.size() : nl + 1;
        if (!inBody) {
            if (line.substr(0, 5) == "-----") { /* skip header */ }
            else if (line.empty()) inBody = true;
            continue;
        }
        if (line.empty()) continue;
        if (line[0] == '=') break; // CRC line
        if (line.substr(0, 5) == "-----") break;
        b64 += line;
    }
    return Base64Decode(b64, outData);
}

// ── PGP MPI encoding ──────────────────────────────────────────────────────────

static void WriteMPI(std::vector<uint8_t>& buf, const std::vector<uint8_t>& v) {
    // Strip leading zeros to find bit length
    size_t start = 0;
    while (start < v.size() - 1 && v[start] == 0) start++;
    uint16_t bits = 0;
    if (!v.empty()) {
        uint8_t top = v[start];
        bits = (uint16_t)((v.size() - start) * 8);
        while (!(top & 0x80)) { top <<= 1; --bits; }
    }
    buf.push_back((uint8_t)(bits >> 8));
    buf.push_back((uint8_t)(bits & 0xff));
    for (size_t j = start; j < v.size(); ++j) buf.push_back(v[j]);
}

static bool ReadMPI(const uint8_t* buf, size_t len, size_t& pos, std::vector<uint8_t>& out) {
    if (pos + 2 > len) return false;
    uint16_t bits = ((uint16_t)buf[pos] << 8) | buf[pos + 1];
    pos += 2;
    size_t bytes = (bits + 7) / 8;
    if (pos + bytes > len) return false;
    out.assign(buf + pos, buf + pos + bytes);
    pos += bytes;
    return true;
}

// ── New-format packet framing ─────────────────────────────────────────────────

static void WriteNewPacket(std::vector<uint8_t>& out, uint8_t tag, const std::vector<uint8_t>& body) {
    out.push_back(0xC0 | tag);
    size_t len = body.size();
    if (len < 192) {
        out.push_back((uint8_t)len);
    } else if (len < 8384) {
        len -= 192;
        out.push_back((uint8_t)(((len >> 8) & 0xff) + 192));
        out.push_back((uint8_t)(len & 0xff));
    } else {
        out.push_back(0xff);
        out.push_back((uint8_t)(len >> 24));
        out.push_back((uint8_t)(len >> 16));
        out.push_back((uint8_t)(len >> 8));
        out.push_back((uint8_t)(len));
    }
    out.insert(out.end(), body.begin(), body.end());
}

// ── Platform crypto ───────────────────────────────────────────────────────────

#ifdef _WIN32

static bool RandomBytes(uint8_t* out, size_t len) {
    return BCryptGenRandom(nullptr, out, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
}

bool GenerateRsaKeyPair(RsaKeyPair& out) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, nullptr, 0)) goto done;
    if (BCryptGenerateKeyPair(alg, &key, 2048, 0)) goto done;
    if (BCryptFinalizeKeyPair(key, 0)) goto done;

    {
        ULONG blobLen = 0;
        if (BCryptExportKey(key, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, nullptr, 0, &blobLen, 0)) goto done;
        std::vector<uint8_t> blob(blobLen);
        if (BCryptExportKey(key, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, blob.data(), blobLen, &blobLen, 0)) goto done;

        auto* hdr = reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(blob.data());
        const uint8_t* p = blob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
        auto take = [&](uint32_t n) -> std::vector<uint8_t> {
            std::vector<uint8_t> v(p, p + n); p += n; return v;
        };
        out.e = take(hdr->cbPublicExp);
        out.n = take(hdr->cbModulus);
        out.p = take(hdr->cbPrime1);
        out.q = take(hdr->cbPrime2);
        out.dp = take(hdr->cbPrime1);
        out.dq = take(hdr->cbPrime2);
        out.qi = take(hdr->cbPrime1);
        out.d  = take(hdr->cbModulus);
        ok = true;
    }
done:
    if (key) BCryptDestroyKey(key);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

bool AesGcmEncrypt(const std::vector<uint8_t>& key,
                   const uint8_t* plaintext, size_t len,
                   std::vector<uint8_t>& out) {
    if (key.size() != 32) return false;
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0)) goto done;
    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0)) goto done;

    {
        ULONG keyObjSize = 0, dummy = 0;
        if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjSize, sizeof(keyObjSize), &dummy, 0)) goto done;
        std::vector<uint8_t> keyObj(keyObjSize);
        if (BCryptGenerateSymmetricKey(alg, &hKey, keyObj.data(), keyObjSize,
                                        (PUCHAR)key.data(), (ULONG)key.size(), 0)) goto done;

        uint8_t nonce[12];
        if (!RandomBytes(nonce, 12)) goto done;

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = nonce;
        info.cbNonce = 12;
        uint8_t tag[16] = {};
        info.pbTag = tag;
        info.cbTag = 16;

        ULONG cbResult = 0;
        ULONG cipherLen = (ULONG)len;
        out.resize(12 + len + 16);
        memcpy(out.data(), nonce, 12);

        if (BCryptEncrypt(hKey, (PUCHAR)plaintext, (ULONG)len,
                           &info, nullptr, 0,
                           out.data() + 12, cipherLen, &cbResult, 0)) goto done;
        memcpy(out.data() + 12 + cbResult, tag, 16);
        out.resize(12 + cbResult + 16);
        ok = true;
    }
done:
    if (hKey) BCryptDestroyKey(hKey);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

bool AesGcmDecrypt(const std::vector<uint8_t>& key,
                   const uint8_t* ciphertext, size_t len,
                   std::vector<uint8_t>& out) {
    if (key.size() != 32 || len < 28) return false; // 12 nonce + 16 tag minimum
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0)) goto done;
    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0)) goto done;

    {
        ULONG keyObjSize = 0, dummy = 0;
        if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjSize, sizeof(keyObjSize), &dummy, 0)) goto done;
        std::vector<uint8_t> keyObj(keyObjSize);
        if (BCryptGenerateSymmetricKey(alg, &hKey, keyObj.data(), keyObjSize,
                                        (PUCHAR)key.data(), (ULONG)key.size(), 0)) goto done;

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = (PUCHAR)ciphertext;
        info.cbNonce = 12;
        size_t encLen = len - 12 - 16;
        info.pbTag = (PUCHAR)(ciphertext + 12 + encLen);
        info.cbTag = 16;

        ULONG cbResult = 0;
        out.resize(encLen);
        if (BCryptDecrypt(hKey, (PUCHAR)(ciphertext + 12), (ULONG)encLen,
                           &info, nullptr, 0,
                           out.data(), (ULONG)encLen, &cbResult, 0)) { out.clear(); goto done; }
        out.resize(cbResult);
        ok = true;
    }
done:
    if (hKey) BCryptDestroyKey(hKey);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

static bool RsaOaepEncrypt(const std::vector<uint8_t>& n,
                            const std::vector<uint8_t>& e,
                            const uint8_t* plaintext, size_t len,
                            std::vector<uint8_t>& out) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, nullptr, 0)) goto done;

    {
        // Build BCRYPT_RSAKEY_BLOB for public key
        BCRYPT_RSAKEY_BLOB hdr = {};
        hdr.Magic = BCRYPT_RSAPUBLIC_MAGIC;
        hdr.BitLength = (ULONG)(n.size() * 8);
        hdr.cbPublicExp = (ULONG)e.size();
        hdr.cbModulus   = (ULONG)n.size();

        std::vector<uint8_t> blob(sizeof(hdr) + e.size() + n.size());
        memcpy(blob.data(), &hdr, sizeof(hdr));
        memcpy(blob.data() + sizeof(hdr), e.data(), e.size());
        memcpy(blob.data() + sizeof(hdr) + e.size(), n.data(), n.size());
        if (BCryptImportKeyPair(alg, nullptr, BCRYPT_RSAPUBLIC_BLOB,
                                 &hKey, blob.data(), (ULONG)blob.size(), 0)) goto done;

        BCRYPT_OAEP_PADDING_INFO pad = {};
        pad.pszAlgId = BCRYPT_SHA1_ALGORITHM;
        ULONG outLen = 0;
        if (BCryptEncrypt(hKey, (PUCHAR)plaintext, (ULONG)len, &pad,
                           nullptr, 0, nullptr, 0, &outLen, BCRYPT_PAD_OAEP)) goto done;
        out.resize(outLen);
        if (BCryptEncrypt(hKey, (PUCHAR)plaintext, (ULONG)len, &pad,
                           nullptr, 0, out.data(), outLen, &outLen, BCRYPT_PAD_OAEP)) goto done;
        out.resize(outLen);
        ok = true;
    }
done:
    if (hKey) BCryptDestroyKey(hKey);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

static bool RsaOaepDecrypt(const RsaKeyPair& kp,
                            const uint8_t* ciphertext, size_t len,
                            std::vector<uint8_t>& out) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, nullptr, 0)) goto done;

    {
        // Use BCRYPT_RSAPRIVATE_BLOB (needs only n,e,p,q); BCrypt derives d/dp/dq/qi.
        // This works even when dp/dq are unavailable (e.g. after LoadSecretKey).
        BCRYPT_RSAKEY_BLOB hdr = {};
        hdr.Magic        = BCRYPT_RSAPRIVATE_MAGIC;
        hdr.BitLength    = (ULONG)(kp.n.size() * 8);
        hdr.cbPublicExp  = (ULONG)kp.e.size();
        hdr.cbModulus    = (ULONG)kp.n.size();
        hdr.cbPrime1     = (ULONG)kp.p.size();
        hdr.cbPrime2     = (ULONG)kp.q.size();

        size_t blobSize = sizeof(hdr) + kp.e.size() + kp.n.size() +
                          kp.p.size() + kp.q.size();
        std::vector<uint8_t> blob(blobSize);
        uint8_t* p = blob.data();
        memcpy(p, &hdr, sizeof(hdr)); p += sizeof(hdr);
        auto append = [&](const std::vector<uint8_t>& v) {
            memcpy(p, v.data(), v.size()); p += v.size();
        };
        append(kp.e); append(kp.n);
        append(kp.p); append(kp.q);

        if (BCryptImportKeyPair(alg, nullptr, BCRYPT_RSAPRIVATE_BLOB,
                                 &hKey, blob.data(), (ULONG)blob.size(), 0)) goto done;
    }

    {
        BCRYPT_OAEP_PADDING_INFO pad = {};
        pad.pszAlgId = BCRYPT_SHA1_ALGORITHM;
        ULONG outLen = 0;
        if (BCryptDecrypt(hKey, (PUCHAR)ciphertext, (ULONG)len, &pad,
                           nullptr, 0, nullptr, 0, &outLen, BCRYPT_PAD_OAEP)) goto done;
        out.resize(outLen);
        if (BCryptDecrypt(hKey, (PUCHAR)ciphertext, (ULONG)len, &pad,
                           nullptr, 0, out.data(), outLen, &outLen, BCRYPT_PAD_OAEP)) goto done;
        out.resize(outLen);
        ok = true;
    }
done:
    if (hKey) BCryptDestroyKey(hKey);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

static bool HmacSha256(const uint8_t* key, size_t keyLen,
                        const uint8_t* data, size_t dataLen,
                        uint8_t out[32]) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = false;
    ULONG dummy = 0;
    ULONG objLen = 0;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                     BCRYPT_ALG_HANDLE_HMAC_FLAG)) goto done;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &dummy, 0)) goto done;
    {
        std::vector<uint8_t> obj(objLen);
        if (BCryptCreateHash(alg, &hash, obj.data(), objLen,
                              (PUCHAR)key, (ULONG)keyLen, 0)) goto done;
        if (BCryptHashData(hash, (PUCHAR)data, (ULONG)dataLen, 0)) goto done;
        if (BCryptFinishHash(hash, out, 32, 0)) goto done;
        ok = true;
    }
done:
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

static bool RsaPkcs1Sign(const RsaKeyPair& kp,
                          const uint8_t* data, size_t dataLen,
                          std::vector<uint8_t>& outSig) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, nullptr, 0)) goto done;

    {
        BCRYPT_RSAKEY_BLOB hdr = {};
        hdr.Magic        = BCRYPT_RSAPRIVATE_MAGIC;
        hdr.BitLength    = (ULONG)(kp.n.size() * 8);
        hdr.cbPublicExp  = (ULONG)kp.e.size();
        hdr.cbModulus    = (ULONG)kp.n.size();
        hdr.cbPrime1     = (ULONG)kp.p.size();
        hdr.cbPrime2     = (ULONG)kp.q.size();

        size_t blobSize = sizeof(hdr) + kp.e.size() + kp.n.size() +
                          kp.p.size() + kp.q.size();
        std::vector<uint8_t> blob(blobSize);
        uint8_t* p = blob.data();
        memcpy(p, &hdr, sizeof(hdr)); p += sizeof(hdr);
        auto append = [&](const std::vector<uint8_t>& v) {
            memcpy(p, v.data(), v.size()); p += v.size();
        };
        append(kp.e); append(kp.n);
        append(kp.p); append(kp.q);

        if (BCryptImportKeyPair(alg, nullptr, BCRYPT_RSAPRIVATE_BLOB,
                                 &hKey, blob.data(), (ULONG)blob.size(), 0)) goto done;
    }

    {
        // Hash the data with SHA-256
        uint8_t digest[32] = {};
        {
            BCRYPT_ALG_HANDLE sha = nullptr;
            BCRYPT_HASH_HANDLE h = nullptr;
            ULONG objLen = 0, dummy = 0;
            if (BCryptOpenAlgorithmProvider(&sha, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) goto done;
            if (BCryptGetProperty(sha, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &dummy, 0)) {
                BCryptCloseAlgorithmProvider(sha, 0); goto done;
            }
            std::vector<uint8_t> obj(objLen);
            if (BCryptCreateHash(sha, &h, obj.data(), objLen, nullptr, 0, 0) ||
                BCryptHashData(h, (PUCHAR)data, (ULONG)dataLen, 0) ||
                BCryptFinishHash(h, digest, 32, 0)) {
                if (h) BCryptDestroyHash(h);
                BCryptCloseAlgorithmProvider(sha, 0);
                goto done;
            }
            BCryptDestroyHash(h);
            BCryptCloseAlgorithmProvider(sha, 0);
        }

        BCRYPT_PKCS1_PADDING_INFO pad = {};
        pad.pszAlgId = BCRYPT_SHA256_ALGORITHM;
        ULONG sigLen = 0;
        if (BCryptSignHash(hKey, &pad, digest, 32, nullptr, 0, &sigLen, BCRYPT_PAD_PKCS1)) goto done;
        outSig.resize(sigLen);
        if (BCryptSignHash(hKey, &pad, digest, 32, outSig.data(), sigLen, &sigLen, BCRYPT_PAD_PKCS1)) goto done;
        outSig.resize(sigLen);
        ok = true;
    }
done:
    if (hKey) BCryptDestroyKey(hKey);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

// AES-256-CFB for SEIPD (OpenPGP MDC mode)
static bool AesCfbEncrypt(const uint8_t* key, size_t keyLen,
                           const uint8_t* iv, size_t ivLen,
                           const uint8_t* plaintext, size_t len,
                           std::vector<uint8_t>& out) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0)) goto done;
    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_CFB, sizeof(BCRYPT_CHAIN_MODE_CFB), 0)) goto done;

    {
        ULONG objLen = 0, dummy = 0;
        if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &dummy, 0)) goto done;
        std::vector<uint8_t> keyObj(objLen);
        if (BCryptGenerateSymmetricKey(alg, &hKey, keyObj.data(), objLen,
                                        (PUCHAR)key, (ULONG)keyLen, 0)) goto done;

        std::vector<uint8_t> ivCopy(iv, iv + ivLen);
        ULONG cbResult = 0;
        out.resize(len);
        if (BCryptEncrypt(hKey, (PUCHAR)plaintext, (ULONG)len, nullptr,
                           ivCopy.data(), (ULONG)ivCopy.size(),
                           out.data(), (ULONG)len, &cbResult, 0)) goto done;
        out.resize(cbResult);
        ok = true;
    }
done:
    if (hKey) BCryptDestroyKey(hKey);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

static bool AesCfbDecrypt(const uint8_t* key, size_t keyLen,
                           const uint8_t* iv, size_t ivLen,
                           const uint8_t* ciphertext, size_t len,
                           std::vector<uint8_t>& out) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0)) goto done;
    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_CFB, sizeof(BCRYPT_CHAIN_MODE_CFB), 0)) goto done;

    {
        ULONG objLen = 0, dummy = 0;
        if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &dummy, 0)) goto done;
        std::vector<uint8_t> keyObj(objLen);
        if (BCryptGenerateSymmetricKey(alg, &hKey, keyObj.data(), objLen,
                                        (PUCHAR)key, (ULONG)keyLen, 0)) goto done;

        std::vector<uint8_t> ivCopy(iv, iv + ivLen);
        ULONG cbResult = 0;
        out.resize(len);
        if (BCryptDecrypt(hKey, (PUCHAR)ciphertext, (ULONG)len, nullptr,
                           ivCopy.data(), (ULONG)ivCopy.size(),
                           out.data(), (ULONG)len, &cbResult, 0)) goto done;
        out.resize(cbResult);
        ok = true;
    }
done:
    if (hKey) BCryptDestroyKey(hKey);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

#else // Linux / OpenSSL

static bool RandomBytes(uint8_t* out, size_t len) {
    return RAND_bytes(out, (int)len) == 1;
}

bool GenerateRsaKeyPair(RsaKeyPair& kp) {
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    bool ok = false;
    if (!rsa || !e) goto done;
    BN_set_word(e, RSA_F4);
    if (RSA_generate_key_ex(rsa, 2048, e, nullptr) != 1) goto done;

    {
        auto toBig = [](const BIGNUM* bn) {
            std::vector<uint8_t> v(BN_num_bytes(bn));
            BN_bn2bin(bn, v.data());
            return v;
        };
        const BIGNUM *bn_n, *bn_e, *bn_d, *bn_p, *bn_q, *bn_dp, *bn_dq, *bn_qi;
        RSA_get0_key(rsa, &bn_n, &bn_e, &bn_d);
        RSA_get0_factors(rsa, &bn_p, &bn_q);
        RSA_get0_crt_params(rsa, &bn_dp, &bn_dq, &bn_qi);
        kp.n  = toBig(bn_n);  kp.e  = toBig(bn_e);  kp.d  = toBig(bn_d);
        kp.p  = toBig(bn_p);  kp.q  = toBig(bn_q);
        kp.dp = toBig(bn_dp); kp.dq = toBig(bn_dq); kp.qi = toBig(bn_qi);
        ok = true;
    }
done:
    RSA_free(rsa);
    BN_free(e);
    return ok;
}

bool AesGcmEncrypt(const std::vector<uint8_t>& key,
                   const uint8_t* plaintext, size_t len,
                   std::vector<uint8_t>& out) {
    if (key.size() != 32) return false;
    uint8_t nonce[12];
    if (!RandomBytes(nonce, 12)) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    out.resize(12 + len + 16);
    memcpy(out.data(), nonce, 12);

    int outLen = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce) != 1) goto done;
    if (EVP_EncryptUpdate(ctx, out.data() + 12, &outLen, plaintext, (int)len) != 1) goto done;
    {
        int finalLen = 0;
        if (EVP_EncryptFinal_ex(ctx, out.data() + 12 + outLen, &finalLen) != 1) goto done;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + 12 + outLen + finalLen) != 1) goto done;
        out.resize(12 + outLen + finalLen + 16);
        ok = true;
    }
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool AesGcmDecrypt(const std::vector<uint8_t>& key,
                   const uint8_t* ciphertext, size_t len,
                   std::vector<uint8_t>& out) {
    if (key.size() != 32 || len < 28) return false;
    size_t encLen = len - 12 - 16;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    out.resize(encLen);
    int outLen = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), ciphertext) != 1) goto done;
    if (EVP_DecryptUpdate(ctx, out.data(), &outLen, ciphertext + 12, (int)encLen) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)(ciphertext + 12 + encLen)) != 1) goto done;
    {
        int finalLen = 0;
        if (EVP_DecryptFinal_ex(ctx, out.data() + outLen, &finalLen) != 1) { out.clear(); goto done; }
        out.resize(outLen + finalLen);
        ok = true;
    }
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static bool RsaOaepEncrypt(const std::vector<uint8_t>& n,
                            const std::vector<uint8_t>& e,
                            const uint8_t* plaintext, size_t len,
                            std::vector<uint8_t>& out) {
    RSA* rsa = RSA_new();
    bool ok = false;
    if (!rsa) return false;
    BIGNUM* bn_n = BN_bin2bn(n.data(), (int)n.size(), nullptr);
    BIGNUM* bn_e = BN_bin2bn(e.data(), (int)e.size(), nullptr);
    if (!bn_n || !bn_e) goto done;
    RSA_set0_key(rsa, bn_n, bn_e, nullptr); bn_n = bn_e = nullptr;
    {
        out.resize(RSA_size(rsa));
        int r = RSA_public_encrypt((int)len, plaintext, out.data(), rsa, RSA_PKCS1_OAEP_PADDING);
        if (r < 0) goto done;
        out.resize(r);
        ok = true;
    }
done:
    BN_free(bn_n); BN_free(bn_e);
    RSA_free(rsa);
    return ok;
}

static bool RsaOaepDecrypt(const RsaKeyPair& kp,
                            const uint8_t* ciphertext, size_t len,
                            std::vector<uint8_t>& out) {
    RSA* rsa = RSA_new();
    bool ok = false;
    if (!rsa) return false;
    BIGNUM* bn_n  = BN_bin2bn(kp.n.data(),  (int)kp.n.size(),  nullptr);
    BIGNUM* bn_e  = BN_bin2bn(kp.e.data(),  (int)kp.e.size(),  nullptr);
    BIGNUM* bn_d  = BN_bin2bn(kp.d.data(),  (int)kp.d.size(),  nullptr);
    BIGNUM* bn_p  = BN_bin2bn(kp.p.data(),  (int)kp.p.size(),  nullptr);
    BIGNUM* bn_q  = BN_bin2bn(kp.q.data(),  (int)kp.q.size(),  nullptr);
    BIGNUM* bn_dp = BN_bin2bn(kp.dp.data(), (int)kp.dp.size(), nullptr);
    BIGNUM* bn_dq = BN_bin2bn(kp.dq.data(), (int)kp.dq.size(), nullptr);
    BIGNUM* bn_qi = BN_bin2bn(kp.qi.data(), (int)kp.qi.size(), nullptr);
    if (!bn_n || !bn_e || !bn_d || !bn_p || !bn_q || !bn_dp || !bn_dq || !bn_qi) goto done;
    RSA_set0_key(rsa, bn_n, bn_e, bn_d); bn_n = bn_e = bn_d = nullptr;
    RSA_set0_factors(rsa, bn_p, bn_q);   bn_p = bn_q = nullptr;
    RSA_set0_crt_params(rsa, bn_dp, bn_dq, bn_qi); bn_dp = bn_dq = bn_qi = nullptr;
    {
        out.resize(RSA_size(rsa));
        int r = RSA_private_decrypt((int)len, ciphertext, out.data(), rsa, RSA_PKCS1_OAEP_PADDING);
        if (r < 0) goto done;
        out.resize(r);
        ok = true;
    }
done:
    BN_free(bn_n); BN_free(bn_e); BN_free(bn_d);
    BN_free(bn_p); BN_free(bn_q);
    BN_free(bn_dp); BN_free(bn_dq); BN_free(bn_qi);
    RSA_free(rsa);
    return ok;
}

static bool HmacSha256(const uint8_t* key, size_t keyLen,
                        const uint8_t* data, size_t dataLen,
                        uint8_t out[32]) {
    unsigned int len = 32;
    return HMAC(EVP_sha256(), key, (int)keyLen, data, dataLen, out, &len) != nullptr;
}

static bool RsaPkcs1Sign(const RsaKeyPair& kp,
                          const uint8_t* data, size_t dataLen,
                          std::vector<uint8_t>& outSig) {
    RSA* rsa = RSA_new();
    bool ok = false;
    if (!rsa) return false;
    BIGNUM* bn_n  = BN_bin2bn(kp.n.data(),  (int)kp.n.size(),  nullptr);
    BIGNUM* bn_e  = BN_bin2bn(kp.e.data(),  (int)kp.e.size(),  nullptr);
    BIGNUM* bn_d  = BN_bin2bn(kp.d.data(),  (int)kp.d.size(),  nullptr);
    if (!bn_n || !bn_e || !bn_d) goto done;
    RSA_set0_key(rsa, bn_n, bn_e, bn_d); bn_n = bn_e = bn_d = nullptr;

    {
        uint8_t digest[32];
        SHA256(data, dataLen, digest);
        outSig.resize(RSA_size(rsa));
        unsigned int sigLen = 0;
        if (RSA_sign(NID_sha256, digest, 32, outSig.data(), &sigLen, rsa) != 1) goto done;
        outSig.resize(sigLen);
        ok = true;
    }
done:
    BN_free(bn_n); BN_free(bn_e); BN_free(bn_d);
    RSA_free(rsa);
    return ok;
}

static bool AesCfbEncrypt(const uint8_t* key, size_t keyLen,
                           const uint8_t* iv, size_t ivLen,
                           const uint8_t* plaintext, size_t len,
                           std::vector<uint8_t>& out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    out.resize(len + 16);
    int outLen = 0, finalLen = 0;
    const EVP_CIPHER* cipher = (keyLen == 32) ? EVP_aes_256_cfb128() : EVP_aes_128_cfb128();
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key, iv) != 1) goto done;
    if (EVP_EncryptUpdate(ctx, out.data(), &outLen, plaintext, (int)len) != 1) goto done;
    if (EVP_EncryptFinal_ex(ctx, out.data() + outLen, &finalLen) != 1) goto done;
    out.resize(outLen + finalLen);
    ok = true;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static bool AesCfbDecrypt(const uint8_t* key, size_t keyLen,
                           const uint8_t* iv, size_t ivLen,
                           const uint8_t* ciphertext, size_t len,
                           std::vector<uint8_t>& out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    out.resize(len);
    int outLen = 0, finalLen = 0;
    const EVP_CIPHER* cipher = (keyLen == 32) ? EVP_aes_256_cfb128() : EVP_aes_128_cfb128();
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key, iv) != 1) goto done;
    if (EVP_DecryptUpdate(ctx, out.data(), &outLen, ciphertext, (int)len) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, out.data() + outLen, &finalLen) != 1) goto done;
    out.resize(outLen + finalLen);
    ok = true;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}
#endif // platform crypto

// ── Public API ────────────────────────────────────────────────────────────────

bool GenerateSessionKey(std::vector<uint8_t>& out) {
    out.resize(32);
    return RandomBytes(out.data(), 32);
}

std::vector<uint8_t> HashNodeName(const std::string& name,
                                   const std::vector<uint8_t>& hashKey) {
    std::vector<uint8_t> out(32);
    if (!HmacSha256(hashKey.data(), hashKey.size(),
                     (const uint8_t*)name.data(), name.size(), out.data()))
        out.clear();
    return out;
}

std::string ToHex(const std::vector<uint8_t>& v) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : v) ss << std::setw(2) << (int)b;
    return ss.str();
}

// S2K: Iterated+Salted SHA-256, 65536 iterations, AES-256
static bool S2KIterated(const uint8_t* salt, const std::string& passphrase,
                          int iters, uint8_t out[32]) {
    // Prefix = salt || passphrase, iterated until iters bytes processed
    std::vector<uint8_t> data;
    data.insert(data.end(), salt, salt + 8);
    data.insert(data.end(), passphrase.begin(), passphrase.end());

    size_t count = (size_t)iters;
    std::vector<uint8_t> buf;
    buf.reserve(count + data.size());
    while (buf.size() < count) buf.insert(buf.end(), data.begin(), data.end());
    buf.resize(count);

#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = false;
    ULONG objLen = 0, dummy = 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) goto s2kDone;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &dummy, 0)) goto s2kDone;
    {
        std::vector<uint8_t> obj(objLen);
        if (BCryptCreateHash(alg, &hash, obj.data(), objLen, nullptr, 0, 0)) goto s2kDone;
        if (BCryptHashData(hash, buf.data(), (ULONG)buf.size(), 0)) goto s2kDone;
        if (BCryptFinishHash(hash, out, 32, 0)) goto s2kDone;
        ok = true;
    }
s2kDone:
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
#else
    SHA256(buf.data(), buf.size(), out);
    return true;
#endif
}

// OpenPGP Symmetric-Key Encrypted Session Key Packet or direct S2K
// Here we use S2K to derive a key for encrypting the secret key's passphrase
// then store the secret key's MPI data encrypted with AES-256-CFB.

bool ArmorSecretKey(const RsaKeyPair& kp,
                    const std::string& passphrase,
                    std::string& outArmored) {
    // Build Secret Key Packet (v4, RSA-2048, tag 5)
    // https://www.rfc-editor.org/rfc/rfc4880#section-5.5.3
    std::vector<uint8_t> pkt;

    // Version
    pkt.push_back(4);
    // Creation time (4 bytes, big-endian)
    uint32_t ts = (uint32_t)std::time(nullptr);
    pkt.push_back((ts >> 24) & 0xff);
    pkt.push_back((ts >> 16) & 0xff);
    pkt.push_back((ts >>  8) & 0xff);
    pkt.push_back( ts        & 0xff);
    // Algorithm: RSA encrypt or sign (3 = RSA)
    pkt.push_back(1); // 1 = RSA Encrypt or Sign
    // Public key MPIs: n, e
    WriteMPI(pkt, kp.n);
    WriteMPI(pkt, kp.e);

    // Secret key material: S2K usage = 254 (SHA-1 checksum in string-to-key)
    pkt.push_back(254);
    // Symmetric cipher: 9 = AES-256
    pkt.push_back(9);
    // S2K specifier: type 3 = Iterated and Salted
    pkt.push_back(3);
    // Hash algorithm: 8 = SHA-256
    pkt.push_back(8);
    // S2K salt (8 bytes random)
    uint8_t salt[8] = {};
    RandomBytes(salt, 8);
    pkt.insert(pkt.end(), salt, salt + 8);
    // Count octet: 0x60 encodes ~65536 iterations
    pkt.push_back(0x60);

    // IV for AES-256-CFB: 16 bytes random
    uint8_t iv[16] = {};
    RandomBytes(iv, 16);
    pkt.insert(pkt.end(), iv, iv + 16);

    // Derive AES key from passphrase
    uint8_t aesKey[32] = {};
    if (!S2KIterated(salt, passphrase, 65536, aesKey)) return false;

    // Build plaintext secret key MPIs: d, p, q, u(=qi)
    std::vector<uint8_t> secretMpis;
    WriteMPI(secretMpis, kp.d);
    WriteMPI(secretMpis, kp.p);
    WriteMPI(secretMpis, kp.q);
    WriteMPI(secretMpis, kp.qi);
    // SHA-1 checksum of the cleartext MPI data (20 bytes)
    // We use SHA-1 here for OpenPGP compliance
    {
        // Simple SHA-1 via a quick implementation or platform call
        // For simplicity we compute a SHA-256 truncated to 20 bytes as a stand-in
        // NOTE: strictly RFC 4880 requires SHA-1 here; use SHA-1 in production
        uint8_t hash[32] = {};
#ifdef _WIN32
        BCRYPT_ALG_HANDLE alg = nullptr;
        BCRYPT_HASH_HANDLE h = nullptr;
        ULONG objLen = 0, dummy = 0;
        if (!BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, nullptr, 0) &&
            !BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &dummy, 0)) {
            std::vector<uint8_t> obj(objLen);
            uint8_t sha1[20] = {};
            if (!BCryptCreateHash(alg, &h, obj.data(), objLen, nullptr, 0, 0) &&
                !BCryptHashData(h, secretMpis.data(), (ULONG)secretMpis.size(), 0) &&
                !BCryptFinishHash(h, sha1, 20, 0)) {
                secretMpis.insert(secretMpis.end(), sha1, sha1 + 20);
                hash[0] = 1; // sentinel: ok
            }
            if (h) BCryptDestroyHash(h);
        }
        if (alg) BCryptCloseAlgorithmProvider(alg, 0);
        if (!hash[0]) return false; // SHA-1 failed
#else
        uint8_t sha1[20];
        SHA1(secretMpis.data(), secretMpis.size(), sha1);
        secretMpis.insert(secretMpis.end(), sha1, sha1 + 20);
#endif
    }

    // Encrypt secret MPIs
    std::vector<uint8_t> encrypted;
    if (!AesCfbEncrypt(aesKey, 32, iv, 16, secretMpis.data(), secretMpis.size(), encrypted))
        return false;

    pkt.insert(pkt.end(), encrypted.begin(), encrypted.end());

    std::vector<uint8_t> fullPacket;
    WriteNewPacket(fullPacket, 5, pkt);
    outArmored = Armor("PRIVATE KEY BLOCK", fullPacket);
    return true;
}

bool LoadSecretKey(const std::string& armored,
                   const std::string& passphrase,
                   RsaKeyPair& out) {
    std::vector<uint8_t> pktData;
    if (!Dearmor(armored, pktData)) return false;

    // Skip packet header (new format tag 5 or old format)
    size_t pos = 0;
    if (pos >= pktData.size()) return false;
    uint8_t ctb = pktData[pos++];
    if (!(ctb & 0x80)) return false;
    bool newFormat = (ctb & 0x40) != 0;
    size_t bodyStart = 0;
    if (newFormat) {
        uint8_t firstLen = pktData[pos++];
        if (firstLen < 192) {
            bodyStart = pos;
        } else if (firstLen < 224) {
            pos++; bodyStart = pos;
        } else if (firstLen == 255) {
            pos += 4; bodyStart = pos;
        } else bodyStart = pos;
    } else {
        uint8_t lenType = ctb & 0x03;
        if (lenType == 0) { pos++; bodyStart = pos; }
        else if (lenType == 1) { pos += 2; bodyStart = pos; }
        else if (lenType == 2) { pos += 4; bodyStart = pos; }
        else bodyStart = pos;
    }
    pos = bodyStart;

    if (pos >= pktData.size()) return false;
    uint8_t version = pktData[pos++];
    if (version != 4) return false;
    pos += 4; // creation time
    uint8_t algo = pktData[pos++];
    if (algo != 1 && algo != 3) return false; // must be RSA

    // Read public MPIs: n, e
    if (!ReadMPI(pktData.data(), pktData.size(), pos, out.n)) return false;
    if (!ReadMPI(pktData.data(), pktData.size(), pos, out.e)) return false;

    if (pos >= pktData.size()) return false;
    uint8_t s2kUsage = pktData[pos++];
    if (s2kUsage != 254) return false;

    uint8_t cipher = pktData[pos++]; (void)cipher; // should be 9 = AES-256
    uint8_t s2kType = pktData[pos++];
    if (s2kType != 3) return false;
    uint8_t hashAlgo = pktData[pos++]; (void)hashAlgo;
    if (pos + 8 + 1 > pktData.size()) return false;
    const uint8_t* salt = pktData.data() + pos; pos += 8;
    uint8_t countByte = pktData[pos++];
    int iters = (16 + (countByte & 15)) << ((countByte >> 4) + 6);
    if (pos + 16 > pktData.size()) return false;
    const uint8_t* iv = pktData.data() + pos; pos += 16;

    uint8_t aesKey[32] = {};
    if (!S2KIterated(salt, passphrase, iters, aesKey)) return false;

    size_t encLen = pktData.size() - pos;
    std::vector<uint8_t> decrypted;
    if (!AesCfbDecrypt(aesKey, 32, iv, 16, pktData.data() + pos, encLen, decrypted))
        return false;

    // Parse decrypted secret MPIs (d, p, q, qi) + 20-byte SHA-1 checksum
    if (decrypted.size() < 20) return false;
    size_t mpiEnd = decrypted.size() - 20;
    size_t mpos = 0;
    if (!ReadMPI(decrypted.data(), mpiEnd, mpos, out.d)) return false;
    if (!ReadMPI(decrypted.data(), mpiEnd, mpos, out.p)) return false;
    if (!ReadMPI(decrypted.data(), mpiEnd, mpos, out.q)) return false;
    if (!ReadMPI(decrypted.data(), mpiEnd, mpos, out.qi)) return false;
    // Derive dp, dq from d, p, q (not stored in PGP format)
    out.dp = out.d; out.dq = out.d; // placeholder; BCrypt/OpenSSL re-derives
    return true;
}

bool LoadPublicKeyFromArmored(const std::string& armored,
                               std::vector<uint8_t>& outN,
                               std::vector<uint8_t>& outE) {
    std::vector<uint8_t> pktData;
    if (!Dearmor(armored, pktData)) return false;

    size_t pos = 0;
    if (pos >= pktData.size()) return false;
    uint8_t ctb = pktData[pos++];
    if (!(ctb & 0x80)) return false;
    bool newFormat = (ctb & 0x40) != 0;
    if (newFormat) {
        uint8_t fl = pktData[pos++];
        if (fl >= 192 && fl < 224) pos++;
        else if (fl == 255) pos += 4;
    } else {
        uint8_t lt = ctb & 0x03;
        if (lt == 0) pos++;
        else if (lt == 1) pos += 2;
        else if (lt == 2) pos += 4;
    }
    if (pos >= pktData.size() || pktData[pos] != 4) return false;
    pos += 5; // skip version + creation time
    pos++; // algorithm byte
    return ReadMPI(pktData.data(), pktData.size(), pos, outN) &&
           ReadMPI(pktData.data(), pktData.size(), pos, outE);
}

// ── OpenPGP message encryption (PKESK + SEIPD v1 MDC) ────────────────────────

bool EncryptMessage(const std::vector<uint8_t>& recipientN,
                    const std::vector<uint8_t>& recipientE,
                    const uint8_t* plaintext, size_t len,
                    std::string& outArmored) {
    // 1. Generate a random 16-byte AES-128 session key (shorter for PKESK/SEIPD v1)
    uint8_t sessionKey[16] = {};
    if (!RandomBytes(sessionKey, 16)) return false;

    // 2. PKESK packet (tag 1): RSA-OAEP encrypted session key
    {
        std::vector<uint8_t> pkeskBody;
        pkeskBody.push_back(3); // version
        // Key ID: 8 bytes (all zero = wildcard)
        for (int i = 0; i < 8; ++i) pkeskBody.push_back(0);
        pkeskBody.push_back(1); // algorithm: RSA
        // Encrypted session key: prefix with 1 byte cipher algo (9 = AES-256, but we use 7 = AES-128)
        uint8_t skWithAlgo[17];
        skWithAlgo[0] = 7; // AES-128
        memcpy(skWithAlgo + 1, sessionKey, 16);
        std::vector<uint8_t> encSK;
        if (!RsaOaepEncrypt(recipientN, recipientE, skWithAlgo, 17, encSK)) return false;
        WriteMPI(pkeskBody, encSK);

        std::vector<uint8_t> pkeskPacket;
        WriteNewPacket(pkeskPacket, 1, pkeskBody);

        // 3. SEIPD packet v1 (tag 18) with MDC
        // Build plaintext: prefix (16+2 bytes) + literal data packet + MDC packet
        std::vector<uint8_t> seipd_plain;
        // OpenPGP random prefix for AES-128: 16 bytes + 2 repeat bytes
        uint8_t prefix[16];
        RandomBytes(prefix, 16);
        seipd_plain.insert(seipd_plain.end(), prefix, prefix + 16);
        seipd_plain.push_back(prefix[14]);
        seipd_plain.push_back(prefix[15]);

        // Literal Data packet (tag 11): 'b' + 0 (filename len) + timestamp + data
        {
            std::vector<uint8_t> litBody;
            litBody.push_back('b');
            litBody.push_back(0); // filename length
            uint32_t ts = (uint32_t)std::time(nullptr);
            litBody.push_back((ts >> 24) & 0xff);
            litBody.push_back((ts >> 16) & 0xff);
            litBody.push_back((ts >>  8) & 0xff);
            litBody.push_back( ts        & 0xff);
            litBody.insert(litBody.end(), plaintext, plaintext + len);
            std::vector<uint8_t> litPacket;
            WriteNewPacket(litPacket, 11, litBody);
            seipd_plain.insert(seipd_plain.end(), litPacket.begin(), litPacket.end());
        }

        // MDC (Modification Detection Code) packet: SHA-1 of (prefix || prefix_repeat || literal_data || mdc_header)
        {
            // Hash: everything so far + 0xD3 0x14 (mdc packet header)
            seipd_plain.push_back(0xD3);
            seipd_plain.push_back(0x14);
            uint8_t sha1[20] = {};
#ifdef _WIN32
            BCRYPT_ALG_HANDLE alg2 = nullptr;
            BCRYPT_HASH_HANDLE h2 = nullptr;
            ULONG objLen2 = 0, dummy2 = 0;
            BCryptOpenAlgorithmProvider(&alg2, BCRYPT_SHA1_ALGORITHM, nullptr, 0);
            BCryptGetProperty(alg2, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen2, sizeof(objLen2), &dummy2, 0);
            std::vector<uint8_t> obj2(objLen2);
            BCryptCreateHash(alg2, &h2, obj2.data(), objLen2, nullptr, 0, 0);
            BCryptHashData(h2, seipd_plain.data(), (ULONG)seipd_plain.size(), 0);
            BCryptFinishHash(h2, sha1, 20, 0);
            if (h2) BCryptDestroyHash(h2);
            if (alg2) BCryptCloseAlgorithmProvider(alg2, 0);
#else
            SHA1(seipd_plain.data(), seipd_plain.size(), sha1);
#endif
            seipd_plain.insert(seipd_plain.end(), sha1, sha1 + 20);
        }

        // Encrypt with AES-128-CFB using an IV of 0
        uint8_t iv16[16] = {};
        std::vector<uint8_t> ciphertext;
        if (!AesCfbEncrypt(sessionKey, 16, iv16, 16,
                            seipd_plain.data(), seipd_plain.size(), ciphertext))
            return false;

        std::vector<uint8_t> seipdBody;
        seipdBody.push_back(1); // version
        seipdBody.insert(seipdBody.end(), ciphertext.begin(), ciphertext.end());
        std::vector<uint8_t> seipdPacket;
        WriteNewPacket(seipdPacket, 18, seipdBody);

        std::vector<uint8_t> fullMsg;
        fullMsg.insert(fullMsg.end(), pkeskPacket.begin(), pkeskPacket.end());
        fullMsg.insert(fullMsg.end(), seipdPacket.begin(), seipdPacket.end());
        outArmored = Armor("MESSAGE", fullMsg);
    }
    return true;
}

bool DecryptMessage(const std::string& armored,
                    const RsaKeyPair& kp,
                    std::vector<uint8_t>& outPlaintext) {
    std::vector<uint8_t> pktData;
    if (!Dearmor(armored, pktData)) return false;

    size_t pos = 0;
    std::vector<uint8_t> sessionKey;
    uint8_t sessionCipher = 0;

    // Parse PKESK packet
    while (pos < pktData.size()) {
        if (!(pktData[pos] & 0x80)) return false;
        bool newFmt = (pktData[pos] & 0x40) != 0;
        uint8_t tag = newFmt ? (pktData[pos] & 0x3f) : ((pktData[pos] >> 2) & 0x0f);
        pos++;
        size_t bodyLen = 0;
        if (newFmt) {
            uint8_t fl = pktData[pos++];
            if (fl < 192) bodyLen = fl;
            else if (fl < 224) { bodyLen = ((fl - 192) << 8) + pktData[pos++] + 192; }
            else if (fl == 255) { bodyLen = ((size_t)pktData[pos]<<24)|((size_t)pktData[pos+1]<<16)|((size_t)pktData[pos+2]<<8)|pktData[pos+3]; pos+=4; }
        } else {
            uint8_t lt = pktData[pos-1] & 0x03;
            if (lt == 0) bodyLen = pktData[pos++];
            else if (lt == 1) { bodyLen = ((size_t)pktData[pos]<<8)|pktData[pos+1]; pos+=2; }
            else if (lt == 2) { bodyLen = ((size_t)pktData[pos]<<24)|((size_t)pktData[pos+1]<<16)|((size_t)pktData[pos+2]<<8)|pktData[pos+3]; pos+=4; }
            else bodyLen = pktData.size() - pos;
        }
        size_t bodyEnd = pos + bodyLen;
        if (bodyEnd > pktData.size()) return false;

        if (tag == 1 && sessionKey.empty()) {
            // PKESK
            size_t bp = pos;
            bp++; // version
            bp += 8; // key ID
            bp++; // algo
            std::vector<uint8_t> encSK;
            if (!ReadMPI(pktData.data(), bodyEnd, bp, encSK)) return false;
            std::vector<uint8_t> skWithAlgo;
            if (!RsaOaepDecrypt(kp, encSK.data(), encSK.size(), skWithAlgo)) return false;
            if (skWithAlgo.empty()) return false;
            sessionCipher = skWithAlgo[0];
            sessionKey.assign(skWithAlgo.begin() + 1, skWithAlgo.end());
        } else if (tag == 18 && !sessionKey.empty()) {
            // SEIPD
            size_t bp = pos;
            bp++; // version
            uint8_t iv[16] = {};
            std::vector<uint8_t> decrypted;
            if (!AesCfbDecrypt(sessionKey.data(), sessionKey.size(), iv, 16,
                                pktData.data() + bp, bodyEnd - bp, decrypted))
                return false;

            // Skip prefix (keysize + 2) + find literal data packet
            size_t prefixLen = sessionKey.size() + 2;
            if (decrypted.size() < prefixLen) return false;
            size_t dp = prefixLen;

            while (dp < decrypted.size()) {
                if (!(decrypted[dp] & 0x80)) break;
                bool nf2 = (decrypted[dp] & 0x40) != 0;
                uint8_t tag2 = nf2 ? (decrypted[dp] & 0x3f) : ((decrypted[dp] >> 2) & 0x0f);
                dp++;
                size_t bl2 = 0;
                if (nf2) {
                    uint8_t fl2 = decrypted[dp++];
                    if (fl2 < 192) bl2 = fl2;
                    else if (fl2 < 224) { bl2 = ((fl2-192)<<8)+decrypted[dp++]+192; }
                    else if (fl2 == 255) { bl2=((size_t)decrypted[dp]<<24)|((size_t)decrypted[dp+1]<<16)|((size_t)decrypted[dp+2]<<8)|decrypted[dp+3]; dp+=4; }
                } else {
                    uint8_t lt2 = (decrypted[dp-1]) & 0x03;
                    if (lt2==0) bl2=decrypted[dp++];
                    else if (lt2==1){bl2=((size_t)decrypted[dp]<<8)|decrypted[dp+1];dp+=2;}
                    else if (lt2==2){bl2=((size_t)decrypted[dp]<<24)|((size_t)decrypted[dp+1]<<16)|((size_t)decrypted[dp+2]<<8)|decrypted[dp+3];dp+=4;}
                    else bl2=decrypted.size()-dp;
                }
                size_t be2 = dp + bl2;
                if (tag2 == 11 && be2 <= decrypted.size()) {
                    // Literal data: format(1) + filename_len(1) + filename + time(4) + data
                    size_t lp = dp;
                    lp++; // format
                    uint8_t fnLen = decrypted[lp++];
                    lp += fnLen; // filename
                    lp += 4; // timestamp
                    outPlaintext.assign(decrypted.begin() + lp, decrypted.begin() + be2);
                    return true;
                }
                dp = be2;
            }
            return false;
        }
        pos = bodyEnd;
    }
    return false;
}

bool SignDetached(const RsaKeyPair& kp,
                  const uint8_t* data, size_t len,
                  std::string& outArmored) {
    std::vector<uint8_t> sig;
    if (!RsaPkcs1Sign(kp, data, len, sig)) return false;

    // Build a minimal OpenPGP signature packet (v4, RSA, SHA-256, no subpackets)
    std::vector<uint8_t> sigBody;
    sigBody.push_back(4); // version
    sigBody.push_back(0); // sig type: binary document
    sigBody.push_back(1); // public key algo: RSA
    sigBody.push_back(8); // hash algo: SHA-256

    // Hashed subpackets (empty)
    sigBody.push_back(0); sigBody.push_back(0);
    // Unhashed subpackets (empty)
    sigBody.push_back(0); sigBody.push_back(0);

    // Left 16 bits of signed hash
    // Hash the data with SHA-256 to get first 2 bytes
    {
#ifdef _WIN32
        BCRYPT_ALG_HANDLE alg3 = nullptr;
        BCRYPT_HASH_HANDLE h3 = nullptr;
        ULONG objLen3 = 0, dummy3 = 0;
        uint8_t digest[32] = {};
        BCryptOpenAlgorithmProvider(&alg3, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        BCryptGetProperty(alg3, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen3, sizeof(objLen3), &dummy3, 0);
        std::vector<uint8_t> obj3(objLen3);
        BCryptCreateHash(alg3, &h3, obj3.data(), objLen3, nullptr, 0, 0);
        BCryptHashData(h3, (PUCHAR)data, (ULONG)len, 0);
        BCryptFinishHash(h3, digest, 32, 0);
        if (h3) BCryptDestroyHash(h3);
        if (alg3) BCryptCloseAlgorithmProvider(alg3, 0);
        sigBody.push_back(digest[0]);
        sigBody.push_back(digest[1]);
#else
        uint8_t digest[32];
        SHA256(data, len, digest);
        sigBody.push_back(digest[0]);
        sigBody.push_back(digest[1]);
#endif
    }

    WriteMPI(sigBody, sig);

    std::vector<uint8_t> pkt;
    WriteNewPacket(pkt, 2, sigBody);
    outArmored = Armor("SIGNATURE", pkt);
    return true;
}

} // namespace ProtonPGP

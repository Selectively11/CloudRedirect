#include "sha256_hmac.h"

#include <cstring>

namespace crypto {

namespace {

constexpr uint32_t kK[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline uint32_t Ror(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

struct Sha256Ctx {
    uint32_t h[8];
    uint64_t bitlen;
    uint8_t buf[64];
    size_t buflen;
};

void Sha256Init(Sha256Ctx& c) {
    c.h[0] = 0x6a09e667; c.h[1] = 0xbb67ae85; c.h[2] = 0x3c6ef372;
    c.h[3] = 0xa54ff53a; c.h[4] = 0x510e527f; c.h[5] = 0x9b05688c;
    c.h[6] = 0x1f83d9ab; c.h[7] = 0x5be0cd19;
    c.bitlen = 0;
    c.buflen = 0;
}

void Sha256Block(Sha256Ctx& c, const uint8_t* p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = (uint32_t(p[i * 4]) << 24) | (uint32_t(p[i * 4 + 1]) << 16) |
               (uint32_t(p[i * 4 + 2]) << 8) | uint32_t(p[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = Ror(w[i - 15], 7) ^ Ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = Ror(w[i - 2], 17) ^ Ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = c.h[0], b = c.h[1], cc = c.h[2], d = c.h[3];
    uint32_t e = c.h[4], f = c.h[5], g = c.h[6], h = c.h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = Ror(e, 6) ^ Ror(e, 11) ^ Ror(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + kK[i] + w[i];
        uint32_t S0 = Ror(a, 2) ^ Ror(a, 13) ^ Ror(a, 22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
    }
    c.h[0] += a; c.h[1] += b; c.h[2] += cc; c.h[3] += d;
    c.h[4] += e; c.h[5] += f; c.h[6] += g; c.h[7] += h;
}

void Sha256Update(Sha256Ctx& c, const uint8_t* data, size_t len) {
    c.bitlen += uint64_t(len) * 8;
    while (len > 0) {
        size_t take = 64 - c.buflen;
        if (take > len) take = len;
        std::memcpy(c.buf + c.buflen, data, take);
        c.buflen += take;
        data += take;
        len -= take;
        if (c.buflen == 64) {
            Sha256Block(c, c.buf);
            c.buflen = 0;
        }
    }
}

void Sha256Final(Sha256Ctx& c, uint8_t out[32]) {
    uint64_t bitlen = c.bitlen;
    uint8_t pad = 0x80;
    Sha256Update(c, &pad, 1);
    uint8_t zero = 0x00;
    while (c.buflen != 56) Sha256Update(c, &zero, 1);
    uint8_t lenbytes[8];
    for (int i = 0; i < 8; i++) lenbytes[i] = uint8_t(bitlen >> (56 - i * 8));
    Sha256Update(c, lenbytes, 8);
    for (int i = 0; i < 8; i++) {
        out[i * 4] = uint8_t(c.h[i] >> 24);
        out[i * 4 + 1] = uint8_t(c.h[i] >> 16);
        out[i * 4 + 2] = uint8_t(c.h[i] >> 8);
        out[i * 4 + 3] = uint8_t(c.h[i]);
    }
}

} // namespace

std::array<uint8_t, 32> Sha256(const uint8_t* data, size_t len) {
    Sha256Ctx c;
    Sha256Init(c);
    Sha256Update(c, data, len);
    std::array<uint8_t, 32> out{};
    Sha256Final(c, out.data());
    return out;
}

std::string ToHex(const uint8_t* data, size_t len) {
    static const char* hex = "0123456789abcdef";
    std::string s;
    s.resize(len * 2);
    for (size_t i = 0; i < len; i++) {
        s[i * 2] = hex[data[i] >> 4];
        s[i * 2 + 1] = hex[data[i] & 0xf];
    }
    return s;
}

std::string Base64Encode(const uint8_t* data, size_t len) {
    static const char* tbl =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 3 <= len; i += 3) {
        uint32_t n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out.push_back(tbl[(n >> 18) & 0x3f]);
        out.push_back(tbl[(n >> 12) & 0x3f]);
        out.push_back(tbl[(n >> 6) & 0x3f]);
        out.push_back(tbl[n & 0x3f]);
    }
    if (i < len) {
        uint32_t n = data[i] << 16;
        bool two = (i + 1 < len);
        if (two) n |= data[i + 1] << 8;
        out.push_back(tbl[(n >> 18) & 0x3f]);
        out.push_back(tbl[(n >> 12) & 0x3f]);
        out.push_back(two ? tbl[(n >> 6) & 0x3f] : '=');
        out.push_back('=');
    }
    return out;
}

std::array<uint8_t, 32> HmacSha256(const uint8_t* key, size_t keyLen,
                                   const uint8_t* msg, size_t msgLen) {
    uint8_t k[64];
    std::memset(k, 0, sizeof(k));
    if (keyLen > 64) {
        auto kh = Sha256(key, keyLen);
        std::memcpy(k, kh.data(), 32);
    } else {
        std::memcpy(k, key, keyLen);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    // inner
    Sha256Ctx inner;
    Sha256Init(inner);
    Sha256Update(inner, ipad, 64);
    Sha256Update(inner, msg, msgLen);
    uint8_t innerDigest[32];
    Sha256Final(inner, innerDigest);
    // outer
    Sha256Ctx outer;
    Sha256Init(outer);
    Sha256Update(outer, opad, 64);
    Sha256Update(outer, innerDigest, 32);
    std::array<uint8_t, 32> out{};
    Sha256Final(outer, out.data());
    return out;
}

} // namespace crypto

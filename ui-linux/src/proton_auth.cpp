#include "proton_auth.h"

#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QRegularExpression>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QDebug>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

#include <argon2.h>
#include <crypt.h>

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <algorithm>
#include <stdio.h>

static const char *kApiBase    = "https://mail.proton.me/api";

static void srpLog(const char *, ...) {}
static const char *kAppVersion = "windows-drive@2.1.0";
static const char *kUserAgent  = "ProtonDrive/2.1.0 (Linux)";

// ── Base64 / Hex helpers ───────────────────────────────────────────────────────

static QByteArray fromB64(const QString &s)  { return QByteArray::fromBase64(s.toUtf8()); }
static QString    toB64(const QByteArray &b)  { return QString::fromLatin1(b.toBase64());  }

// The Modulus field in /auth/v4/info is a PGP clearsign message; body is standard base64.
static QByteArray parseSrpModulus(const QString &pgpSigned)
{
    QStringList lines = pgpSigned.split(QRegularExpression("\r\n|\n|\r"));
    bool inBody = false;
    QString b64;
    for (const QString &line : lines) {
        if (!inBody) {
            if (line.trimmed().isEmpty()) inBody = true;
            continue;
        }
        if (line.startsWith("-----") || line.startsWith('=')) break;
        b64 += line.trimmed();
    }
    return QByteArray::fromBase64(b64.toLatin1());
}

// expandHash: SHA-512(data||0) || SHA-512(data||1) || SHA-512(data||2) || SHA-512(data||3) = 256 bytes
static QByteArray expandHash(const QByteArray &data)
{
    QByteArray result(256, '\0');
    for (int i = 0; i < 4; i++) {
        QByteArray tagged = data;
        tagged.append((char)i);
        SHA512((const uint8_t *)tagged.constData(), tagged.size(),
               (uint8_t *)result.data() + i * 64);
    }
    return result;
}

// LE bytes → BIGNUM (go-srp uses little-endian throughout; caller must BN_free result)
static BIGNUM *leToInt(const QByteArray &le)
{
    QByteArray be = le;
    std::reverse(be.begin(), be.end());
    BIGNUM *n = BN_new();
    BN_bin2bn((const uint8_t *)be.constData(), be.size(), n);
    return n;
}

// BIGNUM → LE bytes, padded/truncated to byteLen
static QByteArray intToLE(const BIGNUM *n, int byteLen)
{
    QByteArray be(byteLen, '\0');
    BN_bn2binpad(n, (uint8_t *)be.data(), byteLen);
    std::reverse(be.begin(), be.end());
    return be;
}

// BCrypt base64 alphabet: ./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789
static const char kBCryptAlpha[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

static QString bcryptBase64Encode(const QByteArray &data)
{
    QString result;
    int len = data.size();
    for (int i = 0; i < len; ) {
        uint8_t b0 = (uint8_t)data[i++];
        uint8_t b1 = (i < len) ? (uint8_t)data[i++] : 0;
        uint8_t b2 = (i < len) ? (uint8_t)data[i++] : 0;
        result += kBCryptAlpha[b0 >> 2];
        result += kBCryptAlpha[((b0 & 3) << 4) | (b1 >> 4)];
        result += kBCryptAlpha[((b1 & 15) << 2) | (b2 >> 6)];
        result += kBCryptAlpha[b2 & 63];
    }
    return result;
}

// ── PGP low-level helpers ─────────────────────────────────────────────────────

static bool pgpDearmor(const QString &armored, QByteArray &out)
{
    QString b64;
    bool inBody = false;
    for (const QString &line : armored.split('\n')) {
        if (!inBody) {
            if (line.startsWith("-----")) { /* skip */ }
            else if (line.trimmed().isEmpty()) inBody = true;
            continue;
        }
        if (line.isEmpty()) continue;
        if (line.startsWith('=') || line.startsWith("-----")) break;
        b64 += line.trimmed();
    }
    out = QByteArray::fromBase64(b64.toLatin1());
    return !out.isEmpty();
}

static bool pgpReadMPI(const uint8_t *buf, size_t len, size_t &pos, QByteArray &out)
{
    if (pos + 2 > len) return false;
    uint16_t bits = (uint16_t(buf[pos]) << 8) | buf[pos + 1];
    pos += 2;
    size_t bytes = (bits + 7) / 8;
    if (pos + bytes > len) return false;
    out = QByteArray((const char *)(buf + pos), (int)bytes);
    pos += bytes;
    return true;
}

// Parse one PGP packet header; returns true and fills tag/bodyStart/bodyLen.
static bool pgpNextPacket(const uint8_t *data, size_t total,
                           size_t &pos, uint8_t &tag,
                           size_t &bodyStart, size_t &bodyLen)
{
    if (pos >= total) return false;
    uint8_t ctb = data[pos++];
    if (!(ctb & 0x80)) return false;

    bool newFmt = (ctb & 0x40) != 0;
    if (newFmt) {
        tag = ctb & 0x3f;
        if (pos >= total) return false;
        uint8_t fl = data[pos++];
        if (fl < 192) {
            bodyLen = fl;
        } else if (fl < 224) {
            if (pos >= total) return false;
            bodyLen = ((size_t)(fl - 192) << 8) + data[pos++] + 192;
        } else if (fl == 255) {
            if (pos + 4 > total) return false;
            bodyLen = ((size_t)data[pos] << 24) | ((size_t)data[pos+1] << 16) |
                      ((size_t)data[pos+2] << 8) | data[pos+3];
            pos += 4;
        } else {
            return false; // partial body — not supported here
        }
    } else {
        tag = (ctb >> 2) & 0x0f;
        uint8_t lt = ctb & 0x03;
        if (lt == 0) { if (pos >= total) return false; bodyLen = data[pos++]; }
        else if (lt == 1) { if (pos+2 > total) return false;
            bodyLen = (size_t(data[pos])<<8)|data[pos+1]; pos+=2; }
        else if (lt == 2) { if (pos+4 > total) return false;
            bodyLen = (size_t(data[pos])<<24)|(size_t(data[pos+1])<<16)|(size_t(data[pos+2])<<8)|data[pos+3]; pos+=4; }
        else bodyLen = total - pos;
    }
    bodyStart = pos;
    if (bodyStart + bodyLen > total) return false;
    return true;
}

// S2K Iterated+Salted (type 3) with SHA-1 or SHA-256, producing keyLen bytes.
static QByteArray s2kIterated(const uint8_t *salt8, const uint8_t *pass, size_t passLen,
                                uint8_t hashAlgo, uint32_t count, int keyLen)
{
    // Build iterated buffer: (salt||pass) repeated to fill `count` bytes
    QByteArray chunk;
    chunk.append((const char *)salt8, 8);
    chunk.append((const char *)pass, (int)passLen);

    size_t total = qMax((size_t)count, (size_t)chunk.size());
    QByteArray buf;
    buf.reserve((int)total + chunk.size());
    while ((size_t)buf.size() < total) buf.append(chunk);
    buf.resize((int)total);

    const EVP_MD *md = (hashAlgo == 2) ? EVP_sha1() : EVP_sha256();
    int hashLen = EVP_MD_size(md);

    QByteArray result;
    for (int instance = 0; result.size() < keyLen; ++instance) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, md, nullptr);
        for (int z = 0; z < instance; ++z) {
            uint8_t zero = 0;
            EVP_DigestUpdate(ctx, &zero, 1);
        }
        EVP_DigestUpdate(ctx, buf.constData(), buf.size());
        uint8_t hash[EVP_MAX_MD_SIZE];
        unsigned int hl = 0;
        EVP_DigestFinal_ex(ctx, hash, &hl);
        EVP_MD_CTX_free(ctx);
        result.append((const char *)hash, (int)hl);
        (void)hashLen;
    }
    result.resize(keyLen);
    return result;
}

// Standard AES-CFB-128 decrypt (for secret key S2K decryption — uses normal CFB with explicit IV).
static bool aesCfbDecrypt(const uint8_t *key, int keyLen,
                           const uint8_t *iv, int /*ivLen*/,
                           const uint8_t *ct, size_t ctLen,
                           QByteArray &out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    const EVP_CIPHER *cipher = (keyLen == 32) ? EVP_aes_256_cfb128() : EVP_aes_128_cfb128();
    out.resize((int)ctLen);
    int outLen = 0;
    bool ok = false;
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key, iv) != 1) goto done;
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (EVP_DecryptUpdate(ctx, (uint8_t *)out.data(), &outLen, ct, (int)ctLen) != 1) goto done;
    out.resize(outLen);
    ok = true;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// SEIPD v1 uses standard AES-CFB-128 with IV=0 continuously — no OpenPGP resync.
// The resync (FR = ct[2..17]) applies only to old-style SED (tag 9); SEIPD relies on
// the MDC for integrity and keeps the CFB state running from the start.
static bool pgpCfbDecrypt(const uint8_t *key, int keyLen,
                           const uint8_t *ct, size_t ctLen,
                           QByteArray &out)
{
    if (ctLen == 0) return true;
    out.resize((int)ctLen);

    uint8_t iv[16] = {};
    const EVP_CIPHER *cipher = (keyLen == 32) ? EVP_aes_256_cfb128() : EVP_aes_128_cfb128();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    EVP_DecryptInit_ex(ctx, cipher, nullptr, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int ol = 0;
    EVP_DecryptUpdate(ctx, (uint8_t *)out.data(), &ol, ct, (int)ctLen);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// RSA-OAEP-SHA1 decrypt with just n,e,d using EVP API (OpenSSL 3.x).
static bool rsaOaepDecrypt(const QByteArray &n, const QByteArray &e, const QByteArray &d,
                            const uint8_t *ct, size_t ctLen, QByteArray &out)
{
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    if (!bld) return false;

    BIGNUM *bn_n = BN_bin2bn((const uint8_t *)n.constData(), n.size(), nullptr);
    BIGNUM *bn_e = BN_bin2bn((const uint8_t *)e.constData(), e.size(), nullptr);
    BIGNUM *bn_d = BN_bin2bn((const uint8_t *)d.constData(), d.size(), nullptr);

    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_CTX *ctx = nullptr;
    bool ok = false;

    if (!bn_n || !bn_e || !bn_d) goto cleanup;
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn_n)) goto cleanup;
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn_e)) goto cleanup;
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, bn_d)) goto cleanup;

    {
        OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
        if (!params) goto cleanup;
        EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
        if (kctx) {
            EVP_PKEY_fromdata_init(kctx);
            EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_KEYPAIR, params);
            EVP_PKEY_CTX_free(kctx);
        }
        OSSL_PARAM_free(params);
    }
    if (!pkey) goto cleanup;

    ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) goto cleanup;
    if (EVP_PKEY_decrypt_init(ctx) != 1) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != 1) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha1()) != 1) goto cleanup;
    {
        size_t outLen = 0;
        if (EVP_PKEY_decrypt(ctx, nullptr, &outLen, ct, ctLen) != 1) goto cleanup;
        out.resize((int)outLen);
        if (EVP_PKEY_decrypt(ctx, (uint8_t *)out.data(), &outLen, ct, ctLen) != 1) goto cleanup;
        out.resize((int)outLen);
        ok = true;
    }

cleanup:
    if (!ok) out.clear();
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BN_free(bn_n); BN_free(bn_e); BN_free(bn_d);
    OSSL_PARAM_BLD_free(bld);
    return ok;
}

// ── RFC 3394 AES-256 key unwrap ───────────────────────────────────────────────

// kekLen: 16 = AES-128, 32 = AES-256 (RFC 6637 kdfCipherAlgo 7 or 9)
static bool rfcAes256Unwrap(const uint8_t *kek, int kekLen, const uint8_t *wrapped,
                             size_t wrappedLen, QByteArray &out)
{
    if (wrappedLen < 24 || wrappedLen % 8 != 0) return false;
    int n = (int)(wrappedLen / 8) - 1;

    uint8_t A[8];
    memcpy(A, wrapped, 8);
    std::vector<uint8_t> R(n * 8);
    for (int i = 0; i < n; i++)
        memcpy(R.data() + i * 8, wrapped + 8 + i * 8, 8);

    const EVP_CIPHER *cipher = (kekLen == 32) ? EVP_aes_256_ecb() : EVP_aes_128_ecb();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, cipher, nullptr, kek, nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    for (int j = 5; j >= 0; j--) {
        for (int i = n; i >= 1; i--) {
            uint64_t t = (uint64_t)n * j + i;
            uint8_t Bin[16];
            memcpy(Bin, A, 8);
            for (int k = 7; k >= 0; k--) { Bin[k] ^= (t & 0xFF); t >>= 8; }
            memcpy(Bin + 8, R.data() + (i - 1) * 8, 8);
            uint8_t Bout[16]; int outl = 0;
            EVP_DecryptUpdate(ctx, Bout, &outl, Bin, 16);
            memcpy(A, Bout, 8);
            memcpy(R.data() + (i - 1) * 8, Bout + 8, 8);
        }
    }
    EVP_CIPHER_CTX_free(ctx);

    static const uint8_t kIV[8] = {0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6};
    if (memcmp(A, kIV, 8) != 0) return false;
    out = QByteArray((const char *)R.data(), n * 8);
    return true;
}

static bool pkcs5Unpad(QByteArray &data)
{
    if (data.isEmpty()) return false;
    int pad = (uint8_t)data.back();
    if (pad < 1 || pad > 8 || pad > data.size()) return false;
    for (int i = data.size() - pad; i < data.size(); i++)
        if ((uint8_t)data[i] != pad) return false;
    data.resize(data.size() - pad);
    return true;
}

// ── PGP private key decryption ────────────────────────────────────────────────

// Decrypt one secret key packet body; return true and fill `out` on success.
static bool decryptSecretKeyBody(const uint8_t *body, size_t bodyLen,
                                  const uint8_t *keyPass, size_t keyPassLen,
                                  ProtonAuthService::RsaKey &out)
{
    size_t pos = 0;
    if (pos >= bodyLen || body[pos++] != 4) return false; // v4 only
    pos += 4; // creation time
    uint8_t algo = body[pos++];

    bool isRsa = (algo == 1 || algo == 3);
    bool isEcc = (algo == 18 || algo == 22); // ECDH or EdDSA (Curve25519)
    if (!isRsa && !isEcc) return false;

    QByteArray n, e;          // RSA public key
    QByteArray oid, pubPoint; // ECC public key
    uint8_t kdfHashAlgo = 8, kdfCipherAlgo = 9;

    if (isRsa) {
        if (!pgpReadMPI(body, bodyLen, pos, n)) return false;
        if (!pgpReadMPI(body, bodyLen, pos, e)) return false;
    } else {
        // ECC: OID length + OID bytes
        if (pos >= bodyLen) return false;
        uint8_t oidLen = body[pos++];
        if (pos + oidLen > bodyLen) return false;
        oid = QByteArray((const char *)(body + pos), oidLen);
        pos += oidLen;
        // Public point MPI
        if (!pgpReadMPI(body, bodyLen, pos, pubPoint)) return false;
        // ECDH KDF params: {0x03, 0x01, hash_algo, cipher_algo}
        if (algo == 18) {
            if (pos + 4 > bodyLen) return false;
            pos += 2; // 0x03 0x01
            kdfHashAlgo   = body[pos++];
            kdfCipherAlgo = body[pos++];
        }
    }

    size_t pubEndPos = pos; // public material ends here; used for fingerprint

    if (pos >= bodyLen) return false;
    uint8_t s2kUsage = body[pos++];

    // Helper: compute SHA-1 v4 fingerprint of the public key portion
    auto computeFingerprint = [&]() -> QByteArray {
        uint8_t hdr[3] = { 0x99, (uint8_t)(pubEndPos >> 8), (uint8_t)(pubEndPos) };
        uint8_t fp[20];
        SHA_CTX ctx;
        SHA1_Init(&ctx);
        SHA1_Update(&ctx, hdr, 3);
        SHA1_Update(&ctx, body, pubEndPos);
        SHA1_Final(fp, &ctx);
        return QByteArray((const char *)fp, 20);
    };

    // Helper: extract and normalise a secret scalar to 32 bytes (big-endian MPI → little-endian)
    auto extractScalar = [](const uint8_t *dm, size_t mpiEnd, size_t &mpos) -> QByteArray {
        QByteArray scalar;
        if (!pgpReadMPI(dm, mpiEnd, mpos, scalar)) return {};
        while (scalar.size() < 32) scalar.prepend('\0');
        if (scalar.size() > 32) scalar = scalar.right(32);
        std::reverse(scalar.begin(), scalar.end()); // OpenPGP big-endian → X25519 little-endian
        return scalar;
    };

    if (s2kUsage == 0) {
        // Unencrypted private material
        if (isRsa) {
            QByteArray d, p, q, qi;
            if (!pgpReadMPI(body, bodyLen, pos, d))  return false;
            if (!pgpReadMPI(body, bodyLen, pos, p))  return false;
            if (!pgpReadMPI(body, bodyLen, pos, q))  return false;
            if (!pgpReadMPI(body, bodyLen, pos, qi)) return false;
            out = { n, e, d, p, q, {}, {}, qi };
        } else {
            size_t mpos = pos;
            QByteArray scalar = extractScalar((const uint8_t *)body, bodyLen, mpos);
            if (scalar.isEmpty()) return false;
            out.isEcc = true;
            out.oid = oid; out.kdfHashAlgo = kdfHashAlgo; out.kdfCipherAlgo = kdfCipherAlgo;
            out.fingerprint = computeFingerprint();
            if (algo == 22) out.ed25519Priv = scalar;
            else            out.x25519Priv  = scalar;
        }
        return true;
    }
    if (s2kUsage != 254 && s2kUsage != 255) return false;

    if (pos >= bodyLen) return false;
    uint8_t cipherAlgo = body[pos++];
    int aesKeyLen = (cipherAlgo == 9) ? 32 : 16;
    int ivLen     = (cipherAlgo == 3) ? 8  : 16;

    if (pos >= bodyLen) return false;
    uint8_t s2kType = body[pos++];

    QByteArray aesKey;

    if (s2kType == 3) {
        if (pos >= bodyLen) return false;
        uint8_t hashAlgo = body[pos++];
        if (pos + 9 > bodyLen) return false;
        const uint8_t *salt8 = body + pos; pos += 8;
        uint8_t countByte = body[pos++];
        uint32_t iters = uint32_t(16 + (countByte & 15)) << ((countByte >> 4) + 6);
        aesKey = s2kIterated(salt8, keyPass, keyPassLen, hashAlgo, iters, aesKeyLen);
    } else if (s2kType == 4) {
        // Argon2id (RFC 9580)
        if (pos + 19 > bodyLen) return false;
        const uint8_t *salt16 = body + pos; pos += 16;
        uint8_t t = body[pos++];
        uint8_t p = body[pos++];
        uint8_t m = body[pos++];
        uint32_t memKib = 1u << m;
        aesKey.resize(aesKeyLen);
        if (argon2id_hash_raw(t, memKib, p, keyPass, keyPassLen,
                               salt16, 16, aesKey.data(), aesKeyLen) != ARGON2_OK)
            return false;
    } else {
        return false;
    }

    if (pos + ivLen > (int)bodyLen) return false;
    const uint8_t *iv = body + pos; pos += ivLen;

    size_t encLen = bodyLen - pos;
    QByteArray decrypted;
    if (!aesCfbDecrypt((const uint8_t *)aesKey.constData(), aesKeyLen,
                        iv, ivLen, body + pos, encLen, decrypted))
        return false;

    size_t checksumLen = (s2kUsage == 254) ? 20 : 2;
    if ((size_t)decrypted.size() <= checksumLen) return false;
    size_t mpiEnd = decrypted.size() - checksumLen;
    size_t mpos = 0;
    const uint8_t *dm = (const uint8_t *)decrypted.constData();

    if (isRsa) {
        QByteArray d, pp, qq, qi;
        if (!pgpReadMPI(dm, mpiEnd, mpos, d))  return false;
        if (!pgpReadMPI(dm, mpiEnd, mpos, pp)) return false;
        if (!pgpReadMPI(dm, mpiEnd, mpos, qq)) return false;
        if (!pgpReadMPI(dm, mpiEnd, mpos, qi)) return false;
        out = { n, e, d, pp, qq, {}, {}, qi };
    } else {
        QByteArray scalar = extractScalar(dm, mpiEnd, mpos);
        if (scalar.isEmpty()) return false;
        out.isEcc = true;
        out.oid = oid; out.kdfHashAlgo = kdfHashAlgo; out.kdfCipherAlgo = kdfCipherAlgo;
        out.fingerprint = computeFingerprint();
        if (algo == 22) out.ed25519Priv = scalar;
        else            out.x25519Priv  = scalar;
    }
    return true;
}

// ── ProtonAuthService implementation ─────────────────────────────────────────

ProtonAuthService::ProtonAuthService(QObject *parent)
    : QObject(parent), m_nam(new QNetworkAccessManager(this)) {}

void ProtonAuthService::start(const QString &email, const QString &password,
                               const QString &tokenPath)
{
    m_email     = email;
    m_password  = password.toUtf8();
    m_tokenPath = tokenPath;
    stepFetchInfo();
}

// ── HTTP ──────────────────────────────────────────────────────────────────────

void ProtonAuthService::postJson(const QString &path, const QByteArray &body,
                                  std::function<void(bool, const QByteArray &)> cb)
{
    QNetworkRequest req(QUrl(QString(kApiBase) + path));
    req.setRawHeader("x-pm-appversion", kAppVersion);
    req.setRawHeader("User-Agent", kUserAgent);
    req.setRawHeader("Accept", "application/vnd.protonmail.api+json");
    req.setRawHeader("Accept-Language", "en-US,en");
    req.setRawHeader("x-pm-locale", "en_US");
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    if (!m_uid.isEmpty()) {
        req.setRawHeader("x-pm-uid", m_uid.toUtf8());
        req.setRawHeader("Authorization", ("Bearer " + m_accessToken).toUtf8());
    }
    auto *reply = m_nam->post(req, body);
    connect(reply, &QNetworkReply::finished, this, [reply, cb, path]() {
        reply->deleteLater();
        QByteArray data = reply->readAll();
        int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        bool ok = (httpStatus >= 200 && httpStatus < 300) ||
                  (reply->error() == QNetworkReply::NoError);
        srpLog("POST %s  HTTP %d  %s", path.toLatin1().constData(), httpStatus, ok ? "OK" : "ERR");
        if (!ok) srpLog("  body: %s", data.constData());
        if (!ok && data.isEmpty())
            data = reply->errorString().toUtf8();
        cb(ok, data);
    });
}

void ProtonAuthService::getJson(const QString &path,
                                 std::function<void(bool, const QByteArray &)> cb)
{
    QNetworkRequest req(QUrl(QString(kApiBase) + path));
    req.setRawHeader("x-pm-appversion", kAppVersion);
    req.setRawHeader("User-Agent", kUserAgent);
    req.setRawHeader("Accept", "application/vnd.protonmail.api+json");
    req.setRawHeader("Accept-Language", "en-US,en");
    req.setRawHeader("x-pm-locale", "en_US");
    if (!m_uid.isEmpty()) {
        req.setRawHeader("x-pm-uid", m_uid.toUtf8());
        req.setRawHeader("Authorization", ("Bearer " + m_accessToken).toUtf8());
    }
    auto *reply = m_nam->get(req);
    connect(reply, &QNetworkReply::finished, this, [reply, cb, path]() {
        reply->deleteLater();
        QByteArray data = reply->readAll();
        int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        bool ok = (httpStatus >= 200 && httpStatus < 300) ||
                  (reply->error() == QNetworkReply::NoError);
        srpLog("GET  %s  HTTP %d  %s", path.toLatin1().constData(), httpStatus, ok ? "OK" : "ERR");
        if (!ok) srpLog("  body: %s", data.constData());
        cb(ok, data);
    });
}

// ── SRP password expansion (go-srp compatible) ───────────────────────────────

QByteArray ProtonAuthService::expandPassword(const QByteArray &pass, int srpVersion,
                                              const QByteArray &srpSalt,
                                              const QByteArray &modulus)
{
    if (srpVersion == 3 || srpVersion == 4) {
        // saltWithProton = srpSalt || "proton"; bcrypt-base64-encode, take first 22 chars
        QByteArray saltWithProton = srpSalt + QByteArray("proton");
        QString enc = bcryptBase64Encode(saltWithProton);
        QString saltStr22 = enc.left(22);
        while (saltStr22.size() < 22) saltStr22 += '.';

        QString setting = "$2y$10$" + saltStr22;
        QByteArray pw72 = pass.left(72);

        struct crypt_data cd = {};
        const char *hash = crypt_r(pw72.constData(), setting.toLatin1().constData(), &cd);
        if (!hash) return {};

        QByteArray cryptedBytes(hash, (int)strlen(hash));
        return expandHash(cryptedBytes + modulus);
    }
    // version 1/2: expandHash(SHA-512(password))
    uint8_t sha[64];
    SHA512((const uint8_t *)pass.constData(), pass.size(), sha);
    return expandHash(QByteArray((const char *)sha, 64));
}

// MailboxPassword: bcrypt(password, $2y$10$<bcryptBase64(keySalt)[:22]>, cost=10) → chars [29..] as bytes
static QByteArray mailboxPassword(const QByteArray &pass, const QByteArray &keySalt)
{
    QString enc = bcryptBase64Encode(keySalt);
    QString saltStr22 = enc.left(22);
    while (saltStr22.size() < 22) saltStr22 += '.';

    QString setting = "$2y$10$" + saltStr22;
    QByteArray pw72 = pass.left(72);

    struct crypt_data cd = {};
    const char *hash = crypt_r(pw72.constData(), setting.toLatin1().constData(), &cd);
    if (!hash) return {};

    // hash is 60 chars: "$2y$10$<22-salt><31-hash>"; return hash portion [29..] as bytes
    int len = (int)strlen(hash);
    return (len > 29) ? QByteArray(hash + 29, len - 29) : QByteArray{};
}

// ── SRP computation (go-srp compatible, all values LE) ───────────────────────

bool ProtonAuthService::computeSrp(const QByteArray &modulusLE,
                                    const QByteArray &serverEphLE,
                                    const QByteArray &hashedPassword,
                                    QByteArray &outClientEph,
                                    QByteArray &outProof)
{
    int byteLen = modulusLE.size();
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *N    = leToInt(modulusLE);
    BIGNUM *g    = BN_new(); BN_set_word(g, 2);
    BIGNUM *NMin1 = BN_new(); BN_copy(NMin1, N); BN_sub_word(NMin1, 1);

    // k = toNat(expandHash(intToLE(byteLen, g) || modulusLE)) mod N
    BIGNUM *k    = leToInt(expandHash(intToLE(g, byteLen) + modulusLE));
    BN_mod(k, k, N, ctx);

    // Generate client secret a in (1, N-1) as LE random bytes
    BIGNUM *a = BN_new();
    do {
        QByteArray rand(byteLen, '\0');
        RAND_bytes((uint8_t *)rand.data(), byteLen);
        BIGNUM *tmp = leToInt(rand);
        BN_copy(a, tmp);
        BN_free(tmp);
        BN_mod(a, a, N, ctx);
    } while (BN_cmp(a, BN_value_one()) <= 0);

    BIGNUM *A = BN_new();
    BN_mod_exp(A, g, a, N, ctx);
    outClientEph = intToLE(A, byteLen);

    // u = toNat(expandHash(A_LE || serverEphLE))
    BIGNUM *u = leToInt(expandHash(outClientEph + serverEphLE));

    // x = toNat(hashedPassword)
    BIGNUM *x = leToInt(hashedPassword);

    // B = toNat(serverEphLE)
    BIGNUM *B = leToInt(serverEphLE);

    // S = (B - k*g^x mod N)^((u*x + a) mod (N-1)) mod N
    BIGNUM *gx   = BN_new(); BN_mod_exp(gx, g, x, N, ctx);
    BIGNUM *kgx  = BN_new(); BN_mod_mul(kgx, k, gx, N, ctx);
    BIGNUM *base = BN_new(); BN_mod_sub(base, B, kgx, N, ctx);
    BIGNUM *ux   = BN_new(); BN_mul(ux, u, x, ctx);
    BIGNUM *exp_ = BN_new(); BN_add(exp_, ux, a); BN_mod(exp_, exp_, NMin1, ctx);
    BIGNUM *S    = BN_new(); BN_mod_exp(S, base, exp_, N, ctx);
    QByteArray S_LE = intToLE(S, byteLen);

    // proof = expandHash(A_LE || serverEphLE || S_LE)
    outProof = expandHash(outClientEph + serverEphLE + S_LE);

    BN_free(N); BN_free(g); BN_free(NMin1); BN_free(k); BN_free(a); BN_free(A);
    BN_free(u); BN_free(x); BN_free(B); BN_free(gx); BN_free(kgx);
    BN_free(base); BN_free(ux); BN_free(exp_); BN_free(S);
    BN_CTX_free(ctx);
    return true;
}

// ── PGP private key decryption ────────────────────────────────────────────────

bool ProtonAuthService::decryptPgpPrivateKey(const QString &armored,
                                              const QByteArray &keyPass,
                                              RsaKey &out)
{
    QByteArray raw;
    if (!pgpDearmor(armored, raw)) return false;

    const uint8_t *data = (const uint8_t *)raw.constData();
    size_t total = raw.size();
    size_t pos = 0;

    bool found = false;
    while (pos < total) {
        uint8_t tag;
        size_t bodyStart, bodyLen;
        if (!pgpNextPacket(data, total, pos, tag, bodyStart, bodyLen)) break;

        if (tag == 5 || tag == 7) {
            ProtonAuthService::RsaKey candidate;
            bool ok = decryptSecretKeyBody(data + bodyStart, bodyLen,
                                           (const uint8_t *)keyPass.constData(), keyPass.size(),
                                           candidate);
            srpLog("decryptPgpPrivateKey: tag=%d ok=%d isEcc=%d ed25519=%d x25519=%d fp=%d",
                   tag, ok, candidate.isEcc,
                   (int)candidate.ed25519Priv.size(),
                   (int)candidate.x25519Priv.size(),
                   (int)candidate.fingerprint.size());
            if (ok) {
                if (candidate.isEcc) {
                    out.isEcc = true;
                    if (!candidate.ed25519Priv.isEmpty())
                        out.ed25519Priv = candidate.ed25519Priv;
                    if (!candidate.x25519Priv.isEmpty()) {
                        out.x25519Priv    = candidate.x25519Priv;
                        out.oid           = candidate.oid;
                        out.kdfHashAlgo   = candidate.kdfHashAlgo;
                        out.kdfCipherAlgo = candidate.kdfCipherAlgo;
                        out.fingerprint   = candidate.fingerprint;
                    }
                    found = true;
                } else if (!found) {
                    out = candidate;
                    found = true;
                }
            }
        }
        pos = bodyStart + bodyLen;
    }
    srpLog("decryptPgpPrivateKey: found=%d isEcc=%d x25519=%d fp=%d",
           found, out.isEcc, (int)out.x25519Priv.size(), (int)out.fingerprint.size());
    return found;
}

// ── PGP message decryption (PKESK + SEIPD v1) ────────────────────────────────

bool ProtonAuthService::decryptPgpMessage(const QString &armored,
                                           const RsaKey &key,
                                           QByteArray &out)
{
    QByteArray raw;
    if (!pgpDearmor(armored, raw)) return false;

    const uint8_t *data = (const uint8_t *)raw.constData();
    size_t total = raw.size();
    size_t pos = 0;

    QByteArray sessionKey;
    int sessionKeyLen = 0;

    while (pos < total) {
        uint8_t tag;
        size_t bodyStart, bodyLen;
        if (!pgpNextPacket(data, total, pos, tag, bodyStart, bodyLen)) break;
        pos = bodyStart + bodyLen;

        if (tag == 1 && sessionKey.isEmpty()) {
            // PKESK: version(1) + keyId(8) + algo(1) + algo-specific data
            const uint8_t *b = data + bodyStart;
            size_t bp = 0;
            bp++;                          // version
            bp += 8;                       // key ID
            if (bp >= bodyLen) continue;
            uint8_t pkedAlgo = b[bp++];
            srpLog("decryptPgpMessage: PKESK algo=%d key.isEcc=%d x25519size=%d",
                   pkedAlgo, key.isEcc, (int)key.x25519Priv.size());

            if ((pkedAlgo == 1 || pkedAlgo == 3) && !key.isEcc) {
                // RSA OAEP
                QByteArray encSK;
                if (!pgpReadMPI(b, bodyLen, bp, encSK)) continue;
                QByteArray skWithAlgo;
                if (!rsaOaepDecrypt(key.n, key.e, key.d,
                                     (const uint8_t *)encSK.constData(), encSK.size(),
                                     skWithAlgo))
                    continue;
                if (skWithAlgo.isEmpty()) continue;
                uint8_t cipherAlgo = (uint8_t)skWithAlgo[0];
                sessionKeyLen = (cipherAlgo == 9) ? 32 : 16;
                sessionKey = skWithAlgo.mid(1);
            } else if (pkedAlgo == 18 && key.isEcc && !key.x25519Priv.isEmpty()) {
                // ECDH X25519 (RFC 6637)
                QByteArray ephMpi;
                if (!pgpReadMPI(b, bodyLen, bp, ephMpi)) {
                    srpLog("decryptPgpMessage: ECDH pgpReadMPI failed"); continue;
                }
                srpLog("decryptPgpMessage: ephMpi size=%d first=0x%02x",
                       (int)ephMpi.size(), ephMpi.isEmpty() ? 0 : (uint8_t)ephMpi[0]);
                // X25519 point is stored as 0x40 || 32-byte raw key
                if (ephMpi.size() != 33 || (uint8_t)ephMpi[0] != 0x40) {
                    srpLog("decryptPgpMessage: ephMpi format wrong (size=%d first=0x%02x)",
                           (int)ephMpi.size(), ephMpi.isEmpty() ? 0 : (uint8_t)ephMpi[0]);
                    continue;
                }
                const uint8_t *ephPub = (const uint8_t *)ephMpi.constData() + 1;

                if (bp >= bodyLen) { srpLog("decryptPgpMessage: no wrapLen byte"); continue; }
                uint8_t wrapLen = b[bp++];
                srpLog("decryptPgpMessage: wrapLen=%d remaining=%d", wrapLen, (int)(bodyLen - bp));
                if (bp + wrapLen > bodyLen) { srpLog("decryptPgpMessage: wrapLen overflow"); continue; }
                const uint8_t *wrapped = b + bp;

                // X25519 shared secret
                uint8_t sharedSecret[32] = {};
                {
                    EVP_PKEY *privEvp = EVP_PKEY_new_raw_private_key(
                        EVP_PKEY_X25519, nullptr,
                        (const uint8_t *)key.x25519Priv.constData(), 32);
                    EVP_PKEY *pubEvp = EVP_PKEY_new_raw_public_key(
                        EVP_PKEY_X25519, nullptr, ephPub, 32);
                    if (!privEvp || !pubEvp) {
                        srpLog("decryptPgpMessage: EVP_PKEY creation failed priv=%p pub=%p", privEvp, pubEvp);
                        EVP_PKEY_free(privEvp); EVP_PKEY_free(pubEvp); continue;
                    }
                    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(privEvp, nullptr);
                    size_t ssLen = 32;
                    EVP_PKEY_derive_init(kctx);
                    EVP_PKEY_derive_set_peer(kctx, pubEvp);
                    int dret = EVP_PKEY_derive(kctx, sharedSecret, &ssLen);
                    srpLog("decryptPgpMessage: X25519 derive ret=%d ssLen=%d", dret, (int)ssLen);
                    EVP_PKEY_CTX_free(kctx);
                    EVP_PKEY_free(privEvp);
                    EVP_PKEY_free(pubEvp);
                    if (dret != 1) continue;
                }

                // RFC 6637 other_info
                QByteArray otherInfo;
                otherInfo.append((char)(uint8_t)key.oid.size());
                otherInfo.append(key.oid);
                otherInfo.append((char)18);
                otherInfo.append((char)3);
                otherInfo.append((char)1);
                otherInfo.append((char)key.kdfHashAlgo);
                otherInfo.append((char)key.kdfCipherAlgo);
                otherInfo.append("Anonymous Sender    ", 20);
                otherInfo.append(key.fingerprint);
                srpLog("decryptPgpMessage: otherInfo size=%d oid=%d fp=%d hashAlgo=%d cipherAlgo=%d",
                       (int)otherInfo.size(), (int)key.oid.size(), (int)key.fingerprint.size(),
                       key.kdfHashAlgo, key.kdfCipherAlgo);

                // KDF: SHA-256(00 00 00 01 || sharedSecret || other_info)
                uint8_t kdfInput[4 + 32 + 256]; int ki = 0;
                kdfInput[ki++]=0; kdfInput[ki++]=0; kdfInput[ki++]=0; kdfInput[ki++]=1;
                memcpy(kdfInput + ki, sharedSecret, 32); ki += 32;
                memcpy(kdfInput + ki, otherInfo.constData(), otherInfo.size()); ki += otherInfo.size();
                int kekLen = (key.kdfCipherAlgo == 9) ? 32 : 16; // 9=AES-256, 7=AES-128
                uint8_t kek[32];
                SHA256(kdfInput, ki, kek); // use first kekLen bytes as the KEK

                // RFC 3394 AES keywrap then PKCS5 unpad
                QByteArray unwrapped;
                bool uwOk = rfcAes256Unwrap(kek, kekLen, wrapped, wrapLen, unwrapped);
                srpLog("decryptPgpMessage: rfcAes256Unwrap ok=%d unwrapped=%d", uwOk, (int)unwrapped.size());
                if (!uwOk) continue;
                bool padOk = pkcs5Unpad(unwrapped);
                srpLog("decryptPgpMessage: pkcs5Unpad ok=%d size=%d", padOk, (int)unwrapped.size());
                if (!padOk || unwrapped.isEmpty()) continue;

                uint8_t cipherAlgo = (uint8_t)unwrapped[0];
                sessionKeyLen = (cipherAlgo == 9) ? 32 : 16;
                sessionKey = unwrapped.mid(1, sessionKeyLen);
                srpLog("decryptPgpMessage: sessionKey cipherAlgo=%d len=%d", cipherAlgo, sessionKeyLen);
            } else {
                srpLog("decryptPgpMessage: PKESK skipped (algo=%d isEcc=%d)", pkedAlgo, key.isEcc);
            }
        } else if (tag == 18 && !sessionKey.isEmpty()) {
            // SEIPD v1: version(1) + OpenPGP-CFB-encrypted data (zero IV, prefix+2, resync)
            const uint8_t *b = data + bodyStart;
            uint8_t seipd_ver = b[0];
            size_t bp = 1; // skip version byte
            srpLog("decryptPgpMessage: SEIPD version=%d bodyLen=%d sessionKeyLen=%d", seipd_ver, (int)bodyLen, sessionKeyLen);
            srpLog("decryptPgpMessage: sessionKey[0..7]: %02x %02x %02x %02x %02x %02x %02x %02x",
                   sessionKey.size()>0?(uint8_t)sessionKey[0]:0, sessionKey.size()>1?(uint8_t)sessionKey[1]:0,
                   sessionKey.size()>2?(uint8_t)sessionKey[2]:0, sessionKey.size()>3?(uint8_t)sessionKey[3]:0,
                   sessionKey.size()>4?(uint8_t)sessionKey[4]:0, sessionKey.size()>5?(uint8_t)sessionKey[5]:0,
                   sessionKey.size()>6?(uint8_t)sessionKey[6]:0, sessionKey.size()>7?(uint8_t)sessionKey[7]:0);
            srpLog("decryptPgpMessage: ct[0..19]: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                   bodyLen>1?(uint8_t)b[1]:0, bodyLen>2?(uint8_t)b[2]:0, bodyLen>3?(uint8_t)b[3]:0, bodyLen>4?(uint8_t)b[4]:0,
                   bodyLen>5?(uint8_t)b[5]:0, bodyLen>6?(uint8_t)b[6]:0, bodyLen>7?(uint8_t)b[7]:0, bodyLen>8?(uint8_t)b[8]:0,
                   bodyLen>9?(uint8_t)b[9]:0, bodyLen>10?(uint8_t)b[10]:0, bodyLen>11?(uint8_t)b[11]:0, bodyLen>12?(uint8_t)b[12]:0,
                   bodyLen>13?(uint8_t)b[13]:0, bodyLen>14?(uint8_t)b[14]:0, bodyLen>15?(uint8_t)b[15]:0, bodyLen>16?(uint8_t)b[16]:0,
                   bodyLen>17?(uint8_t)b[17]:0, bodyLen>18?(uint8_t)b[18]:0, bodyLen>19?(uint8_t)b[19]:0, bodyLen>20?(uint8_t)b[20]:0);
            QByteArray decrypted;
            bool cfbOk = pgpCfbDecrypt((const uint8_t *)sessionKey.constData(), sessionKeyLen,
                                        b + bp, bodyLen - 1, decrypted);
            srpLog("decryptPgpMessage: pgpCfbDecrypt ok=%d decrypted=%d", cfbOk, (int)decrypted.size());
            if (!cfbOk) continue;

            // Skip OpenPGP random prefix (AES blockSize=16 + 2 check bytes)
            size_t prefixLen = 18;
            srpLog("decryptPgpMessage: first 20 decrypted bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                   decrypted.size() > 0 ? (uint8_t)decrypted[0] : 0,
                   decrypted.size() > 1 ? (uint8_t)decrypted[1] : 0,
                   decrypted.size() > 2 ? (uint8_t)decrypted[2] : 0,
                   decrypted.size() > 3 ? (uint8_t)decrypted[3] : 0,
                   decrypted.size() > 4 ? (uint8_t)decrypted[4] : 0,
                   decrypted.size() > 5 ? (uint8_t)decrypted[5] : 0,
                   decrypted.size() > 6 ? (uint8_t)decrypted[6] : 0,
                   decrypted.size() > 7 ? (uint8_t)decrypted[7] : 0,
                   decrypted.size() > 8 ? (uint8_t)decrypted[8] : 0,
                   decrypted.size() > 9 ? (uint8_t)decrypted[9] : 0,
                   decrypted.size() > 10 ? (uint8_t)decrypted[10] : 0,
                   decrypted.size() > 11 ? (uint8_t)decrypted[11] : 0,
                   decrypted.size() > 12 ? (uint8_t)decrypted[12] : 0,
                   decrypted.size() > 13 ? (uint8_t)decrypted[13] : 0,
                   decrypted.size() > 14 ? (uint8_t)decrypted[14] : 0,
                   decrypted.size() > 15 ? (uint8_t)decrypted[15] : 0,
                   decrypted.size() > 16 ? (uint8_t)decrypted[16] : 0,
                   decrypted.size() > 17 ? (uint8_t)decrypted[17] : 0,
                   decrypted.size() > 18 ? (uint8_t)decrypted[18] : 0,
                   decrypted.size() > 19 ? (uint8_t)decrypted[19] : 0);
            if ((size_t)decrypted.size() < prefixLen) { srpLog("decryptPgpMessage: too short for prefix"); continue; }
            size_t dp = prefixLen;

            const uint8_t *dm = (const uint8_t *)decrypted.constData();
            size_t dtotal = decrypted.size();
            while (dp < dtotal) {
                uint8_t tag2;
                size_t bs2, bl2;
                if (!pgpNextPacket(dm, dtotal, dp, tag2, bs2, bl2)) {
                    srpLog("decryptPgpMessage: pgpNextPacket failed at dp=%d dtotal=%d", (int)dp, (int)dtotal);
                    break;
                }
                srpLog("decryptPgpMessage: inner tag=%d bs2=%d bl2=%d", tag2, (int)bs2, (int)bl2);
                dp = bs2 + bl2;
                if (tag2 == 11 && bl2 > 6) {
                    // Literal data: format(1)+namelen(1)+name+time(4)+data
                    size_t lp = bs2;
                    lp++;              // format
                    uint8_t fnLen = dm[lp++];
                    lp += fnLen;       // filename
                    lp += 4;           // timestamp
                    srpLog("decryptPgpMessage: literal data lp=%d end=%d", (int)lp, (int)(bs2+bl2));
                    if (lp <= bs2 + bl2) {
                        out = QByteArray((const char *)(dm + lp), (int)(bs2 + bl2 - lp));
                        srpLog("decryptPgpMessage: SUCCESS out=%d bytes", (int)out.size());
                        return true;
                    }
                }
            }
            srpLog("decryptPgpMessage: SEIPD parsed but no literal data found");
        } else {
            srpLog("decryptPgpMessage: tag=%d sessionKeyEmpty=%d (skipped)", tag, sessionKey.isEmpty());
        }
    }
    srpLog("decryptPgpMessage: returning false");
    return false;
}

// ── Auth flow steps ───────────────────────────────────────────────────────────

void ProtonAuthService::stepFetchInfo()
{
    emit statusMessage("Requesting SRP challenge...");
    QJsonObject infoObj;
    infoObj["Username"] = m_email;
    QByteArray body = QJsonDocument(infoObj).toJson(QJsonDocument::Compact);
    postJson("/auth/v4/info", body, [this](bool ok, const QByteArray &resp) {
        srpLog("/auth/v4/info full response: %s", resp.constData());
        QJsonObject j = QJsonDocument::fromJson(resp).object();
        if (!ok) {
            int code = j["Code"].toInt();
            QString detail = code ? QString("Code %1").arg(code) : QString(resp);
            emit failed("Network error on /auth/v4/info: " + detail); return;
        }
        if (j["Code"].toInt() != 1000) {
            emit failed(QString("SRP info failed: Code %1").arg(j["Code"].toInt())); return;
        }
        stepAuthenticate(j["Modulus"].toString(), j["ServerEphemeral"].toString(),
                          j["Salt"].toString(), j["SRPSession"].toString(),
                          j["Version"].toInt());
    });
}

void ProtonAuthService::stepAuthenticate(const QString &modHex, const QString &serverEphB64,
                                          const QString &srpSaltB64, const QString &sessionId,
                                          int version)
{
    emit statusMessage("Computing SRP proof...");
    QByteArray modBytes     = parseSrpModulus(modHex);
    QByteArray saltBytes    = fromB64(srpSaltB64);
    QByteArray serverEphB   = fromB64(serverEphB64);
    QByteArray passExpanded = expandPassword(m_password, version, saltBytes, modBytes);

    QByteArray clientEph, proof;
    if (!computeSrp(modBytes, serverEphB, passExpanded, clientEph, proof)) {
        emit failed("SRP computation failed"); return;
    }

    emit statusMessage("Authenticating...");
    QJsonObject authObj;
    authObj["Username"]       = m_email;
    authObj["ClientEphemeral"] = toB64(clientEph);
    authObj["ClientProof"]     = toB64(proof);
    authObj["SRPSession"]      = sessionId;
    QByteArray body = QJsonDocument(authObj).toJson(QJsonDocument::Compact);

    postJson("/auth/v4", body, [this](bool ok, const QByteArray &resp) {
        srpLog("/auth/v4 full response: %s", resp.constData());
        QJsonObject j = QJsonDocument::fromJson(resp).object();
        int code = j["Code"].toInt();
        if (!ok) {
            QString detail = code ? QString("Code %1").arg(code) : QString(resp);
            emit failed("Network error on /auth/v4: " + detail); return;
        }
        if (code != 1000) {
            QString msg = (code == 8002) ? "Incorrect password." : QString("Auth failed: Code %1").arg(code);
            emit failed(msg); return;
        }
        m_uid          = j["UID"].toString();
        m_accessToken  = j["AccessToken"].toString();
        m_refreshToken = j["RefreshToken"].toString();
        m_expiresAt    = QDateTime::currentSecsSinceEpoch() + j["ExpiresIn"].toInteger(3600);
        if (j["TwoFactor"].toObject()["Enabled"].toInt() & 1) {
            emit statusMessage("Two-factor authentication required.");
            emit needsTwoFactor();
        } else {
            stepFetchSalts();
        }
    });
}

void ProtonAuthService::submitTwoFactor(const QString &code)
{
    if (code.isEmpty()) {
        emit failed("Two-factor authentication cancelled.");
        return;
    }
    emit statusMessage("Submitting two-factor code...");
    QJsonObject obj;
    obj["TwoFactorCode"] = code;
    postJson("/auth/v4/2fa", QJsonDocument(obj).toJson(QJsonDocument::Compact),
             [this](bool ok, const QByteArray &resp) {
        QJsonObject j = QJsonDocument::fromJson(resp).object();
        int c = j["Code"].toInt();
        if (!ok || c != 1000) {
            QString detail = j["Error"].toString();
            emit failed("Two-factor authentication failed: "
                        + (detail.isEmpty() ? QString("Code %1").arg(c) : detail));
            return;
        }
        stepFetchSalts();
    });
}

void ProtonAuthService::stepFetchSalts()
{
    emit statusMessage("Fetching key salts...");
    getJson("/core/v4/keys/salts", [this](bool ok, const QByteArray &resp) {
        if (!ok) { emit failed("Network error on /core/v4/keys/salts: " + QString(resp)); return; }
        QJsonObject j = QJsonDocument::fromJson(resp).object();
        QJsonArray salts = j["KeySalts"].toArray();
        for (const QJsonValue &v : salts) {
            QString salt = v.toObject()["KeySalt"].toString();
            if (!salt.isEmpty()) { m_primarySaltB64 = salt; break; }
        }
        stepFetchUserKey();
    });
}

void ProtonAuthService::stepFetchUserKey()
{
    emit statusMessage("Fetching user keys...");
    getJson("/core/v4/users", [this](bool ok, const QByteArray &resp) {
        if (!ok) { emit failed("Network error on /core/v4/users: " + QString(resp)); return; }
        QJsonObject j = QJsonDocument::fromJson(resp).object();
        QJsonArray keys = j["User"].toObject()["Keys"].toArray();
        QString primaryKey;
        for (const QJsonValue &v : keys) {
            if (v.toObject()["Primary"].toInt() == 1) {
                primaryKey = v.toObject()["PrivateKey"].toString(); break;
            }
        }
        if (primaryKey.isEmpty()) { emit failed("No primary user key found"); return; }
        stepDeriveAndDecryptUser(primaryKey);
    });
}

void ProtonAuthService::stepDeriveAndDecryptUser(const QString &userKeyArmored)
{
    emit statusMessage("Decrypting user key...");

    // Derive key passphrase from account password (go-srp MailboxPassword)
    if (!m_primarySaltB64.isEmpty()) {
        QByteArray keySalt = fromB64(m_primarySaltB64);
        m_keyPass = mailboxPassword(m_password, keySalt);
        if (m_keyPass.isEmpty()) {
            emit failed("Key passphrase derivation failed"); return;
        }
    } else {
        // Legacy accounts have no KeySalt; passphrase is the raw password bytes
        m_keyPass = m_password;
    }

    if (!decryptPgpPrivateKey(userKeyArmored, m_keyPass, m_userKey)) {
        emit failed("Failed to decrypt user private key. Wrong password?"); return;
    }
    stepFetchAddresses();
}

void ProtonAuthService::stepFetchAddresses()
{
    emit statusMessage("Fetching address keys...");
    getJson("/core/v4/addresses", [this](bool ok, const QByteArray &resp) {
        if (!ok) { emit failed("Network error on /core/v4/addresses: " + QString(resp)); return; }
        QJsonObject j = QJsonDocument::fromJson(resp).object();
        QJsonArray addresses = j["Addresses"].toArray();
        for (const QJsonValue &av : addresses) {
            QJsonObject addr = av.toObject();
            QJsonArray akeys = addr["Keys"].toArray();
            for (const QJsonValue &kv : akeys) {
                QJsonObject ak = kv.toObject();
                if (ak["Primary"].toInt() == 1) {
                    stepDecryptAddress(ak["PrivateKey"].toString(),
                                        ak["Token"].toString(),
                                        addr["Email"].toString());
                    return;
                }
            }
        }
        emit failed("No primary address key found");
    });
}

void ProtonAuthService::stepDecryptAddress(const QString &addrKeyArmored,
                                            const QString &addrKeyToken,
                                            const QString &email)
{
    emit statusMessage("Decrypting address key...");
    m_addrEmail = email;

    QByteArray addrKeyPass;
    if (!addrKeyToken.isEmpty()) {
        if (!decryptPgpMessage(addrKeyToken, m_userKey, addrKeyPass)) {
            emit failed("Failed to decrypt address key token"); return;
        }
    } else {
        addrKeyPass = m_keyPass;
    }

    if (!decryptPgpPrivateKey(addrKeyArmored, addrKeyPass, m_addrKey)) {
        emit failed("Failed to decrypt address private key"); return;
    }
    stepFetchShares();
}

void ProtonAuthService::stepFetchShares()
{
    emit statusMessage("Fetching drive metadata...");
    getJson("/drive/shares", [this](bool ok, const QByteArray &resp) {
        if (!ok) { emit failed("Network error on /drive/shares: " + QString(resp)); return; }
        QJsonObject j = QJsonDocument::fromJson(resp).object();
        if (j["Code"].toInt() != 1000) {
            emit failed(QString("Drive shares failed: Code %1").arg(j["Code"].toInt())); return;
        }
        QJsonArray shares = j["Shares"].toArray();
        for (const QJsonValue &sv : shares) {
            QJsonObject s = sv.toObject();
            bool locked = s["Locked"].toBool(true);
            if (!locked && s["Type"].toInt() == 1) {
                m_volumeId = s["VolumeID"].toString();
                stepWriteToken(s["ShareID"].toString(), s["LinkID"].toString());
                return;
            }
        }
        emit failed("No unlocked main drive share found");
    });
}

void ProtonAuthService::stepWriteToken(const QString &shareId, const QString &rootLinkId)
{
    emit statusMessage("Saving token...");

    QJsonObject tok;
    tok["access_token"]  = m_accessToken;
    tok["refresh_token"] = m_refreshToken;
    tok["expires_at"]    = m_expiresAt;
    tok["uid"]           = m_uid;
    tok["volume_id"]     = m_volumeId;
    tok["share_id"]      = shareId;
    tok["root_link_id"]  = rootLinkId;
    tok["address_email"] = m_addrEmail;
    if (m_addrKey.isEcc) {
        tok["address_key_type"]    = QString("ecc");
        tok["address_key_x25519"]  = toB64(m_addrKey.x25519Priv);
        tok["address_key_ed25519"] = toB64(m_addrKey.ed25519Priv);
        tok["address_key_oid"]     = toB64(m_addrKey.oid);
        tok["address_kdf_hash"]    = (int)m_addrKey.kdfHashAlgo;
        tok["address_kdf_cipher"]  = (int)m_addrKey.kdfCipherAlgo;
        tok["address_key_fp"]      = toB64(m_addrKey.fingerprint);
    } else {
        tok["address_key_type"] = QString("rsa");
        tok["address_key_n"]    = toB64(m_addrKey.n);
        tok["address_key_e"]    = toB64(m_addrKey.e);
        tok["address_key_d"]    = toB64(m_addrKey.d);
        tok["address_key_p"]    = toB64(m_addrKey.p);
        tok["address_key_q"]    = toB64(m_addrKey.q);
        tok["address_key_dp"]   = toB64(m_addrKey.dp.isEmpty() ? m_addrKey.d : m_addrKey.dp);
        tok["address_key_dq"]   = toB64(m_addrKey.dq.isEmpty() ? m_addrKey.d : m_addrKey.dq);
        tok["address_key_qi"]   = toB64(m_addrKey.qi);
    }

    QByteArray json = QJsonDocument(tok).toJson(QJsonDocument::Indented);

    // Atomic write: temp + rename, 0600 permissions
    QString dir = QFileInfo(m_tokenPath).absolutePath();
    QDir().mkpath(dir);
    QString tmpPath = m_tokenPath + ".tmp";

    int fd = open(tmpPath.toUtf8().constData(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { emit failed("Failed to create token file"); return; }
    ssize_t written = 0;
    while (written < json.size()) {
        ssize_t n = ::write(fd, json.constData() + written, json.size() - written);
        if (n < 0) { if (errno == EINTR) continue; ::close(fd); unlink(tmpPath.toUtf8()); emit failed("Token write error"); return; }
        written += n;
    }
    ::close(fd);
    if (rename(tmpPath.toUtf8().constData(), m_tokenPath.toUtf8().constData()) != 0) {
        unlink(tmpPath.toUtf8());
        emit failed("Failed to finalize token file");
        return;
    }

    emit statusMessage("Authentication successful!");
    emit succeeded();
}

// ── Remote app listing ────────────────────────────────────────────────────────

static QString hmacSha256Hex(const QByteArray &key, const QByteArray &data)
{
    unsigned char digest[32];
    unsigned int len = 32;
    HMAC(EVP_sha256(),
         (const unsigned char *)key.constData(), key.size(),
         (const unsigned char *)data.constData(), data.size(),
         digest, &len);
    QString hex;
    hex.reserve(64);
    for (int i = 0; i < 32; ++i)
        hex += QString("%1").arg(digest[i], 2, 16, QChar('0'));
    return hex;
}

bool ProtonAuthService::loadTokenFile(const QString &tokenPath)
{
    QFile f(tokenPath);
    if (!f.open(QIODevice::ReadOnly)) return false;
    QJsonObject tok = QJsonDocument::fromJson(f.readAll()).object();
    f.close();

    m_accessToken    = tok["access_token"].toString();
    m_uid            = tok["uid"].toString();
    m_listShareId    = tok["share_id"].toString();
    m_listRootLinkId = tok["root_link_id"].toString();

    if (m_accessToken.isEmpty() || m_uid.isEmpty() ||
        m_listShareId.isEmpty() || m_listRootLinkId.isEmpty())
        return false;

    QString keyType = tok["address_key_type"].toString();
    if (keyType == "ecc") {
        m_addrKey               = {};
        m_addrKey.isEcc         = true;
        m_addrKey.x25519Priv    = fromB64(tok["address_key_x25519"].toString());
        m_addrKey.ed25519Priv   = fromB64(tok["address_key_ed25519"].toString());
        m_addrKey.oid           = fromB64(tok["address_key_oid"].toString());
        m_addrKey.kdfHashAlgo   = (uint8_t)tok["address_kdf_hash"].toInt(8);
        m_addrKey.kdfCipherAlgo = (uint8_t)tok["address_kdf_cipher"].toInt(9);
        m_addrKey.fingerprint   = fromB64(tok["address_key_fp"].toString());
    } else {
        m_addrKey       = {};
        m_addrKey.isEcc = false;
        m_addrKey.n  = fromB64(tok["address_key_n"].toString());
        m_addrKey.e  = fromB64(tok["address_key_e"].toString());
        m_addrKey.d  = fromB64(tok["address_key_d"].toString());
        m_addrKey.p  = fromB64(tok["address_key_p"].toString());
        m_addrKey.q  = fromB64(tok["address_key_q"].toString());
        m_addrKey.dp = fromB64(tok["address_key_dp"].toString());
        m_addrKey.dq = fromB64(tok["address_key_dq"].toString());
        m_addrKey.qi = fromB64(tok["address_key_qi"].toString());
    }
    return true;
}

void ProtonAuthService::listRemoteApps(const QString &tokenPath, const QString &accountId)
{
    m_listAccountId = accountId;
    m_tokenPath     = tokenPath;
    m_deleteMode    = false;
    if (!loadTokenFile(tokenPath)) {
        emit failed("Cannot read or incomplete Proton token — re-authenticate");
        return;
    }
    listFetchShare();
}

void ProtonAuthService::deleteAppFolder(const QString &tokenPath,
                                         const QString &accountId,
                                         uint32_t appId)
{
    m_listAccountId = accountId;
    m_tokenPath     = tokenPath;
    m_deleteMode    = true;
    m_deleteAppId   = appId;
    if (!loadTokenFile(tokenPath)) {
        emit failed("Cannot read or incomplete Proton token — re-authenticate");
        return;
    }
    listFetchShare();
}

void ProtonAuthService::listFetchShare()
{
    getJson("/drive/v2/shares/" + m_listShareId, [this](bool ok, const QByteArray &resp) {
        if (!ok) { emit failed("Proton list: failed to fetch share"); return; }
        QJsonObject share = QJsonDocument::fromJson(resp).object()["Share"].toObject();
        QString shareKey        = share["Key"].toString();
        QString sharePassphrase = share["Passphrase"].toString();

        QByteArray passBytes;
        bool decOk = decryptPgpMessage(sharePassphrase, m_addrKey, passBytes);
        if (!decOk) {
            QByteArray decoded = QByteArray::fromBase64(sharePassphrase.toUtf8());
            decOk = decryptPgpMessage(QString::fromLatin1(decoded), m_addrKey, passBytes);
        }
        if (!decOk) { emit failed("Proton list: failed to decrypt share passphrase"); return; }

        RsaKey shareKeyPair;
        if (!decryptPgpPrivateKey(shareKey, passBytes, shareKeyPair)) {
            emit failed("Proton list: failed to load share key");
            return;
        }

        listFetchRootLink(shareKeyPair);
    });
}

void ProtonAuthService::listFetchRootLink(const RsaKey &shareKey)
{
    QString path = "/drive/v2/shares/" + m_listShareId + "/links/" + m_listRootLinkId;
    getJson(path, [this, shareKey](bool ok, const QByteArray &resp) {
        if (!ok) { emit failed("Proton list: failed to fetch root link"); return; }
        QJsonObject link = QJsonDocument::fromJson(resp).object()["Link"].toObject();

        QString nodeKey        = link["NodeKey"].toString();
        QString nodePassphrase = link["NodePassphrase"].toString();
        QString nodeHashKey    = link["NodeHashKey"].toString();

        QByteArray nodePassBytes;
        if (!decryptPgpMessage(nodePassphrase, shareKey, nodePassBytes)) {
            emit failed("Proton list: failed to decrypt root node passphrase");
            return;
        }
        RsaKey rootNodeKey;
        if (!decryptPgpPrivateKey(nodeKey, nodePassBytes, rootNodeKey)) {
            emit failed("Proton list: failed to load root node key");
            return;
        }
        QByteArray hashKeyBytes;
        if (!decryptPgpMessage(nodeHashKey, rootNodeKey, hashKeyBytes)) {
            emit failed("Proton list: failed to decrypt root hash key");
            return;
        }

        listFindFolder(rootNodeKey, hashKeyBytes, m_listRootLinkId, "cloudredirect", false);
    });
}

void ProtonAuthService::listFindFolder(const RsaKey &parentKey, const QByteArray &hashKey,
                                        const QString &parentLinkId, const QString &targetName,
                                        bool isAccountFolder)
{
    QString targetHash = hmacSha256Hex(hashKey, targetName.toLower().toUtf8());
    QString path = "/drive/v2/shares/" + m_listShareId + "/folders/" + parentLinkId
                 + "/children?Page=0&PageSize=150";

    getJson(path, [this, parentKey, targetHash, isAccountFolder](bool ok, const QByteArray &resp) {
        if (!ok) { emit failed("Proton list: failed to list folder children"); return; }
        QJsonArray links = QJsonDocument::fromJson(resp).object()["Links"].toArray();

        for (const QJsonValue &v : links) {
            QJsonObject lj = v.toObject();
            if (lj["Hash"].toString().toLower() != targetHash) continue;

            QString childLinkId      = lj["LinkID"].toString();
            QString childNodeKey     = lj["NodeKey"].toString();
            QString childNodePass    = lj["NodePassphrase"].toString();
            QString childNodeHashKey = lj["NodeHashKey"].toString();

            QByteArray childPassBytes;
            if (!decryptPgpMessage(childNodePass, parentKey, childPassBytes)) {
                emit failed("Proton list: failed to decrypt folder node passphrase");
                return;
            }
            RsaKey childKey;
            if (!decryptPgpPrivateKey(childNodeKey, childPassBytes, childKey)) {
                emit failed("Proton list: failed to load folder node key");
                return;
            }
            QByteArray childHashBytes;
            if (!decryptPgpMessage(childNodeHashKey, childKey, childHashBytes)) {
                emit failed("Proton list: failed to decrypt folder hash key");
                return;
            }

            if (!isAccountFolder) {
                listFindFolder(childKey, childHashBytes, childLinkId,
                               m_listAccountId, true);
            } else if (m_deleteMode) {
                delFindAppFolder(childKey, childHashBytes, childLinkId);
            } else {
                auto result = std::make_shared<QList<uint32_t>>();
                listFetchAppChildren(childKey, childLinkId, 0, result);
            }
            return;
        }

        if (m_deleteMode) {
            // Folder not found — already gone, treat as success
            emit appFolderDeleted();
        } else {
            fprintf(stderr, "[Proton] %s folder not found in drive\n",
                    isAccountFolder ? qPrintable(m_listAccountId) : "CloudRedirect");
            emit remoteAppsListed({});
        }
    });
}

void ProtonAuthService::listFetchAppChildren(const RsaKey &accountKey,
                                              const QString &accountLinkId,
                                              int page,
                                              std::shared_ptr<QList<uint32_t>> result)
{
    QString path = "/drive/v2/shares/" + m_listShareId + "/folders/" + accountLinkId
                 + "/children?Page=" + QString::number(page) + "&PageSize=150";

    getJson(path, [this, accountKey, accountLinkId, page, result](bool ok, const QByteArray &resp) {
        if (!ok) {
            emit remoteAppsListed(*result);
            return;
        }
        QJsonArray links = QJsonDocument::fromJson(resp).object()["Links"].toArray();

        for (const QJsonValue &v : links) {
            QJsonObject lj = v.toObject();
            if (lj["State"].toInt() == 2) continue;
            if (lj["Type"].toInt() != 1) continue;

            QString childNodeKey  = lj["NodeKey"].toString();
            QString childNodePass = lj["NodePassphrase"].toString();
            QString nameEncrypted = lj["Name"].toString();

            QByteArray childPassBytes;
            if (!decryptPgpMessage(childNodePass, accountKey, childPassBytes)) continue;
            RsaKey childKey;
            if (!decryptPgpPrivateKey(childNodeKey, childPassBytes, childKey)) continue;

            QByteArray nameBytes;
            if (!decryptPgpMessage(nameEncrypted, childKey, nameBytes)) continue;

            bool parseOk;
            uint32_t appId = QString::fromUtf8(nameBytes).toUInt(&parseOk);
            if (parseOk && appId > 0)
                result->append(appId);
        }

        if (links.size() == 150) {
            listFetchAppChildren(accountKey, accountLinkId, page + 1, result);
        } else {
            emit remoteAppsListed(*result);
        }
    });
}

void ProtonAuthService::delFindAppFolder(const RsaKey &accountKey,
                                          const QByteArray &accountHashKey,
                                          const QString &accountLinkId)
{
    QString targetHash = hmacSha256Hex(accountHashKey,
                                       QString::number(m_deleteAppId).toUtf8());
    QString path = "/drive/v2/shares/" + m_listShareId + "/folders/" + accountLinkId
                 + "/children?Page=0&PageSize=150";

    getJson(path, [this, accountKey, targetHash](bool ok, const QByteArray &resp) {
        if (!ok) { emit failed("Proton delete: failed to list account folder children"); return; }
        QJsonArray links = QJsonDocument::fromJson(resp).object()["Links"].toArray();

        for (const QJsonValue &v : links) {
            QJsonObject lj = v.toObject();
            if (lj["Hash"].toString().toLower() != targetHash) continue;
            if (lj["State"].toInt() == 2) {
                // Already in trash
                emit appFolderDeleted();
                return;
            }
            delTrashFolder(lj["LinkID"].toString());
            return;
        }
        // Not found — already gone
        emit appFolderDeleted();
    });
}

void ProtonAuthService::delTrashFolder(const QString &linkId)
{
    QString path = "/drive/v2/shares/" + m_listShareId + "/links/trash";
    QJsonObject body;
    body["LinkIDs"] = QJsonArray{linkId};
    postJson(path, QJsonDocument(body).toJson(QJsonDocument::Compact),
             [this](bool ok, const QByteArray &resp) {
        if (!ok) {
            QJsonObject j = QJsonDocument::fromJson(resp).object();
            emit failed(QString("Proton delete: trash failed (Code %1)")
                        .arg(j["Code"].toInt()));
            return;
        }
        emit appFolderDeleted();
    });
}

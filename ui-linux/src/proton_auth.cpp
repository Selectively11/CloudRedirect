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

static const char *kApiBase    = "https://mail.proton.me/api";
static const char *kAppVersion = "external-drive-cloudredirect@2.1.8-stable";

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

// OpenPGP CFB decrypt: zero IV, 16-byte random prefix, 2 check bytes, resync, then data.
// Used for SEIPD (Symmetrically Encrypted Integrity Protected Data) packets.
static bool pgpCfbDecrypt(const uint8_t *key, int keyLen,
                           const uint8_t *ct, size_t ctLen,
                           QByteArray &out)
{
    out.resize((int)ctLen);
    if (ctLen == 0) return true;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    const EVP_CIPHER *ecb = (keyLen == 32) ? EVP_aes_256_ecb() : EVP_aes_128_ecb();
    EVP_EncryptInit_ex(ctx, ecb, nullptr, key, nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    uint8_t fr[16] = {};
    uint8_t fre[16];
    uint8_t *outP = (uint8_t *)out.data();
    int dummy = 16;
    size_t pos = 0;

    // Decrypt first 16 bytes (random prefix)
    EVP_EncryptUpdate(ctx, fre, &dummy, fr, 16);
    size_t step1 = (ctLen < 16) ? ctLen : 16;
    for (size_t i = 0; i < step1; i++) outP[i] = ct[i] ^ fre[i];
    pos = step1;

    if (pos + 2 <= ctLen) {
        // Decrypt 2 check bytes
        memcpy(fr, ct, 16);
        EVP_EncryptUpdate(ctx, fre, &dummy, fr, 16);
        outP[pos]   = ct[pos]   ^ fre[0];
        outP[pos+1] = ct[pos+1] ^ fre[1];
        pos += 2;

        // Resync: new FR = ct[2..17]
        memcpy(fr, ct + 2, 16);

        // Decrypt remaining bytes in 16-byte ECB blocks
        while (pos < ctLen) {
            EVP_EncryptUpdate(ctx, fre, &dummy, fr, 16);
            size_t n = ctLen - pos;
            if (n > 16) n = 16;
            for (size_t i = 0; i < n; i++) outP[pos + i] = ct[pos + i] ^ fre[i];
            memcpy(fr, ct + pos, n);
            pos += n;
        }
    }

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

// ── PGP private key decryption ────────────────────────────────────────────────

// Decrypt one secret key packet body; return true and fill `out` on success.
static bool decryptSecretKeyBody(const uint8_t *body, size_t bodyLen,
                                  const uint8_t *keyPass, size_t keyPassLen,
                                  ProtonAuthService::RsaKey &out)
{
    // Expose RsaKey fields via a helper struct pointer trick isn't available —
    // use local variables and copy out.
    size_t pos = 0;
    if (pos >= bodyLen || body[pos++] != 4) return false; // v4 only
    pos += 4; // creation time
    uint8_t algo = body[pos++];
    if (algo != 1 && algo != 3) return false; // RSA only

    QByteArray n, e;
    if (!pgpReadMPI(body, bodyLen, pos, n)) return false;
    if (!pgpReadMPI(body, bodyLen, pos, e)) return false;

    if (pos >= bodyLen) return false;
    uint8_t s2kUsage = body[pos++];

    if (s2kUsage == 0) {
        // Unencrypted key (shouldn't happen for Proton, but handle it)
        QByteArray d, p, q, qi;
        if (!pgpReadMPI(body, bodyLen, pos, d)) return false;
        if (!pgpReadMPI(body, bodyLen, pos, p)) return false;
        if (!pgpReadMPI(body, bodyLen, pos, q)) return false;
        if (!pgpReadMPI(body, bodyLen, pos, qi)) return false;
        out = { n, e, d, p, q, {}, {}, qi };
        return true;
    }
    if (s2kUsage != 254 && s2kUsage != 255) return false;

    if (pos >= bodyLen) return false;
    uint8_t cipherAlgo = body[pos++];
    int aesKeyLen = (cipherAlgo == 9) ? 32 : 16; // 9=AES-256, 7=AES-128, others=16
    int ivLen     = (cipherAlgo == 3) ? 8  : 16; // 3=CAST5 (8-byte IV), others 16

    if (pos >= bodyLen) return false;
    uint8_t s2kType = body[pos++];

    QByteArray aesKey;

    if (s2kType == 3) {
        // Iterated+Salted
        if (pos >= bodyLen) return false;
        uint8_t hashAlgo = body[pos++];
        if (pos + 9 > bodyLen) return false;
        const uint8_t *salt8 = body + pos; pos += 8;
        uint8_t countByte = body[pos++];
        uint32_t iters = uint32_t(16 + (countByte & 15)) << ((countByte >> 4) + 6);
        aesKey = s2kIterated(salt8, keyPass, keyPassLen, hashAlgo, iters, aesKeyLen);
    } else if (s2kType == 4) {
        // Argon2id (RFC 9580 / crypto-refresh)
        if (pos + 19 > bodyLen) return false;
        const uint8_t *salt16 = body + pos; pos += 16;
        uint8_t t = body[pos++]; // iterations
        uint8_t p = body[pos++]; // parallelism
        uint8_t m = body[pos++]; // memory: 2^m kibibytes
        uint32_t memKib = 1u << m;
        aesKey.resize(aesKeyLen);
        if (argon2id_hash_raw(t, memKib, p, keyPass, keyPassLen,
                               salt16, 16, aesKey.data(), aesKeyLen) != ARGON2_OK)
            return false;
    } else {
        return false; // unsupported S2K type
    }

    if (pos + ivLen > (int)bodyLen) return false;
    const uint8_t *iv = body + pos; pos += ivLen;

    size_t encLen = bodyLen - pos;
    QByteArray decrypted;
    if (!aesCfbDecrypt((const uint8_t *)aesKey.constData(), aesKeyLen,
                        iv, ivLen,
                        body + pos, encLen, decrypted))
        return false;

    // Secret MPIs end: usage 254 → 20-byte SHA-1 checksum; 255 → 2-byte simple
    size_t checksumLen = (s2kUsage == 254) ? 20 : 2;
    if ((size_t)decrypted.size() <= checksumLen) return false;
    size_t mpiEnd = decrypted.size() - checksumLen;

    size_t mpos = 0;
    const uint8_t *dm = (const uint8_t *)decrypted.constData();
    QByteArray d, pp, qq, qi;
    if (!pgpReadMPI(dm, mpiEnd, mpos, d))  return false;
    if (!pgpReadMPI(dm, mpiEnd, mpos, pp)) return false;
    if (!pgpReadMPI(dm, mpiEnd, mpos, qq)) return false;
    if (!pgpReadMPI(dm, mpiEnd, mpos, qi)) return false;

    out = { n, e, d, pp, qq, {}, {}, qi };
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
    req.setRawHeader("User-Agent", kAppVersion);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    if (!m_uid.isEmpty()) {
        req.setRawHeader("x-pm-uid", m_uid.toUtf8());
        req.setRawHeader("Authorization", ("Bearer " + m_accessToken).toUtf8());
    }
    auto *reply = m_nam->post(req, body);
    connect(reply, &QNetworkReply::finished, this, [reply, cb]() {
        reply->deleteLater();
        if (reply->error() != QNetworkReply::NoError) {
            cb(false, reply->errorString().toUtf8());
        } else {
            cb(true, reply->readAll());
        }
    });
}

void ProtonAuthService::getJson(const QString &path,
                                 std::function<void(bool, const QByteArray &)> cb)
{
    QNetworkRequest req(QUrl(QString(kApiBase) + path));
    req.setRawHeader("x-pm-appversion", kAppVersion);
    req.setRawHeader("User-Agent", kAppVersion);
    if (!m_uid.isEmpty()) {
        req.setRawHeader("x-pm-uid", m_uid.toUtf8());
        req.setRawHeader("Authorization", ("Bearer " + m_accessToken).toUtf8());
    }
    auto *reply = m_nam->get(req);
    connect(reply, &QNetworkReply::finished, this, [reply, cb]() {
        reply->deleteLater();
        if (reply->error() != QNetworkReply::NoError) {
            cb(false, reply->errorString().toUtf8());
        } else {
            cb(true, reply->readAll());
        }
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

    while (pos < total) {
        uint8_t tag;
        size_t bodyStart, bodyLen;
        if (!pgpNextPacket(data, total, pos, tag, bodyStart, bodyLen)) break;

        if (tag == 5 || tag == 7) { // secret key or subkey
            ProtonAuthService::RsaKey candidate;
            if (decryptSecretKeyBody(data + bodyStart, bodyLen,
                                      (const uint8_t *)keyPass.constData(), keyPass.size(),
                                      candidate)) {
                out = candidate;
                return true;
            }
        }
        pos = bodyStart + bodyLen;
    }
    return false;
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
            // PKESK: version(1) + keyId(8) + algo(1) + encrypted-session-key MPI
            const uint8_t *b = data + bodyStart;
            size_t bp = 0;
            bp++; // version
            bp += 8; // key ID
            bp++; // algo
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
        } else if (tag == 18 && !sessionKey.isEmpty()) {
            // SEIPD v1: version(1) + OpenPGP-CFB-encrypted data (zero IV, prefix+2, resync)
            const uint8_t *b = data + bodyStart;
            size_t bp = 1; // skip version byte
            QByteArray decrypted;
            if (!pgpCfbDecrypt((const uint8_t *)sessionKey.constData(), sessionKeyLen,
                                b + bp, bodyLen - 1, decrypted))
                continue;

            // Skip OpenPGP random prefix (AES blockSize=16 + 2 check bytes)
            size_t prefixLen = 18;
            if ((size_t)decrypted.size() < prefixLen) continue;
            size_t dp = prefixLen;

            const uint8_t *dm = (const uint8_t *)decrypted.constData();
            size_t dtotal = decrypted.size();
            while (dp < dtotal) {
                uint8_t tag2;
                size_t bs2, bl2;
                if (!pgpNextPacket(dm, dtotal, dp, tag2, bs2, bl2)) break;
                dp = bs2 + bl2;
                if (tag2 == 11 && bl2 > 6) {
                    // Literal data: format(1)+namelen(1)+name+time(4)+data
                    size_t lp = bs2;
                    lp++;              // format
                    uint8_t fnLen = dm[lp++];
                    lp += fnLen;       // filename
                    lp += 4;           // timestamp
                    if (lp <= bs2 + bl2) {
                        out = QByteArray((const char *)(dm + lp), (int)(bs2 + bl2 - lp));
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

// ── Auth flow steps ───────────────────────────────────────────────────────────

void ProtonAuthService::stepFetchInfo()
{
    emit statusMessage("Requesting SRP challenge...");
    QJsonObject infoObj;
    infoObj["Username"] = m_email;
    infoObj["Intent"]   = QString("Proton");
    QByteArray body = QJsonDocument(infoObj).toJson(QJsonDocument::Compact);
    postJson("/auth/v4/info", body, [this](bool ok, const QByteArray &resp) {
        if (!ok) { emit failed("Network error on /auth/v4/info: " + QString(resp)); return; }
        QJsonObject j = QJsonDocument::fromJson(resp).object();
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
    authObj["Intent"]          = "Proton";
    QByteArray body = QJsonDocument(authObj).toJson(QJsonDocument::Compact);

    postJson("/auth/v4", body, [this](bool ok, const QByteArray &resp) {
        if (!ok) { emit failed("Network error on /auth/v4: " + QString(resp)); return; }
        QJsonObject j = QJsonDocument::fromJson(resp).object();
        int code = j["Code"].toInt();
        if (code != 1000) {
            QString msg = (code == 8002) ? "Incorrect password." : QString("Auth failed: Code %1").arg(code);
            emit failed(msg); return;
        }
        m_uid          = j["UID"].toString();
        m_accessToken  = j["AccessToken"].toString();
        m_refreshToken = j["RefreshToken"].toString();
        m_expiresAt    = QDateTime::currentSecsSinceEpoch() + j["ExpiresIn"].toInteger(3600);
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

    // Derive key passphrase from account password
    if (!m_primarySaltB64.isEmpty()) {
        QByteArray keySalt = fromB64(m_primarySaltB64);
        QByteArray out(32, '\0');
        if (argon2id_hash_raw(4, 65536, 4,
                               m_password.constData(), m_password.size(),
                               keySalt.constData(), keySalt.size(),
                               out.data(), 32) != ARGON2_OK) {
            emit failed("Argon2id key derivation failed"); return;
        }
        m_keyPass = out;
    } else {
        uint8_t sha[32];
        SHA256((const uint8_t *)m_password.constData(), m_password.size(), sha);
        m_keyPass = QByteArray((const char *)sha, 32);
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
    stepFetchVolumes();
}

void ProtonAuthService::stepFetchVolumes()
{
    emit statusMessage("Fetching drive metadata...");
    getJson("/drive/v2/volumes", [this](bool ok, const QByteArray &resp) {
        if (!ok) { emit failed("Network error on /drive/v2/volumes: " + QString(resp)); return; }
        QJsonObject j = QJsonDocument::fromJson(resp).object();
        QJsonArray vols = j["Volumes"].toArray();
        if (vols.isEmpty()) { emit failed("No Drive volume found"); return; }
        QString volId = vols[0].toObject()["VolumeID"].toString();
        if (volId.isEmpty()) { emit failed("Empty volume ID"); return; }
        stepFetchShares(volId);
    });
}

void ProtonAuthService::stepFetchShares(const QString &volumeId)
{
    m_volumeId = volumeId;
    getJson("/drive/v2/volumes/" + volumeId + "/shares",
            [this](bool ok, const QByteArray &resp) {
        if (!ok) { emit failed("Network error fetching shares: " + QString(resp)); return; }
        QJsonObject j = QJsonDocument::fromJson(resp).object();
        QJsonArray shares = j["Shares"].toArray();
        for (const QJsonValue &sv : shares) {
            QJsonObject s = sv.toObject();
            if (s["IsLocked"].toInt() == 0 && s["Type"].toInt() == 1) {
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
    tok["address_key_n"]  = toB64(m_addrKey.n);
    tok["address_key_e"]  = toB64(m_addrKey.e);
    tok["address_key_d"]  = toB64(m_addrKey.d);
    tok["address_key_p"]  = toB64(m_addrKey.p);
    tok["address_key_q"]  = toB64(m_addrKey.q);
    tok["address_key_dp"] = toB64(m_addrKey.dp.isEmpty() ? m_addrKey.d : m_addrKey.dp);
    tok["address_key_dq"] = toB64(m_addrKey.dq.isEmpty() ? m_addrKey.d : m_addrKey.dq);
    tok["address_key_qi"] = toB64(m_addrKey.qi);

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

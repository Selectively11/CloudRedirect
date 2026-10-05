#pragma once
#include <QObject>
#include <QString>
#include <QByteArray>
#include <QList>
#include <functional>
#include <memory>
#include <vector>

class QNetworkAccessManager;
class QNetworkReply;

class ProtonAuthService : public QObject
{
    Q_OBJECT

public:
    explicit ProtonAuthService(QObject *parent = nullptr);

    struct RsaKey {
        // RSA fields (used when isEcc == false)
        QByteArray n, e, d, p, q, dp, dq, qi;
        // ECC fields (used when isEcc == true)
        bool isEcc = false;
        QByteArray ed25519Priv;
        QByteArray x25519Priv;   // 32 bytes, little-endian (OpenSSL EVP_PKEY_X25519 format)
        // ECDH KDF metadata (needed for address-key-token decryption)
        QByteArray oid;
        uint8_t kdfHashAlgo   = 8; // SHA-256
        uint8_t kdfCipherAlgo = 9; // AES-256
        QByteArray fingerprint;    // SHA-1 of public key packet body, for KDF param
    };

    void start(const QString &email, const QString &password, const QString &tokenPath);
    void listRemoteApps(const QString &tokenPath, const QString &accountId);
    void deleteAppFolder(const QString &tokenPath, const QString &accountId, uint32_t appId);
    void submitTwoFactor(const QString &code);

signals:
    void statusMessage(const QString &msg);
    void succeeded();
    void failed(const QString &error);
    void needsTwoFactor();
    void remoteAppsListed(const QList<uint32_t> &appIds);
    void appFolderDeleted();

private:
    QString   m_email;
    QByteArray m_password;
    QString   m_tokenPath;
    QNetworkAccessManager *m_nam;

    // Session
    QString m_uid;
    QString m_accessToken;
    QString m_refreshToken;
    qint64  m_expiresAt = 0;

    // Key derivation
    QString    m_primarySaltB64;
    QByteArray m_keyPass;

    // Keys
    RsaKey  m_userKey;
    RsaKey  m_addrKey;
    QString m_addrEmail;

    // Drive metadata
    QString m_volumeId;
    QString m_shareId;
    QString m_rootLinkId;

    // Listing / delete flow state
    QString  m_listAccountId;
    QString  m_listShareId;
    QString  m_listRootLinkId;
    bool     m_deleteMode = false;
    uint32_t m_deleteAppId = 0;

    // HTTP helpers
    void postJson(const QString &path, const QByteArray &body,
                  std::function<void(bool, const QByteArray &)> cb);
    void getJson(const QString &path,
                 std::function<void(bool, const QByteArray &)> cb);

    // Crypto
    QByteArray expandPassword(const QByteArray &pass, int srpVersion,
                              const QByteArray &srpSalt, const QByteArray &modulus);
    bool computeSrp(const QByteArray &modulusLE, const QByteArray &serverEphLE,
                    const QByteArray &hashedPassword,
                    QByteArray &outClientEph, QByteArray &outProof);
    bool decryptPgpPrivateKey(const QString &armored, const QByteArray &keyPass, RsaKey &out);
    bool decryptPgpMessage(const QString &armored, const RsaKey &key, QByteArray &out);

    // Auth flow steps
    void stepFetchInfo();
    void stepAuthenticate(const QString &modHex, const QString &serverEphB64,
                          const QString &srpSaltB64, const QString &sessionId, int version);
    void stepFetchSalts();
    void stepFetchUserKey();
    void stepDeriveAndDecryptUser(const QString &userKeyArmored);
    void stepFetchAddresses();
    void stepDecryptAddress(const QString &addrKeyArmored, const QString &addrKeyToken,
                            const QString &email);
    void stepFetchShares();
    void stepWriteToken(const QString &shareId, const QString &rootLinkId);

    // Shared token loading for listing and delete
    bool loadTokenFile(const QString &tokenPath);

    // Remote-app listing steps
    void listFetchShare();
    void listFetchRootLink(const RsaKey &shareKey);
    void listFindFolder(const RsaKey &parentKey, const QByteArray &hashKey,
                        const QString &parentLinkId, const QString &targetName,
                        bool isAccountFolder);
    void listFetchAppChildren(const RsaKey &accountKey, const QString &accountLinkId,
                              int page, std::shared_ptr<QList<uint32_t>> result);

    // Delete-specific steps (reuse listFetchShare/listFetchRootLink/listFindFolder)
    void delFindAppFolder(const RsaKey &accountKey, const QByteArray &accountHashKey,
                          const QString &accountLinkId);
    void delTrashFolder(const QString &linkId);

};

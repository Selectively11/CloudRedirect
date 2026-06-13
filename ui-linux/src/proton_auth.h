#pragma once
#include <QObject>
#include <QString>
#include <QByteArray>
#include <functional>
#include <vector>

class QNetworkAccessManager;
class QNetworkReply;

class ProtonAuthService : public QObject
{
    Q_OBJECT

public:
    explicit ProtonAuthService(QObject *parent = nullptr);

    struct RsaKey { QByteArray n, e, d, p, q, dp, dq, qi; };

    void start(const QString &email, const QString &password, const QString &tokenPath);

signals:
    void statusMessage(const QString &msg);
    void succeeded();
    void failed(const QString &error);

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
    void stepFetchVolumes();
    void stepFetchShares(const QString &volumeId);
    void stepWriteToken(const QString &shareId, const QString &rootLinkId);
};

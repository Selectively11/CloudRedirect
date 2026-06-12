#pragma once
#include <QObject>
#include <QString>
#include <QTcpServer>

// OAuth2 auth code flow with PKCE.

class OAuthService : public QObject
{
    Q_OBJECT

public:
    explicit OAuthService(QObject *parent = nullptr);
    ~OAuthService();

    Q_INVOKABLE void startAuth(const QString &provider, const QString &tokenPath);
    Q_INVOKABLE void startProtonAuth(const QString &email, const QString &password, const QString &tokenPath);
    Q_INVOKABLE void cancel();

signals:
    void authSucceeded(const QString &provider);
    void authFailed(const QString &provider, const QString &error);
    void statusMessage(const QString &msg);

private slots:
    void onNewConnection();

private:
    QString generateRandomString(int length);
    QString computeCodeChallenge(const QString &verifier);
    void exchangeCodeForTokens(const QString &code, int retryCount = 0);

    QTcpServer *m_server = nullptr;
    QString m_provider;
    QString m_tokenPath;
    QString m_state;
    QString m_codeVerifier;
    QString m_redirectUri;
    int m_port = 0;
};

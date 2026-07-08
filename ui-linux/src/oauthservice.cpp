#include "oauthservice.h"
#include <QTcpSocket>
#include <QDesktopServices>
#include <QUrl>
#include <QUrlQuery>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QFile>
#include <QDir>
#include <QRandomGenerator>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDebug>
#include <QPointer>
#include <QTimer>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <dlfcn.h>
#include <memory>

static const char* GDRIVE_CLIENT_ID = "1072944905499-vm2v2i5dvn0a0d2o4ca36i1vge8cvbn0.apps.googleusercontent.com";
static const char* GDRIVE_CLIENT_SECRET = "v6V3fKV_zWU7iw1DrpO1rknX";
static const char* GDRIVE_TOKEN_URL = "https://oauth2.googleapis.com/token";
static const char* GDRIVE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
static const char* GDRIVE_SCOPE = "https://www.googleapis.com/auth/drive.file";

// OneDrive (using rclone's public client ID)
static const char* ONEDRIVE_CLIENT_ID = "b15665d9-eda6-4092-8539-0eec376afd59";
static const char* ONEDRIVE_CLIENT_SECRET = "qtyfaBBYA403=unZUP40~_#";
static const char* ONEDRIVE_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
static const char* ONEDRIVE_AUTH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
static const char* ONEDRIVE_SCOPE = "Files.ReadWrite offline_access";

// ── libsecret runtime binding (optional, no compile-time dependency) ────

typedef void* GCancellable;
typedef struct _GError { int domain; int code; char* message; } GError;
typedef struct _SecretSchema {
    const char* name;
    int flags;
    struct { const char* name; int type; } attributes[32];
} SecretSchema;

typedef int (*secret_password_store_sync_fn)(const SecretSchema*, const char*, const char*, const char*, GCancellable*, GError**, ...);
typedef void (*g_error_free_fn)(GError*);

static void* g_libsecret = nullptr;
static void* g_libglib = nullptr;
static secret_password_store_sync_fn secret_password_store_sync = nullptr;
static g_error_free_fn g_error_free = nullptr;
static bool g_secretServiceAvailable = false;
static bool g_secretServiceChecked = false;

static SecretSchema g_tokenSchema = {
    "io.github.cloudredirect.Token",
    0, // SECRET_SCHEMA_NONE
    {
        { "provider", 0 }, // SECRET_SCHEMA_ATTRIBUTE_STRING
        { "account", 0 },
        { nullptr, 0 }
    }
};

static void initSecretService() {
    if (g_secretServiceChecked) return;
    g_secretServiceChecked = true;
    
    g_libsecret = dlopen("libsecret-1.so.0", RTLD_NOW | RTLD_LOCAL);
    if (!g_libsecret) {
        qDebug() << "[TokenStorage] libsecret not available:" << dlerror();
        return;
    }
    
    g_libglib = dlopen("libglib-2.0.so.0", RTLD_NOW | RTLD_LOCAL);
    if (!g_libglib) {
        qDebug() << "[TokenStorage] libglib not available:" << dlerror();
        dlclose(g_libsecret);
        g_libsecret = nullptr;
        return;
    }
    
    secret_password_store_sync = (secret_password_store_sync_fn)dlsym(g_libsecret, "secret_password_store_sync");
    g_error_free = (g_error_free_fn)dlsym(g_libglib, "g_error_free");
    
    if (!secret_password_store_sync || !g_error_free) {
        qDebug() << "[TokenStorage] Failed to resolve libsecret symbols";
        dlclose(g_libsecret);
        dlclose(g_libglib);
        g_libsecret = nullptr;
        g_libglib = nullptr;
        return;
    }
    
    g_secretServiceAvailable = true;
    qDebug() << "[TokenStorage] libsecret available, using Secret Service for token storage";
}

static bool storeTokenInSecretService(const QString& provider, const QString& account, const QString& json) {
    initSecretService();
    if (!g_secretServiceAvailable) return false;
    
    GError* error = nullptr;
    QString label = QString("CloudRedirect %1 token").arg(provider);
    
    int ok = secret_password_store_sync(
        &g_tokenSchema, "default", label.toUtf8().constData(), json.toUtf8().constData(),
        nullptr, &error,
        "provider", provider.toUtf8().constData(),
        "account", account.toUtf8().constData(),
        nullptr);
    
    if (error) {
        qDebug() << "[TokenStorage] Secret Service store failed:" << error->message;
        g_error_free(error);
        return false;
    }
    
    return ok != 0;
}

// Extract provider and account from token path
// Path format: ~/.config/CloudRedirect/tokens/{provider}_{account}.json
static bool parseTokenPath(const QString& path, QString& provider, QString& account) {
    QFileInfo fi(path);
    QString basename = fi.baseName(); // e.g., "gdrive_12345678"
    int sep = basename.indexOf('_');
    if (sep < 0) return false;
    provider = basename.left(sep);
    account = basename.mid(sep + 1);
    return !provider.isEmpty() && !account.isEmpty();
}

OAuthService::OAuthService(QObject *parent) : QObject(parent) {}

OAuthService::~OAuthService()
{
    cancel();
}

QString OAuthService::generateRandomString(int length)
{
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    QString result;
    result.reserve(length);
    auto *rng = QRandomGenerator::global();
    for (int i = 0; i < length; i++)
        result.append(charset[rng->bounded(64)]);
    return result;
}

QString OAuthService::computeCodeChallenge(const QString &verifier)
{
    QByteArray hash = QCryptographicHash::hash(verifier.toLatin1(), QCryptographicHash::Sha256);
    return hash.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
}

void OAuthService::startAuth(const QString &provider, const QString &tokenPath)
{
    cancel(); // clean up any previous attempt

    m_provider = provider;
    m_tokenPath = tokenPath;

    // Generate PKCE values (used for Google Drive)
    m_state = generateRandomString(32);
    m_codeVerifier = generateRandomString(64);
    QString codeChallenge = computeCodeChallenge(m_codeVerifier);

    // OneDrive uses rclone's fixed port 53682, Google Drive uses dynamic port
    m_server = new QTcpServer(this);
    
    if (provider == "onedrive") {
        // rclone's Azure AD app only has http://localhost:53682/ registered
        if (!m_server->listen(QHostAddress::LocalHost, 53682)) {
            emit authFailed(provider, "Failed to start local HTTP server on port 53682: " + m_server->errorString());
            delete m_server;
            m_server = nullptr;
            return;
        }
        m_redirectUri = "http://localhost:53682/";
    } else if (provider == "gdrive") {
        // Fixed port for Google Drive, ugh
        if (!m_server->listen(QHostAddress::LocalHost, 53692)) {
            emit authFailed(provider, "Failed to start local HTTP server on port 53692: " + m_server->errorString());
            delete m_server;
            m_server = nullptr;
            return;
        }
        m_redirectUri = "http://localhost:53692/callback";
    } else {
        // Other providers use dynamic port
        if (!m_server->listen(QHostAddress::LocalHost, 0)) {
            emit authFailed(provider, "Failed to start local HTTP server: " + m_server->errorString());
            delete m_server;
            m_server = nullptr;
            return;
        }
        m_redirectUri = QString("http://localhost:%1/callback").arg(m_server->serverPort());
    }
    
    m_port = m_server->serverPort();
    connect(m_server, &QTcpServer::newConnection, this, &OAuthService::onNewConnection);

    emit statusMessage(QString("Listening on %1").arg(m_redirectUri));

    // Build auth URL
    QUrl authUrl;
    QUrlQuery params;

    if (provider == "gdrive") {
        authUrl.setUrl(GDRIVE_AUTH_URL);
        params.addQueryItem("client_id", GDRIVE_CLIENT_ID);
        params.addQueryItem("redirect_uri", m_redirectUri);
        params.addQueryItem("response_type", "code");
        params.addQueryItem("scope", GDRIVE_SCOPE);
        params.addQueryItem("access_type", "offline");
        params.addQueryItem("prompt", "consent");
        params.addQueryItem("state", m_state);
        params.addQueryItem("code_challenge", codeChallenge);
        params.addQueryItem("code_challenge_method", "S256");
    } else if (provider == "onedrive") {
        authUrl.setUrl(ONEDRIVE_AUTH_URL);
        params.addQueryItem("client_id", ONEDRIVE_CLIENT_ID);
        params.addQueryItem("redirect_uri", m_redirectUri);
        params.addQueryItem("response_type", "code");
        params.addQueryItem("scope", ONEDRIVE_SCOPE);
        params.addQueryItem("prompt", "consent");
        params.addQueryItem("state", m_state);
        params.addQueryItem("code_challenge", codeChallenge);
        params.addQueryItem("code_challenge_method", "S256");
    } else {
        emit authFailed(provider, "Unknown provider: " + provider);
        cancel();
        return;
    }

    authUrl.setQuery(params);

    qDebug() << "[OAuth] Auth URL:" << authUrl.toString();
    emit statusMessage("Opening browser for authorization...");
    if (!QDesktopServices::openUrl(authUrl)) {
        qWarning() << "[OAuth] Failed to open browser, emitting URL for manual copy";
        emit browserFailed(authUrl.toString());
    }
}

void OAuthService::onNewConnection()
{
    if (!m_server) return;

    QTcpSocket *socket = m_server->nextPendingConnection();
    if (!socket) return;

    // Use QPointer to safely check if objects are still alive
    QPointer<OAuthService> self(this);
    QPointer<QTcpSocket> socketGuard(socket);
    
    // Timeout for incomplete requests
    QTimer::singleShot(30000, this, [self, socketGuard]() {
        if (!self) return;  // OAuthService was destroyed
        if (socketGuard && socketGuard->state() == QAbstractSocket::ConnectedState) {
            socketGuard->disconnectFromHost();
        }
    });

    auto recvBuf = std::make_shared<QByteArray>();
    connect(socket, &QTcpSocket::readyRead, this, [this, socket, recvBuf, self]() {
        if (!self) return;  // OAuthService was destroyed
        
        *recvBuf += socket->readAll();
        if (!recvBuf->contains("\r\n\r\n")) return; // wait for complete request

        // Disconnect signal to prevent re-entry
        disconnect(socket, &QTcpSocket::readyRead, this, nullptr);

        QString request = QString::fromUtf8(*recvBuf);

        // Expected: "GET /callback?code=XXX&state=YYY HTTP/1.1" (Google)
        // Or:       "GET /?code=XXX HTTP/1.1" (OneDrive via rclone)
        int getEnd = request.indexOf(" HTTP/");
        if (getEnd < 0) {
            socket->close();
            socket->deleteLater();
            return;
        }
        QString path = request.mid(4, getEnd - 4);
        qDebug() << "[OAuth] Received request:" << path;

        // Ignore non-callback requests (favicon, preflight, etc.)
        if (!path.startsWith("/callback") && !path.startsWith("/?")) {
            qDebug() << "[OAuth] Ignoring non-callback request";
            socket->write("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
            socket->flush();
            socket->close();
            socket->deleteLater();
            return;
        }

        QUrl url("http://localhost" + path);
        QUrlQuery query(url.query());
        QString code = query.queryItemValue("code");
        QString state = query.queryItemValue("state");
        QString error = query.queryItemValue("error");

        bool stateValid = (state == m_state);
        qDebug() << "[OAuth] code present:" << !code.isEmpty()
                 << "state valid:" << stateValid
                 << "error:" << error;

        QString html;
        if (!error.isEmpty()) {
            QString safeError = error.toHtmlEscaped();
            html = "<html><body><h2>Authorization Failed</h2><p>" + safeError + "</p><p>You can close this tab.</p></body></html>";
        } else if (code.isEmpty() || !stateValid) {
            html = "<html><body><h2>Error</h2><p>Invalid callback. Please try again.</p></body></html>";
        } else {
            html = "<html><body><h2>Authorization Successful</h2><p>You can close this tab and return to CloudRedirect.</p></body></html>";
        }

        QByteArray response = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n" + html.toUtf8();
        socket->write(response);
        socket->flush();
        socket->close();
        socket->deleteLater();

        // Process result after socket is cleaned up
        if (!error.isEmpty()) {
            emit authFailed(m_provider, "Authorization denied: " + error);
            cancel();
        } else if (code.isEmpty() || !stateValid) {
            emit authFailed(m_provider, "Invalid state or missing code");
            cancel();
        } else {
            emit statusMessage("Authorization code received. Exchanging for tokens...");
            exchangeCodeForTokens(code);
        }
    });
}

void OAuthService::exchangeCodeForTokens(const QString &code, int retryCount)
{
    auto *nam = new QNetworkAccessManager(this);
    QPointer<OAuthService> self(this);

    QUrl tokenUrl;
    QUrlQuery body;

    if (m_provider == "gdrive") {
        tokenUrl.setUrl(GDRIVE_TOKEN_URL);
        body.addQueryItem("code", code);
        body.addQueryItem("client_id", GDRIVE_CLIENT_ID);
        body.addQueryItem("client_secret", GDRIVE_CLIENT_SECRET);
        body.addQueryItem("redirect_uri", m_redirectUri);
        body.addQueryItem("grant_type", "authorization_code");
        body.addQueryItem("code_verifier", m_codeVerifier);
    } else if (m_provider == "onedrive") {
        tokenUrl.setUrl(ONEDRIVE_TOKEN_URL);
        body.addQueryItem("code", code);
        body.addQueryItem("client_id", ONEDRIVE_CLIENT_ID);
        body.addQueryItem("client_secret", ONEDRIVE_CLIENT_SECRET);
        body.addQueryItem("redirect_uri", m_redirectUri);
        body.addQueryItem("grant_type", "authorization_code");
        body.addQueryItem("scope", ONEDRIVE_SCOPE);
        body.addQueryItem("code_verifier", m_codeVerifier);
    }

    QNetworkRequest req(tokenUrl);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");

    QNetworkReply *reply = nam->post(req, body.toString(QUrl::FullyEncoded).replace("%20", "+").toUtf8());

    connect(reply, &QNetworkReply::finished, this, [this, self, reply, nam, code, retryCount]() {
        reply->setParent(nullptr);
        reply->deleteLater();
        nam->deleteLater();

        if (!self) return;

        if (reply->error() != QNetworkReply::NoError) {
            // Retry once -- broken IPv6 fails instantly, retry gives IPv4 a chance
            if (retryCount < 2) {
                qDebug() << "[OAuth] Token exchange failed, retrying:" << reply->errorString();
                emit statusMessage("Retrying token exchange...");
                QTimer::singleShot(500, this, [this, code, retryCount]() {
                    exchangeCodeForTokens(code, retryCount + 1);
                });
                return;
            }
            emit authFailed(m_provider, "Token exchange failed: " + reply->errorString());
            cancel();
            return;
        }

        QByteArray responseData = reply->readAll();
        QJsonDocument doc = QJsonDocument::fromJson(responseData);
        if (!doc.isObject()) {
            emit authFailed(m_provider, "Invalid token response");
            cancel();
            return;
        }

        QJsonObject obj = doc.object();
        QString accessToken = obj.value("access_token").toString();
        QString refreshToken = obj.value("refresh_token").toString();
        qint64 expiresIn = obj.value("expires_in").toInteger(3600);

        if (refreshToken.isEmpty()) {
            emit authFailed(m_provider, "No refresh token received. Try revoking access and re-authenticating.");
            cancel();
            return;
        }

        // Token JSON format must match what the .so expects
        qint64 expiresAt = QDateTime::currentSecsSinceEpoch() + expiresIn;
        QJsonObject tokenObj;
        tokenObj["access_token"] = accessToken;
        tokenObj["refresh_token"] = refreshToken;
        tokenObj["expires_at"] = expiresAt;

        QJsonDocument tokenDoc(tokenObj);
        QByteArray tokenJson = tokenDoc.toJson(QJsonDocument::Indented);

        QString provider, account;
        if (parseTokenPath(m_tokenPath, provider, account)) {
            storeTokenInSecretService(provider, account, QString::fromUtf8(tokenJson));
        }

        // Always write file -- CLI and isProviderAuthenticated both rely on it
        {
            QString dir = QFileInfo(m_tokenPath).absolutePath();
            QDir().mkpath(dir);

            // Atomic write: temp file with 0600 perms, then rename
            QString tempPath = m_tokenPath + ".tmp";
            int fd = open(tempPath.toUtf8().constData(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (fd < 0) {
                emit authFailed(m_provider, "Failed to create token temp file");
                cancel();
                return;
            }
            QByteArray data = tokenJson;
            ssize_t written = 0;
            while (written < data.size()) {
                ssize_t n = ::write(fd, data.constData() + written, data.size() - written);
                if (n < 0) {
                    if (errno == EINTR) continue;
                    ::close(fd);
                    unlink(tempPath.toUtf8().constData());
                    emit authFailed(m_provider, "Failed to write token file");
                    cancel();
                    return;
                }
                written += n;
            }
            ::close(fd);
            if (rename(tempPath.toUtf8().constData(), m_tokenPath.toUtf8().constData()) != 0) {
                unlink(tempPath.toUtf8().constData());
                emit authFailed(m_provider, "Failed to finalize token file");
                cancel();
                return;
            }
        }

        emit statusMessage(QString("Tokens saved. Access token expires in %1s (auto-refresh enabled).").arg(expiresIn));
        emit authSucceeded(m_provider);
        cancel(); // stop listener
    });
}

void OAuthService::cancel()
{
    if (m_server) {
        m_server->close();
        m_server->deleteLater();
        m_server = nullptr;
    }
}

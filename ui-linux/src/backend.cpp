#include "backend.h"
#include "utils.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QDirIterator>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QStandardPaths>
#include <QTextStream>
#include <QProcess>
#include <QDesktopServices>
#include <QUrl>
#include <QUrlQuery>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QTimer>
#include <QDateTime>
#include <QCoreApplication>
#include <QRegularExpression>
#include <QAtomicInt>
#include <QThread>
#include <QVariantMap>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>

// Defined below; used by loadConfig() before its definition.
static bool r2CredentialsValid(const QString &path);
static bool s3CredentialsValid(const QString &path);

static const char* GDRIVE_CLIENT_ID = "1072944905499-vm2v2i5dvn0a0d2o4ca36i1vge8cvbn0.apps.googleusercontent.com";
static const char* GDRIVE_CLIENT_SECRET = "v6V3fKV_zWU7iw1DrpO1rknX";
static const char* ONEDRIVE_CLIENT_ID = "b15665d9-eda6-4092-8539-0eec376afd59";
static const char* ONEDRIVE_CLIENT_SECRET = "qtyfaBBYA403=unZUP40~_#";

static void copyDir(const QString &src, const QString &dst, QJsonArray &undoOps, uint appId)
{
    QDir().mkpath(dst);
    QDirIterator it(src, QDir::Files | QDir::NoDotAndDotDot, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        it.next();
        QString relPath = QDir(src).relativeFilePath(it.filePath());
        QString dstPath = dst + "/" + relPath;
        QDir().mkpath(QFileInfo(dstPath).absolutePath());
        if (!QFile::copy(it.filePath(), dstPath))
            continue;  // Skip failed copies - don't record in undo log

        QJsonObject op;
        op["type"] = "file_copy";
        op["source"] = it.filePath();
        op["dest"] = dstPath;
        op["appId"] = (int)appId;
        undoOps.append(op);
    }
}

static QString backupRootForAccount(const QString &accountId)
{
    return QDir::cleanPath(crConfigDir() + "/backups/" + accountId);
}

static bool isPathWithin(const QString &root, const QString &path)
{
    QString cleanRoot = QDir::cleanPath(root);
    QString cleanPath = QDir::cleanPath(path);
    return cleanPath == cleanRoot || cleanPath.startsWith(cleanRoot + "/");
}

// Internal Steam app IDs that should not be shown in the UI
static const QSet<uint> kHiddenAppIds = { 7, 760, 2371090 };

static QString flatpakRepoDescriptorPath()
{
    return "/app/share/cloud_redirect/cloudredirect.flatpakrepo";
}

static bool flatpakRepoDescriptorHasGpgKey()
{
    QFile f(flatpakRepoDescriptorPath());
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return false;
    QString repo = f.readAll();
    return repo.contains(QRegularExpression("^GPGKey=\\S", QRegularExpression::MultilineOption));
}

Backend::Backend(QObject *parent)
    : QObject(parent), m_nam(new QNetworkAccessManager(this))
{
    detectSteamPath();
    scanStorageForApps();  // Primary source: what's actually synced
    loadConfig();
    
    // Delay name resolution and remote fetch until event loop is running
    QTimer::singleShot(100, this, &Backend::resolveAppNames);
    QTimer::singleShot(200, this, &Backend::fetchRemoteApps);
}

void Backend::detectSteamPath()
{
    QString home = realHomePath();

    QString path = home + "/.local/share/Steam";
    if (QDir(path).exists()) {
        m_steamPath = path;
    } else {
        path = home + "/.var/app/com.valvesoftware.Steam/.local/share/Steam";
        if (QDir(path).exists())
            m_steamPath = path;
        else
            m_steamPath = home + "/.steam/steam";
    }

    m_storagePath = crConfigDir() + "/storage";

    m_deployed = false;
    QString crPath = crDataDir() + "/cloud_redirect.so";
    m_deployed = QFile::exists(crPath);

    // Parse account ID from loginusers.vdf (MostRecent > AutoLogin > Timestamp)
    QString loginUsersPath = m_steamPath + "/config/loginusers.vdf";
    QFile f(loginUsersPath);
    if (f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QString content = f.readAll();
        f.close();

        QStringList lines = content.split('\n');
        QString currentId;
        QString currentPersonaName;
        bool inUser = false;
        int depth = 0;

        quint64 bestTsSid = 0, bestTs = 0;
        QString bestTsPersona;

        for (const auto &line : lines) {
            QString trimmed = line.trimmed();
            if (trimmed == "{") { depth++; continue; }
            if (trimmed == "}") { depth--; if (depth == 1) inUser = false; continue; }

            if (depth == 1 && trimmed.startsWith('"')) {
                int end = trimmed.indexOf('"', 1);
                if (end > 1) {
                    QString key = trimmed.mid(1, end - 1);
                    bool ok;
                    quint64 sid = key.toULongLong(&ok);
                    if (ok && sid > 76561197960265728ULL) {
                        currentId = key;
                        currentPersonaName.clear();
                        inUser = true;
                    }
                }
            }

            if (inUser && depth == 2) {
                if (trimmed.contains("\"PersonaName\"")) {
                    int keyEndQuote = trimmed.indexOf('"', trimmed.indexOf('"') + 1);
                    int valStart = trimmed.indexOf('"', keyEndQuote + 1);
                    if (valStart > 0) {
                        int valEnd = trimmed.indexOf('"', valStart + 1);
                        if (valEnd > valStart) {
                            currentPersonaName = trimmed.mid(valStart + 1, valEnd - valStart - 1);
                        }
                    }
                }
                if (trimmed.contains("\"MostRecent\"") && trimmed.contains("\"1\"")) {
                    quint64 sid = currentId.toULongLong();
                    m_accountId = QString::number(sid & 0xFFFFFFFF);
                    m_accountName = currentPersonaName;
                }
                if (m_accountId.isEmpty() && trimmed.contains("\"AutoLogin\"") && trimmed.contains("\"1\"")) {
                    quint64 sid = currentId.toULongLong();
                    m_accountId = QString::number(sid & 0xFFFFFFFF);
                    m_accountName = currentPersonaName;
                }
                if (m_accountId.isEmpty() && trimmed.contains("\"Timestamp\"")) {
                    static const QString kTimestamp = "\"Timestamp\"";
                    int vStart = trimmed.indexOf('"', trimmed.indexOf(kTimestamp) + kTimestamp.length());
                    if (vStart > 0) {
                        int vEnd = trimmed.indexOf('"', vStart + 1);
                        if (vEnd > vStart) {
                            quint64 ts = trimmed.mid(vStart + 1, vEnd - vStart - 1).toULongLong();
                            if (ts > bestTs) {
                                bestTs = ts;
                                bestTsSid = currentId.toULongLong();
                                bestTsPersona = currentPersonaName;
                            }
                        }
                    }
                }
            }
        }

        // Last resort: use the user with the highest Timestamp
        if (m_accountId.isEmpty() && bestTsSid != 0) {
            m_accountId = QString::number(bestTsSid & 0xFFFFFFFF);
            m_accountName = bestTsPersona;
        }
    }
}

QString Backend::getAccountId() const { return m_accountId; }

void Backend::scanStorageForApps()
{
    m_apps.clear();
    
    if (m_accountId.isEmpty() || m_storagePath.isEmpty()) return;

    QString accountDir = m_storagePath + "/" + m_accountId;
    QDir dir(accountDir);
    if (!dir.exists()) return;

    static const QSet<QString> metadataFiles = {"cn.dat", "root_token.dat", "file_tokens.dat", "deleted.dat"};

    QStringList appDirs = dir.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
    for (const auto &appIdStr : appDirs) {
        bool ok;
        uint appId = appIdStr.toUInt(&ok);
        if (!ok || appId == 0) continue;
        if (kHiddenAppIds.contains(appId)) continue;

        QString appDir = accountDir + "/" + appIdStr;
        
        // Read save root from root_token.dat
        QString saveRoot;
        QFile rootTokenFile(appDir + "/root_token.dat");
        if (rootTokenFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
            saveRoot = QString::fromUtf8(rootTokenFile.readAll()).trimmed();
            rootTokenFile.close();
        }
        
        // Count files and compute size (skip metadata)
        QDirIterator it(appDir, QDir::Files, QDirIterator::Subdirectories);
        int count = 0;
        qint64 size = 0;
        while (it.hasNext()) {
            it.next();
            QString fileName = it.fileName();
            if (metadataFiles.contains(fileName)) continue;
            count++;
            size += it.fileInfo().size();
        }

        QString name = m_nameCache.value(appId, QString("App %1").arg(appId));
        m_apps.append({appId, name, QString(), saveRoot, count, size, true, false});
    }

    emit appsChanged();
}

void Backend::loadSLSsteamApps()
{
    m_apps.clear();
    QString home = realHomePath();

    QStringList configPaths = {
        xdgConfigHome() + "/SLSsteam/config.yaml",
        home + "/.var/app/com.valvesoftware.Steam/.config/SLSsteam/config.yaml",
    };

    for (const auto &configPath : configPaths) {
        QFile f(configPath);
        if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
            continue;

        QTextStream in(&f);
        bool inAdditionalApps = false;

        while (!in.atEnd()) {
            QString line = in.readLine();
            QString trimmed = line.trimmed();

            if (!line.startsWith(' ') && !line.startsWith('\t') && !trimmed.startsWith('-')) {
                if (inAdditionalApps) break;
                if (trimmed.startsWith("AdditionalApps")) {
                    inAdditionalApps = true;
                    continue;
                }
            }

            if (inAdditionalApps && trimmed.startsWith("- ")) {
                QString numStr = trimmed.mid(2).trimmed();
                int commentIdx = numStr.indexOf('#');
                if (commentIdx >= 0) numStr = numStr.left(commentIdx).trimmed();

                bool ok;
                uint appId = numStr.toUInt(&ok);
                if (ok && appId > 0) {
                    QString name = m_nameCache.value(appId, QString("App %1").arg(appId));
                    m_apps.append({appId, name, QString(), QString(), 0, 0, true, false});
                }
            }
        }
        f.close();

        if (!m_apps.isEmpty()) break;
    }

    emit appsChanged();
}

void Backend::loadConfig()
{
    QString configPath = crConfigDir() + "/config.json";
    fprintf(stderr, "[Backend] loadConfig from: %s\n", configPath.toUtf8().constData());
    QFile f(configPath);
    if (!f.open(QIODevice::ReadOnly)) {
        fprintf(stderr, "[Backend] loadConfig: file not found or cannot open\n");
        return;
    }

    QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    f.close();
    if (!doc.isObject()) {
        fprintf(stderr, "[Backend] loadConfig: invalid JSON\n");
        return;
    }

    QJsonObject obj = doc.object();
    m_providerName = obj.value("provider").toString("local");
    m_syncFolderPath = obj.value("sync_folder_path").toString();
    m_notificationsEnabled = obj.value("notifications_enabled").toBool(true);
    m_statsSyncEnabled = obj.value("stats_sync_enabled").toBool(true);

    m_syncPlaytime = obj.value("sync_playtime").toBool(false);
    fprintf(stderr, "[Backend] loadConfig: provider=%s syncFolder=%s notifications=%s\n",
        m_providerName.toUtf8().constData(), m_syncFolderPath.toUtf8().constData(),
        m_notificationsEnabled ? "true" : "false");

    m_providerAuthenticated = false;
    if (m_providerName == "gdrive" || m_providerName == "onedrive") {
        QString tokenPath = defaultTokenPath(m_providerName);
        if (QFile::exists(tokenPath)) {
            m_providerAuthenticated = true;
        }
    } else if (m_providerName == "r2") {
        m_providerAuthenticated = r2CredentialsValid(r2CredentialPath());
    } else if (m_providerName == "s3") {
        m_providerAuthenticated = s3CredentialsValid(s3CredentialPath());
    } else if (m_providerName == "folder" && !m_syncFolderPath.isEmpty()) {
        m_providerAuthenticated = QDir(m_syncFolderPath).exists();
    }

    // Load store cache (names and header URLs)
    QString cachePath = crConfigDir() + "/store_cache.json";
    QFile cacheFile(cachePath);
    if (cacheFile.open(QIODevice::ReadOnly)) {
        QJsonDocument cacheDoc = QJsonDocument::fromJson(cacheFile.readAll());
        cacheFile.close();
        if (cacheDoc.isObject()) {
            QJsonObject cacheObj = cacheDoc.object();
            for (auto it = cacheObj.begin(); it != cacheObj.end(); ++it) {
                uint appId = it.key().toUInt();
                QJsonObject entry = it.value().toObject();
                QString name = entry["name"].toString();
                QString headerUrl = entry["headerUrl"].toString();
                if (!name.isEmpty()) {
                    m_nameCache[appId] = name;
                }
                if (!headerUrl.isEmpty()) {
                    m_headerCache[appId] = headerUrl;
                }
            }
        }
    }

    // Apply cached names and headers to apps
    for (auto &app : m_apps) {
        if (m_nameCache.contains(app.appId))
            app.name = m_nameCache[app.appId];
        if (m_headerCache.contains(app.appId))
            app.headerUrl = m_headerCache[app.appId];
    }

    emit settingsChanged();
}

void Backend::saveConfig()
{
    QString configDir = crConfigDir();
    QDir().mkpath(configDir);

    QString configPath = configDir + "/config.json";
    
    // Read existing config to preserve keys not managed by this function
    QJsonObject obj;
    QFile existing(configPath);
    if (existing.open(QIODevice::ReadOnly)) {
        QJsonDocument doc = QJsonDocument::fromJson(existing.readAll());
        existing.close();
        if (doc.isObject())
            obj = doc.object();
    }
    
    obj["provider"] = m_providerName;
    obj["sync_folder_path"] = m_syncFolderPath;
    obj["notifications_enabled"] = m_notificationsEnabled;
    obj["stats_sync_enabled"] = m_statsSyncEnabled;

    obj["sync_playtime"] = m_syncPlaytime;

    // Atomic write: write to temp, then rename
    QString tempPath = configPath + ".tmp";
    QFile f(tempPath);
    if (f.open(QIODevice::WriteOnly)) {
        f.write(QJsonDocument(obj).toJson());
        f.close();
        // rename() is atomic on POSIX if same filesystem; fallback to copy+delete
        if (!QFile::rename(tempPath, configPath)) {
            QFile::remove(configPath);
            if (!QFile::rename(tempPath, configPath)) {
                QFile::copy(tempPath, configPath);
                QFile::remove(tempPath);
            }
        }
    }

    emit settingsChanged();
}

int Backend::managedAppCount() const {
    int count = 0;
    for (const auto &app : m_apps) {
        if (app.isLocal && !app.name.contains("Soundtrack", Qt::CaseInsensitive))
            count++;
    }
    return count;
}
QString Backend::steamPath() const { return m_steamPath; }
QString Backend::storagePath() const { return m_storagePath; }
bool Backend::isDeployed() const { return m_deployed; }

QString Backend::providerName() const { return m_providerName; }
void Backend::setProviderName(const QString &name) { 
    m_providerName = name; 
    saveConfig();
}
QString Backend::providerPath() const { return m_providerPath; }
void Backend::setProviderPath(const QString &path) { m_providerPath = path; emit settingsChanged(); }
QString Backend::syncFolderPath() const { return m_syncFolderPath; }
void Backend::setSyncFolderPath(const QString &path) { 
    m_syncFolderPath = path; 
    saveConfig();
}
bool Backend::providerAuthenticated() const { return m_providerAuthenticated; }

bool Backend::notificationsEnabled() const { return m_notificationsEnabled; }
void Backend::setNotificationsEnabled(bool enabled)
{
    if (m_notificationsEnabled == enabled) return;
    m_notificationsEnabled = enabled;
    saveConfig();
}

bool Backend::statsSyncEnabled() const { return m_statsSyncEnabled; }
void Backend::setStatsSyncEnabled(bool enabled)
{
    if (m_statsSyncEnabled == enabled) return;
    m_statsSyncEnabled = enabled;
    saveConfig();
    emit settingsChanged();
}


bool Backend::syncPlaytime() const { return m_syncPlaytime; }
void Backend::setSyncPlaytime(bool enabled)
{
    if (m_syncPlaytime == enabled) return;
    m_syncPlaytime = enabled;
    saveConfig();
}

QVariantList Backend::getManagedApps()
{
    QVariantList list;
    for (const auto &app : m_apps) {
        QVariantMap m;
        m["appId"] = app.appId;
        m["name"] = app.name;
        list.append(m);
    }
    return list;
}

QVariantList Backend::getAppDetails()
{
    QVariantList list;
    for (const auto &app : m_apps) {
        // Skip soundtrack apps - they don't have save data to manage
        if (app.name.contains("Soundtrack", Qt::CaseInsensitive)) continue;
        
        QVariantMap m;
        m["appId"] = app.appId;
        m["name"] = app.name;
        m["fileCount"] = app.fileCount;
        m["totalSize"] = app.totalSize;
        m["sizeFormatted"] = formatSize(app.totalSize);
        m["saveRoot"] = app.saveRoot;
        m["isLocal"] = app.isLocal;
        m["isRemote"] = app.isRemote;
        if (!app.headerUrl.isEmpty()) {
            m["headerUrl"] = app.headerUrl;
        } else if (m_headerCache.contains(app.appId)) {
            m["headerUrl"] = m_headerCache[app.appId];
        } else {
            m["headerUrl"] = QString("https://shared.steamstatic.com/store_item_assets/steam/apps/%1/header.jpg").arg(app.appId);
        }
        list.append(m);
    }
    return list;
}

void Backend::deleteAppData(uint appId)
{
    if (m_accountId.isEmpty()) return;

    QString appDir = m_storagePath + "/" + m_accountId + "/" + QString::number(appId);
    QString userdataDir = m_steamPath + "/userdata/" + m_accountId + "/" + QString::number(appId);
    QString backupRoot = crConfigDir() + "/backups/" + m_accountId;
    QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss");
    QString backupDir = backupRoot + "/" + QString::number(appId) + "_" + timestamp;

    QJsonArray undoOps;

    // Count source files to verify backup completeness
    int sourceFileCount = 0;
    if (QDir(appDir).exists()) {
        QDirIterator counter(appDir, QDir::Files | QDir::NoDotAndDotDot, QDirIterator::Subdirectories);
        while (counter.hasNext()) { counter.next(); sourceFileCount++; }
    }
    if (QDir(userdataDir).exists()) {
        QDirIterator counter(userdataDir, QDir::Files | QDir::NoDotAndDotDot, QDirIterator::Subdirectories);
        while (counter.hasNext()) { counter.next(); sourceFileCount++; }
    }

    if (QDir(appDir).exists()) {
        QDir().mkpath(backupDir);
        copyDir(appDir, backupDir + "/storage", undoOps, appId);
    }

    if (QDir(userdataDir).exists()) {
        QDir().mkpath(backupDir);
        copyDir(userdataDir, backupDir + "/userdata", undoOps, appId);
    }

    QJsonObject undoLog;
    undoLog["version"] = 1;
    undoLog["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    undoLog["appId"] = (int)appId;
    undoLog["accountId"] = m_accountId;
    undoLog["operations"] = undoOps;

    QFile undoFile(backupDir + "/undo_log.json");
    if (undoFile.open(QIODevice::WriteOnly)) {
        undoFile.write(QJsonDocument(undoLog).toJson());
        undoFile.close();
    }

    // Verify backup completeness before destroying originals
    if (sourceFileCount > 0 && undoOps.size() < sourceFileCount) {
        fprintf(stderr, "[Backend] Backup incomplete (%d/%d files) for app %u, aborting delete\n",
                undoOps.size(), sourceFileCount, appId);
        return;
    }

    QDir dir(appDir);
    if (dir.exists()) {
        dir.removeRecursively();
    }

    QDir udDir(userdataDir);
    if (udDir.exists()) {
        udDir.removeRecursively();
    }

    deleteCloudAppData(appId);

    m_apps.erase(std::remove_if(m_apps.begin(), m_apps.end(),
        [appId](const AppInfo &a) { return a.appId == appId; }), m_apps.end());

    emit appsChanged();
}

void Backend::resolveAppNames()
{
    QStringList ids;
    for (const auto &app : m_apps) {
        if (app.name.startsWith("App ") && !m_nameCache.contains(app.appId))
            ids.append(QString::number(app.appId));
    }
    
    if (ids.isEmpty()) {
        emit appNamesResolved();
        return;
    }

    // IStoreBrowseService/GetItems request
    QJsonArray idsArray;
    for (const auto &id : ids) {
        QJsonObject idObj;
        idObj["appid"] = id.toInt();
        idsArray.append(idObj);
    }
    
    QJsonObject contextObj;
    contextObj["language"] = "english";
    contextObj["country_code"] = "US";
    
    QJsonObject dataRequestObj;
    dataRequestObj["include_basic_info"] = true;
    dataRequestObj["include_assets"] = true;
    
    QJsonObject requestObj;
    requestObj["ids"] = idsArray;
    requestObj["context"] = contextObj;
    requestObj["data_request"] = dataRequestObj;
    
    QString inputJson = QString::fromUtf8(QJsonDocument(requestObj).toJson(QJsonDocument::Compact));
    QString encodedJson = QUrl::toPercentEncoding(inputJson);
    QString url = "https://api.steampowered.com/IStoreBrowseService/GetItems/v1?input_json=" + encodedJson;

    QNetworkRequest req{QUrl{url}};
    QNetworkReply *reply = m_nam->get(req);

    connect(reply, &QNetworkReply::finished, this, [this, reply, ids]() {
        reply->deleteLater();
        
        if (reply->error() != QNetworkReply::NoError) {
            emit appNamesResolved();
            return;
        }

        QByteArray data = reply->readAll();
        QJsonDocument doc = QJsonDocument::fromJson(data);
        QJsonObject root = doc.object();
        QJsonObject response = root["response"].toObject();
        QJsonArray storeItems = response["store_items"].toArray();

        for (const auto &item : storeItems) {
            QJsonObject itemObj = item.toObject();
            uint appId = itemObj["appid"].toInteger();
            QString name = itemObj["name"].toString();
            
            // Parse header URL from assets.header (can be "header.jpg" or "{hash}/header.jpg")
            QString headerUrl;
            QJsonObject assets = itemObj["assets"].toObject();
            QString header = assets["header"].toString();
            if (!header.isEmpty()) {
                headerUrl = QString("https://shared.steamstatic.com/store_item_assets/steam/apps/%1/%2").arg(appId).arg(header);
            }
            
            if (appId > 0 && !name.isEmpty()) {
                m_nameCache[appId] = name;
                if (!headerUrl.isEmpty()) {
                    m_headerCache[appId] = headerUrl;
                }
                for (auto &app : m_apps) {
                    if (app.appId == appId) {
                        app.name = name;
                        if (!headerUrl.isEmpty()) {
                            app.headerUrl = headerUrl;
                        }
                    }
                }
            }
        }

        // Save cache
        QString cachePath = crConfigDir() + "/store_cache.json";
        QJsonObject cacheObj;
        for (auto it = m_nameCache.begin(); it != m_nameCache.end(); ++it) {
            QJsonObject entry;
            entry["name"] = it.value();
            if (m_headerCache.contains(it.key())) {
                entry["headerUrl"] = m_headerCache[it.key()];
            }
            cacheObj[QString::number(it.key())] = entry;
        }

        QFile f(cachePath);
        if (f.open(QIODevice::WriteOnly)) {
            f.write(QJsonDocument(cacheObj).toJson());
            f.close();
        }

        emit appNamesResolved();
        emit appsChanged();
    });
}

void Backend::refreshStatus()
{
    detectSteamPath();
    scanStorageForApps();  // Primary source: what's actually synced
    loadConfig();
    QTimer::singleShot(0, this, &Backend::resolveAppNames);
    emit statusChanged();
}

QString Backend::defaultTokenPath(const QString &provider) const
{
    return crConfigDir() + "/tokens_" + provider + ".json";
}

void Backend::startOAuth(const QString &provider)
{
    QString tokenPath = m_providerPath;
    if (tokenPath.isEmpty()) {
        tokenPath = defaultTokenPath(provider);
        m_providerPath = tokenPath;
    }
    emit settingsChanged();
}

void Backend::openLogFile()
{
    QString logPath = crConfigDir() + "/cloud_redirect.log";
    if (QFile::exists(logPath)) {
        QDesktopServices::openUrl(QUrl::fromLocalFile(logPath));
    }
}

void Backend::openConfigFolder()
{
    QString configPath = crConfigDir();
    QDir().mkpath(configPath);
    QDesktopServices::openUrl(QUrl::fromLocalFile(configPath));
}

QVariantList Backend::scanOrphans()
{
    QVariantList results;
    if (m_accountId.isEmpty()) return results;

    QString accountDir = m_storagePath + "/" + m_accountId;
    QDir dir(accountDir);
    if (!dir.exists()) return results;

    // Internal metadata files that are never orphans
    static const QSet<QString> whitelist = {
        ".cloudredirect/Playtime.bin",
        ".cloudredirect/UserGameStats.bin",
        "Playtime.bin",
        "UserGameStats.bin",
    };

    QStringList appDirs = dir.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
    for (const auto &appIdStr : appDirs) {
        bool ok;
        uint appId = appIdStr.toUInt(&ok);
        if (!ok || appId == 0) continue;

        QString appDir = accountDir + "/" + appIdStr;

        // Read file_tokens.dat to get referenced filenames
        QSet<QString> referenced;
        QFile tokensFile(appDir + "/file_tokens.dat");
        if (tokensFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QTextStream in(&tokensFile);
            while (!in.atEnd()) {
                QString line = in.readLine();
                int tabIdx = line.indexOf('\t');
                if (tabIdx > 0) {
                    referenced.insert(line.left(tabIdx));
                }
            }
            tokensFile.close();
        }

        // List actual blob files
        QString blobDir = appDir + "/blobs";
        QDir blobQDir(blobDir);
        if (!blobQDir.exists()) continue;

        QStringList blobFiles = blobQDir.entryList(QDir::Files);
        QStringList orphans;
        qint64 orphanSize = 0;

        for (const auto &blob : blobFiles) {
            if (whitelist.contains(blob)) continue;
            if (!referenced.contains(blob)) {
                orphans.append(blob);
                QFileInfo fi(blobDir + "/" + blob);
                orphanSize += fi.size();
            }
        }

        if (!orphans.isEmpty()) {
            QVariantMap entry;
            entry["appId"] = appId;
            entry["name"] = m_nameCache.value(appId, QString("App %1").arg(appId));
            entry["orphanCount"] = orphans.size();
            entry["orphanSize"] = orphanSize;
            entry["orphanSizeFormatted"] = formatSize(orphanSize);
            results.append(entry);
        }
    }

    return results;
}

QString Backend::formatSize(qint64 bytes) const
{
    if (bytes < 1024) return QString::number(bytes) + " B";
    if (bytes < 1024 * 1024) return QString::number(bytes / 1024.0, 'f', 1) + " KB";
    if (bytes < 1024LL * 1024 * 1024) return QString::number(bytes / (1024.0 * 1024.0), 'f', 1) + " MB";
    return QString::number(bytes / (1024.0 * 1024.0 * 1024.0), 'f', 2) + " GB";
}

QString Backend::accountId() const { return m_accountId; }
QString Backend::accountName() const { return m_accountName; }

#ifndef CR_VERSION
#define CR_VERSION "2.0.5"
#endif
QString Backend::version() const { return QStringLiteral(CR_VERSION); }

int Backend::remoteOnlyAppCount() const {
    int count = 0;
    for (const auto &app : m_apps) {
        if (app.isRemote && !app.isLocal && !app.name.contains("Soundtrack", Qt::CaseInsensitive))
            count++;
    }
    return count;
}

QString Backend::readAccessToken() const
{
    QString tokenPath;
    if (m_providerName == "gdrive") {
        tokenPath = m_providerPath.isEmpty() ? defaultTokenPath("gdrive") : m_providerPath;
    } else if (m_providerName == "onedrive") {
        tokenPath = m_providerPath.isEmpty() ? defaultTokenPath("onedrive") : m_providerPath;
    } else {
        return QString();
    }
    
    QFile f(tokenPath);
    if (!f.open(QIODevice::ReadOnly)) return QString();
    
    QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    f.close();
    QJsonObject obj = doc.object();
    
    // Check if token is expired and refresh if needed
    qint64 expiresAt = obj.value("expires_at").toInteger(0);
    if (expiresAt > 0 && QDateTime::currentSecsSinceEpoch() >= expiresAt - 60) {
        // Thread-safe re-entrancy guard
        static QAtomicInt s_refreshing{0};
        if (!s_refreshing.testAndSetAcquire(0, 1)) return QString();
        struct RefreshGuard {
            QAtomicInt& flag;
            RefreshGuard(QAtomicInt& f) : flag(f) {}
            ~RefreshGuard() { flag.storeRelease(0); }
        } guard(s_refreshing);
        
        QString refreshToken = obj.value("refresh_token").toString();
        if (refreshToken.isEmpty()) return QString();
        
        // Synchronous refresh with reduced timeout
        QNetworkAccessManager nam;
        QUrlQuery body;
        body.addQueryItem("client_id", m_providerName == "onedrive" ? ONEDRIVE_CLIENT_ID : GDRIVE_CLIENT_ID);
        body.addQueryItem("client_secret", m_providerName == "onedrive" ? ONEDRIVE_CLIENT_SECRET : GDRIVE_CLIENT_SECRET);
        body.addQueryItem("refresh_token", refreshToken);
        body.addQueryItem("grant_type", "refresh_token");
        if (m_providerName == "onedrive")
            body.addQueryItem("scope", "Files.ReadWrite offline_access");
        
        QNetworkRequest req(QUrl(m_providerName == "onedrive"
            ? "https://login.microsoftonline.com/common/oauth2/v2.0/token"
            : "https://oauth2.googleapis.com/token"));
        req.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
        
        // Retry up to 2 times (broken IPv6 fails instantly, retry gives IPv4 a chance)
        QNetworkReply *reply = nullptr;
        for (int attempt = 0; attempt < 3; ++attempt) {
            QEventLoop loop;
            QTimer timeout;
            timeout.setSingleShot(true);
            reply = nam.post(req, body.toString(QUrl::FullyEncoded).toUtf8());
            QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
            QObject::connect(&timeout, &QTimer::timeout, reply, &QNetworkReply::abort);
            timeout.start(10000);
            loop.exec();
            if (reply->error() == QNetworkReply::NoError) break;
            reply->deleteLater();
            reply = nullptr;
            if (attempt < 2) QThread::msleep(500);
        }
        
        if (reply && reply->error() == QNetworkReply::NoError) {
            QJsonDocument respDoc = QJsonDocument::fromJson(reply->readAll());
            QJsonObject respObj = respDoc.object();
            QString newToken = respObj.value("access_token").toString();
            qint64 newExpiry = QDateTime::currentSecsSinceEpoch() + respObj.value("expires_in").toInteger(3600);
            
            if (!newToken.isEmpty()) {
                // Update token file atomically
                obj["access_token"] = newToken;
                obj["expires_at"] = newExpiry;
                QString tempPath = tokenPath + ".tmp";
                QFile wf(tempPath);
                if (wf.open(QIODevice::WriteOnly)) {
                    wf.write(QJsonDocument(obj).toJson());
                    wf.close();
                    if (!QFile::rename(tempPath, tokenPath)) {
                        QFile::remove(tokenPath);
                        if (!QFile::rename(tempPath, tokenPath)) {
                            QFile::copy(tempPath, tokenPath);
                            QFile::remove(tempPath);
                        }
                    }
                }
                reply->deleteLater();
                return newToken;
            }
        }
        if (reply) reply->deleteLater();
        return QString();
    }
    
    return obj.value("access_token").toString();
}

void Backend::fetchRemoteApps()
{
    if (m_accountId.isEmpty()) {
        return;
    }
    if (m_providerName != "gdrive" && m_providerName != "onedrive") {
        fprintf(stderr, "[Backend] provider is not gdrive/onedrive, skipping\n");
        emit remoteAppsFetched();
        return;
    }
    
    QString token = readAccessToken();
    if (token.isEmpty()) {
        fprintf(stderr, "[Backend] No valid access token for remote listing\n");
        emit remoteAppsFetched();
        return;
    }

    if (m_providerName == "gdrive")
        fetchGoogleDriveApps(token);
    else
        fetchOneDriveApps(token);
}

void Backend::refreshAndFetch()
{
    fetchRemoteApps();
}

void Backend::fetchGoogleDriveApps(const QString &token)
{
    // Step 1: Find "CloudRedirect" folder in Drive root
    QString query = QString("name='CloudRedirect' and mimeType='application/vnd.google-apps.folder' and trashed=false");
    QUrl url("https://www.googleapis.com/drive/v3/files");
    QUrlQuery params;
    params.addQueryItem("q", query);
    params.addQueryItem("fields", "files(id)");
    params.addQueryItem("spaces", "drive");
    url.setQuery(params);

    QNetworkRequest req(url);
    req.setRawHeader("Authorization", ("Bearer " + token).toUtf8());

    auto *reply = m_nam->get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply, token]() {
        reply->deleteLater();
        if (reply->error() != QNetworkReply::NoError) {
            fprintf(stderr, "[Backend] GDrive: failed to find root folder: %s\n",
                    reply->errorString().toUtf8().constData());
            emit remoteAppsFetched();
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray files = doc.object().value("files").toArray();
        if (files.isEmpty()) {
            fprintf(stderr, "[Backend] GDrive: CloudRedirect folder not found\n");
            emit remoteAppsFetched();
            return;
        }

        QString rootFolderId = files[0].toObject().value("id").toString();
        
        // Step 2: Find account folder inside CloudRedirect
        QString query2 = QString("name='%1' and '%2' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false")
            .arg(m_accountId, rootFolderId);
        QUrl url2("https://www.googleapis.com/drive/v3/files");
        QUrlQuery params2;
        params2.addQueryItem("q", query2);
        params2.addQueryItem("fields", "files(id)");
        url2.setQuery(params2);

        QNetworkRequest req2(url2);
        req2.setRawHeader("Authorization", ("Bearer " + token).toUtf8());

        auto *reply2 = m_nam->get(req2);
        connect(reply2, &QNetworkReply::finished, this, [this, reply2, token, rootFolderId]() {
            reply2->deleteLater();
            if (reply2->error() != QNetworkReply::NoError) {
                fprintf(stderr, "[Backend] GDrive: failed to find account folder\n");
                emit remoteAppsFetched();
                return;
            }

            QJsonDocument doc2 = QJsonDocument::fromJson(reply2->readAll());
            QJsonArray files2 = doc2.object().value("files").toArray();
            if (files2.isEmpty()) {
                fprintf(stderr, "[Backend] GDrive: account folder not found\n");
                emit remoteAppsFetched();
                return;
            }

            QString accountFolderId = files2[0].toObject().value("id").toString();

            // Step 3: List app folders inside account folder
            QString query3 = QString("'%1' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false")
                .arg(accountFolderId);
            QUrl url3("https://www.googleapis.com/drive/v3/files");
            QUrlQuery params3;
            params3.addQueryItem("q", query3);
            params3.addQueryItem("fields", "files(name)");
            params3.addQueryItem("pageSize", "1000");
            url3.setQuery(params3);

            QNetworkRequest req3(url3);
            req3.setRawHeader("Authorization", ("Bearer " + token).toUtf8());

            auto *reply3 = m_nam->get(req3);
            connect(reply3, &QNetworkReply::finished, this, [this, reply3]() {
                reply3->deleteLater();
                if (reply3->error() != QNetworkReply::NoError) {
                    fprintf(stderr, "[Backend] GDrive: failed to list app folders\n");
                    emit remoteAppsFetched();
                    return;
                }

                QJsonDocument doc3 = QJsonDocument::fromJson(reply3->readAll());
                QJsonArray appFolders = doc3.object().value("files").toArray();

                m_remoteAppIds.clear();
                for (const auto &val : appFolders) {
                    QString name = val.toObject().value("name").toString();
                    bool ok;
                    uint appId = name.toUInt(&ok);
                    if (ok && appId > 0 && !kHiddenAppIds.contains(appId)) {
                        m_remoteAppIds.insert(appId);
                    }
                }

                // Merge with local apps
                QSet<uint32_t> localAppIds;
                for (auto &app : m_apps) {
                    localAppIds.insert(app.appId);
                    if (m_remoteAppIds.contains(app.appId)) {
                        app.isRemote = true;
                    }
                }

                // Add remote-only apps
                for (uint32_t appId : m_remoteAppIds) {
                    if (!localAppIds.contains(appId)) {
                        QString name = m_nameCache.value(appId, QString("App %1").arg(appId));
                        m_apps.append({appId, name, QString(), QString(), 0, 0, false, true});
                    }
                }

                fprintf(stderr, "[Backend] Remote apps: %d remote IDs, %d total apps\n",
                        (int)m_remoteAppIds.size(), (int)m_apps.size());
                emit appsChanged();
                emit remoteAppsFetched();
                QTimer::singleShot(0, this, &Backend::resolveAppNames);
            });
        });
    });
}

void Backend::fetchOneDriveApps(const QString &token)
{
    QUrl url(QString("https://graph.microsoft.com/v1.0/me/drive/root:/CloudRedirect/%1:/children")
        .arg(m_accountId));
    QUrlQuery params;
    params.addQueryItem("$select", "name,folder");
    url.setQuery(params);

    QNetworkRequest req(url);
    req.setRawHeader("Authorization", ("Bearer " + token).toUtf8());

    auto *reply = m_nam->get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        if (reply->error() != QNetworkReply::NoError) {
            fprintf(stderr, "[Backend] OneDrive: failed to list account folder: %s\n",
                    reply->errorString().toUtf8().constData());
            emit remoteAppsFetched();
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray items = doc.object().value("value").toArray();
        m_remoteAppIds.clear();
        for (const auto &val : items) {
            QJsonObject item = val.toObject();
            if (!item.contains("folder")) continue;
            QString name = item.value("name").toString();
            bool ok;
            uint appId = name.toUInt(&ok);
            if (ok && appId > 0 && !kHiddenAppIds.contains(appId))
                m_remoteAppIds.insert(appId);
        }

        QSet<uint32_t> localAppIds;
        for (auto &app : m_apps) {
            localAppIds.insert(app.appId);
            if (m_remoteAppIds.contains(app.appId))
                app.isRemote = true;
        }
        for (uint32_t appId : m_remoteAppIds) {
            if (!localAppIds.contains(appId)) {
                QString name = m_nameCache.value(appId, QString("App %1").arg(appId));
                m_apps.append({appId, name, QString(), QString(), 0, 0, false, true});
            }
        }

        fprintf(stderr, "[Backend] OneDrive remote apps: %d remote IDs, %d total apps\n",
                (int)m_remoteAppIds.size(), (int)m_apps.size());
        emit appsChanged();
        emit remoteAppsFetched();
        QTimer::singleShot(0, this, &Backend::resolveAppNames);
    });
}

void Backend::deleteCloudAppData(uint appId)
{
    QString token = readAccessToken();
    if (token.isEmpty()) return;

    if (m_providerName == "gdrive") {
        deleteGoogleDriveAppData(appId, token);
    } else if (m_providerName == "onedrive") {
        deleteOneDriveAppData(appId, token);
    }
}

void Backend::deleteGoogleDriveAppData(uint appId, const QString &token)
{
    // Find app folder CloudRedirect/<accountId>/<appId> and delete recursively
    QString query = QString("name='CloudRedirect' and mimeType='application/vnd.google-apps.folder' and trashed=false");
    QUrl url("https://www.googleapis.com/drive/v3/files");
    QUrlQuery params;
    params.addQueryItem("q", query);
    params.addQueryItem("fields", "files(id)");
    url.setQuery(params);

    QNetworkRequest req(url);
    req.setRawHeader("Authorization", ("Bearer " + token).toUtf8());

    auto *reply = m_nam->get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply, token, appId]() {
        reply->deleteLater();
        if (reply->error() != QNetworkReply::NoError) return;

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray files = doc.object().value("files").toArray();
        if (files.isEmpty()) return;
        QString rootId = files[0].toObject().value("id").toString();

        // Find account folder
        QString q2 = QString("name='%1' and '%2' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false")
            .arg(m_accountId, rootId);
        QUrl url2("https://www.googleapis.com/drive/v3/files");
        QUrlQuery params2;
        params2.addQueryItem("q", q2);
        params2.addQueryItem("fields", "files(id)");
        url2.setQuery(params2);
        QNetworkRequest req2(url2);
        req2.setRawHeader("Authorization", ("Bearer " + token).toUtf8());

        auto *reply2 = m_nam->get(req2);
        connect(reply2, &QNetworkReply::finished, this, [this, reply2, token, appId]() {
            reply2->deleteLater();
            if (reply2->error() != QNetworkReply::NoError) return;

            QJsonDocument doc2 = QJsonDocument::fromJson(reply2->readAll());
            QJsonArray files2 = doc2.object().value("files").toArray();
            if (files2.isEmpty()) return;
            QString accountId = files2[0].toObject().value("id").toString();

            // Find app folder
            QString q3 = QString("name='%1' and '%2' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false")
                .arg(QString::number(appId), accountId);
            QUrl url3("https://www.googleapis.com/drive/v3/files");
            QUrlQuery params3;
            params3.addQueryItem("q", q3);
            params3.addQueryItem("fields", "files(id)");
            url3.setQuery(params3);
            QNetworkRequest req3(url3);
            req3.setRawHeader("Authorization", ("Bearer " + token).toUtf8());

            auto *reply3 = m_nam->get(req3);
            connect(reply3, &QNetworkReply::finished, this, [this, reply3, token, appId]() {
                reply3->deleteLater();
                if (reply3->error() != QNetworkReply::NoError) return;

                QJsonDocument doc3 = QJsonDocument::fromJson(reply3->readAll());
                QJsonArray files3 = doc3.object().value("files").toArray();
                if (files3.isEmpty()) return;
                QString folderId = files3[0].toObject().value("id").toString();

                // Delete the folder (Google Drive recursively deletes contents)
                QUrl deleteUrl("https://www.googleapis.com/drive/v3/files/" + folderId);
                QNetworkRequest delReq(deleteUrl);
                delReq.setRawHeader("Authorization", ("Bearer " + token).toUtf8());
                auto *delReply = m_nam->deleteResource(delReq);
                connect(delReply, &QNetworkReply::finished, this, [delReply, appId]() {
                    delReply->deleteLater();
                    if (delReply->error() == QNetworkReply::NoError) {
                        fprintf(stderr, "[Backend] Deleted Google Drive folder for app %u\n", appId);
                    } else {
                        fprintf(stderr, "[Backend] Failed to delete Google Drive folder for app %u: %s\n",
                                appId, delReply->errorString().toUtf8().constData());
                    }
                });
            });
        });
    });
}

void Backend::deleteOneDriveAppData(uint appId, const QString &token)
{
    // Match Windows behavior: list all files under accountId/appId/, then delete each one
    // First, get the folder ID for CloudRedirect/<accountId>/<appId>
    QString folderPath = QString("CloudRedirect/%1/%2").arg(m_accountId).arg(appId);
    QUrl url(QString("https://graph.microsoft.com/v1.0/me/drive/root:/%1:?$select=id").arg(folderPath));

    QNetworkRequest req(url);
    req.setRawHeader("Authorization", ("Bearer " + token).toUtf8());

    auto *reply = m_nam->get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply, token, appId]() {
        reply->deleteLater();
        int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        
        if (status == 404) {
            fprintf(stderr, "[Backend] OneDrive folder for app %u not found (nothing to delete)\n", appId);
            return;
        }
        if (reply->error() != QNetworkReply::NoError) {
            fprintf(stderr, "[Backend] Failed to get OneDrive folder for app %u: %s\n",
                    appId, reply->errorString().toUtf8().constData());
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QString folderId = doc.object().value("id").toString();
        if (folderId.isEmpty()) {
            fprintf(stderr, "[Backend] OneDrive folder ID empty for app %u\n", appId);
            return;
        }

        // List all children recursively, delete files only (matches Windows behavior)
        listAndDeleteOneDriveFiles(folderId, token, appId);
    });
}

void Backend::listAndDeleteOneDriveFiles(const QString &folderId, const QString &token, uint appId)
{
    QUrl url(QString("https://graph.microsoft.com/v1.0/me/drive/items/%1/children?$select=id,name,folder").arg(folderId));

    QNetworkRequest req(url);
    req.setRawHeader("Authorization", ("Bearer " + token).toUtf8());

    auto *reply = m_nam->get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply, token, appId]() {
        reply->deleteLater();
        if (reply->error() != QNetworkReply::NoError) {
            fprintf(stderr, "[Backend] Failed to list OneDrive children for app %u: %s\n",
                    appId, reply->errorString().toUtf8().constData());
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonArray items = doc.object().value("value").toArray();

        for (const auto &val : items) {
            QJsonObject item = val.toObject();
            QString itemId = item.value("id").toString();
            bool isFolder = item.contains("folder");

            if (isFolder) {
                // Recurse into subfolder to find files
                listAndDeleteOneDriveFiles(itemId, token, appId);
            } else {
                // Delete the file
                deleteOneDriveItem(itemId, token, appId);
            }
        }

        // Handle pagination
        QString nextLink = doc.object().value("@odata.nextLink").toString();
        if (!nextLink.isEmpty()) {
            int pathStart = nextLink.indexOf("/v1.0/");
            if (pathStart >= 0) {
                QString nextPath = nextLink.mid(pathStart);
                QUrl nextUrl("https://graph.microsoft.com" + nextPath);
                QNetworkRequest nextReq(nextUrl);
                nextReq.setRawHeader("Authorization", ("Bearer " + token).toUtf8());
                auto *nextReply = m_nam->get(nextReq);
                connect(nextReply, &QNetworkReply::finished, this, [this, nextReply, token, appId]() {
                    nextReply->deleteLater();
                    if (nextReply->error() != QNetworkReply::NoError) return;
                    
                    QJsonDocument nextDoc = QJsonDocument::fromJson(nextReply->readAll());
                    QJsonArray nextItems = nextDoc.object().value("value").toArray();
                    for (const auto &val : nextItems) {
                        QJsonObject item = val.toObject();
                        QString itemId = item.value("id").toString();
                        bool isFolder = item.contains("folder");
                        if (isFolder) {
                            listAndDeleteOneDriveFiles(itemId, token, appId);
                        } else {
                            deleteOneDriveItem(itemId, token, appId);
                        }
                    }
                });
            }
        }
    });
}

void Backend::deleteOneDriveItem(const QString &itemId, const QString &token, uint appId)
{
    QUrl url(QString("https://graph.microsoft.com/v1.0/me/drive/items/%1").arg(itemId));

    QNetworkRequest req(url);
    req.setRawHeader("Authorization", ("Bearer " + token).toUtf8());

    auto *reply = m_nam->deleteResource(req);
    connect(reply, &QNetworkReply::finished, this, [reply, itemId, appId]() {
        reply->deleteLater();
        int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (status >= 200 && status < 300) {
            fprintf(stderr, "[Backend] Deleted OneDrive file %s for app %u\n",
                    itemId.toUtf8().constData(), appId);
        } else if (status == 404) {
            // Already deleted
        } else {
            fprintf(stderr, "[Backend] Failed to delete OneDrive file %s for app %u: HTTP %d\n",
                    itemId.toUtf8().constData(), appId, status);
        }
    });
}

QVariantList Backend::listBackups()
{
    QVariantList results;
    QString backupRoot = backupRootForAccount(m_accountId);
    QDir dir(backupRoot);
    if (!dir.exists()) return results;
    
    QStringList entries = dir.entryList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
    for (const auto &entry : entries) {
        QVariantMap m;
        m["path"] = backupRoot + "/" + entry;
        m["name"] = entry;
        
        QFile undoFile(backupRoot + "/" + entry + "/undo_log.json");
        if (undoFile.open(QIODevice::ReadOnly)) {
            QJsonDocument doc = QJsonDocument::fromJson(undoFile.readAll());
            undoFile.close();
            QJsonObject obj = doc.object();
            m["timestamp"] = obj.value("timestamp").toString();
            m["appId"] = obj.value("appId").toInt();
            m["accountId"] = obj.value("accountId").toString();
            QJsonArray ops = obj.value("operations").toArray();
            m["fileCount"] = ops.size();
        }
        
        // Get actual file count and size
        qint64 totalSize = 0;
        int fileCount = 0;
        QDirIterator it(backupRoot + "/" + entry, QDir::Files, QDirIterator::Subdirectories);
        while (it.hasNext()) {
            it.next();
            if (it.fileName() == "undo_log.json") continue;
            fileCount++;
            totalSize += it.fileInfo().size();
        }
        m["fileCount"] = fileCount;
        m["totalSize"] = totalSize;
        m["sizeFormatted"] = formatSize(totalSize);
        
        results.append(m);
    }
    return results;
}

QString Backend::restoreBackup(const QString &backupPath)
{
    QString cleanBackupPath = QDir::cleanPath(backupPath);
    if (!isPathWithin(backupRootForAccount(m_accountId), cleanBackupPath))
        return "Invalid backup path";

    QFile undoFile(cleanBackupPath + "/undo_log.json");
    if (!undoFile.open(QIODevice::ReadOnly)) return "Cannot read undo log";
    
    QJsonDocument doc = QJsonDocument::fromJson(undoFile.readAll());
    undoFile.close();
    
    QJsonArray ops = doc.object().value("operations").toArray();
    int restored = 0;
    int skipped = 0;
    QStringList errors;
    
    for (const auto &op : ops) {
        QJsonObject o = op.toObject();
        QString type = o["type"].toString();
        QString dest = o["dest"].toString();
        
        if (type == "file_copy") {
            QString backupFile = dest;
            if (!isPathWithin(cleanBackupPath, backupFile)) {
                skipped++;
                errors.append("Skipped invalid backup entry: " + backupFile);
                continue;
            }
            QString originalPath = o["source"].toString();
            
            // Validate restore target is within expected directories
            if (!isPathWithin(m_storagePath, originalPath) &&
                !isPathWithin(m_steamPath + "/userdata", originalPath)) {
                skipped++;
                errors.append("Skipped unsafe restore path: " + originalPath);
                continue;
            }
            
            if (!QFile::exists(backupFile)) {
                skipped++;
                errors.append("Backup file missing: " + backupFile);
                continue;
            }
            
            QDir().mkpath(QFileInfo(originalPath).absolutePath());
            QFile::remove(originalPath);  // QFile::copy won't overwrite existing files
            if (QFile::copy(backupFile, originalPath)) {
                restored++;
            } else {
                skipped++;
                errors.append("Failed to restore: " + originalPath);
            }
        }
    }
    
    return QString("Restored %1 file(s), %2 skipped%3")
        .arg(restored).arg(skipped)
        .arg(errors.isEmpty() ? "" : ". Errors: " + errors.join("; "));
}

void Backend::deleteBackup(const QString &backupPath)
{
    QString cleanBackupPath = QDir::cleanPath(backupPath);
    if (!isPathWithin(backupRootForAccount(m_accountId), cleanBackupPath))
        return;

    QDir dir(cleanBackupPath);
    if (dir.exists()) {
        dir.removeRecursively();
    }
}

QString Backend::getAppName(uint appId) const
{
    if (m_nameCache.contains(appId))
        return m_nameCache[appId];
    return QString("App %1").arg(appId);
}

QString Backend::getAppHeaderUrl(uint appId) const
{
    if (m_headerCache.contains(appId))
        return m_headerCache[appId];
    return QString("https://shared.steamstatic.com/store_item_assets/steam/apps/%1/header.jpg").arg(appId);
}

// Verify an R2 credentials file exists and carries all four required fields.
// Mirrors the native R2Provider::Init validation (account_id, access_key_id,
// secret_access_key, bucket must all be non-empty). Values are not checked
// against R2 -- that happens at runtime in the DLL.
static bool r2CredentialsValid(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return false;
    QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    f.close();
    if (!doc.isObject())
        return false;
    QJsonObject o = doc.object();
    const char *required[] = { "account_id", "access_key_id",
                               "secret_access_key", "bucket" };
    for (const char *k : required) {
        if (o.value(k).toString().isEmpty())
            return false;
    }
    return true;
}

static bool s3CredentialsValid(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return false;
    QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    f.close();
    if (!doc.isObject())
        return false;
    QJsonObject o = doc.object();
    // Generic S3 needs an explicit endpoint + region (no account-derived host).
    const char *required[] = { "access_key_id", "secret_access_key",
                               "bucket", "endpoint", "region" };
    for (const char *k : required) {
        if (o.value(k).toString().isEmpty())
            return false;
    }
    return true;
}

bool Backend::isProviderAuthenticated(const QString &provider) const
{
    // "folder"/"local" don't authenticate.
    if (provider == "local" || provider == "folder")
        return false;

    // R2 uses static credentials in r2_credentials.json, not an OAuth token.
    if (provider == "r2")
        return r2CredentialsValid(r2CredentialPath());

    // S3-compatible providers likewise use static credentials, not OAuth.
    if (provider == "s3")
        return s3CredentialsValid(s3CredentialPath());

    QString tokenPath = defaultTokenPath(provider);
    return QFile::exists(tokenPath);
}

QString Backend::r2CredentialPath() const
{
    // Must match the native CLI convention (cli.cpp: provider "r2" ->
    // r2_credentials.json) so the DLL finds it without an explicit token_path.
    return crConfigDir() + "/r2_credentials.json";
}

QVariantMap Backend::getR2Credentials() const
{
    QVariantMap out;
    QFile f(r2CredentialPath());
    if (!f.open(QIODevice::ReadOnly))
        return out;
    QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    f.close();
    if (!doc.isObject())
        return out;
    QJsonObject o = doc.object();
    out["account_id"]   = o.value("account_id").toString();
    out["access_key_id"]= o.value("access_key_id").toString();
    out["bucket"]       = o.value("bucket").toString();
    out["key_prefix"]   = o.value("key_prefix").toString();
    out["endpoint"]     = o.value("endpoint").toString();
    // Never expose the secret back to the UI; just report whether one is set so
    // the form can show a placeholder and leave the field blank on re-edit.
    out["has_secret"]   = !o.value("secret_access_key").toString().isEmpty();
    return out;
}

bool Backend::saveR2Credentials(const QString &accountId,
                                const QString &accessKeyId,
                                const QString &secretAccessKey,
                                const QString &bucket,
                                const QString &keyPrefix,
                                const QString &endpoint)
{
    const QString acct   = accountId.trimmed();
    const QString access = accessKeyId.trimmed();
    QString secret       = secretAccessKey.trimmed();
    const QString buck   = bucket.trimmed();

    if (acct.isEmpty() || access.isEmpty() || buck.isEmpty()) {
        fprintf(stderr, "[Backend] saveR2Credentials: missing required field\n");
        return false;
    }

    // The secret may be left blank on re-edit to keep the existing one. Only
    // reuse it when a valid file already exists; otherwise a blank secret is an
    // error (nothing to fall back to).
    const QString credPath = r2CredentialPath();
    if (secret.isEmpty()) {
        QFile f(credPath);
        if (f.open(QIODevice::ReadOnly)) {
            QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
            f.close();
            if (doc.isObject())
                secret = doc.object().value("secret_access_key").toString();
        }
        if (secret.isEmpty()) {
            fprintf(stderr, "[Backend] saveR2Credentials: no secret provided and "
                            "none on file\n");
            return false;
        }
    }

    QJsonObject o;
    o["account_id"]        = acct;
    o["access_key_id"]     = access;
    o["secret_access_key"] = secret;
    o["bucket"]            = buck;
    if (!keyPrefix.trimmed().isEmpty())
        o["key_prefix"] = keyPrefix.trimmed();
    if (!endpoint.trimmed().isEmpty())
        o["endpoint"] = endpoint.trimmed();

    QDir().mkpath(crConfigDir());

    // Atomic write with 0600 perms (credentials are sensitive), mirroring the
    // OAuth token writer in oauthservice.cpp.
    const QByteArray data = QJsonDocument(o).toJson();
    const QString tempPath = credPath + ".tmp";
    int fd = open(tempPath.toUtf8().constData(),
                  O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        fprintf(stderr, "[Backend] saveR2Credentials: cannot open temp file\n");
        return false;
    }
    qint64 written = 0;
    while (written < data.size()) {
        ssize_t n = ::write(fd, data.constData() + written, data.size() - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            unlink(tempPath.toUtf8().constData());
            fprintf(stderr, "[Backend] saveR2Credentials: write failed\n");
            return false;
        }
        written += n;
    }
    ::close(fd);
    if (rename(tempPath.toUtf8().constData(), credPath.toUtf8().constData()) != 0) {
        unlink(tempPath.toUtf8().constData());
        fprintf(stderr, "[Backend] saveR2Credentials: rename failed\n");
        return false;
    }

    // Register the credential path in config so the native side resolves it even
    // if the convention filename ever changes. saveConfig() preserves unknown
    // keys, so read-modify-write token_paths here directly.
    const QString configPath = crConfigDir() + "/config.json";
    QJsonObject cfg;
    QFile cf(configPath);
    if (cf.open(QIODevice::ReadOnly)) {
        QJsonDocument d = QJsonDocument::fromJson(cf.readAll());
        cf.close();
        if (d.isObject())
            cfg = d.object();
    }
    QJsonObject tokenPaths = cfg.value("token_paths").toObject();
    tokenPaths["r2"] = credPath;
    cfg["token_paths"] = tokenPaths;
    {
        const QByteArray cfgData = QJsonDocument(cfg).toJson();
        const QString cfgTemp = configPath + ".tmp";
        QFile w(cfgTemp);
        if (w.open(QIODevice::WriteOnly)) {
            w.write(cfgData);
            w.close();
            if (!QFile::rename(cfgTemp, configPath)) {
                QFile::remove(configPath);
                QFile::rename(cfgTemp, configPath);
            }
        }
    }

    // Refresh cached auth flag and notify QML.
    m_providerAuthenticated = (m_providerName == "r2");
    emit settingsChanged();
    return true;
}

QString Backend::s3CredentialPath() const
{
    // Must match the native CLI convention (cli.cpp / ResolveProviderTokenPath:
    // provider "s3" -> s3_credentials.json) so the DLL finds it without an
    // explicit token_path.
    return crConfigDir() + "/s3_credentials.json";
}

QVariantMap Backend::getS3Credentials() const
{
    QVariantMap out;
    QFile f(s3CredentialPath());
    if (!f.open(QIODevice::ReadOnly))
        return out;
    QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    f.close();
    if (!doc.isObject())
        return out;
    QJsonObject o = doc.object();
    out["access_key_id"]       = o.value("access_key_id").toString();
    out["bucket"]              = o.value("bucket").toString();
    out["endpoint"]            = o.value("endpoint").toString();
    out["region"]              = o.value("region").toString();
    out["key_prefix"]          = o.value("key_prefix").toString();
    out["sign_payload"]        = o.value("sign_payload").toBool();
    out["allow_insecure_http"] = o.value("allow_insecure_http").toBool();
    out["allow_insecure_tls"]  = o.value("allow_insecure_tls").toBool();
    out["ca_cert_path"]        = o.value("ca_cert_path").toString();
    // Never expose the secret back to the UI; just report whether one is set.
    out["has_secret"]          = !o.value("secret_access_key").toString().isEmpty();
    return out;
}

bool Backend::saveS3Credentials(const QString &accessKeyId,
                                const QString &secretAccessKey,
                                const QString &bucket,
                                const QString &endpoint,
                                const QString &region,
                                const QString &keyPrefix,
                                bool signPayload,
                                bool allowInsecureHttp,
                                bool allowInsecureTls,
                                const QString &caCertPath)
{
    const QString access = accessKeyId.trimmed();
    QString secret       = secretAccessKey.trimmed();
    const QString buck   = bucket.trimmed();
    const QString endp   = endpoint.trimmed();
    const QString reg    = region.trimmed();

    if (access.isEmpty() || buck.isEmpty() || endp.isEmpty() || reg.isEmpty()) {
        fprintf(stderr, "[Backend] saveS3Credentials: missing required field\n");
        return false;
    }

    // The secret may be left blank on re-edit to keep the existing one. Only
    // reuse it when a valid file already exists; otherwise a blank secret is an
    // error (nothing to fall back to).
    const QString credPath = s3CredentialPath();
    if (secret.isEmpty()) {
        QFile f(credPath);
        if (f.open(QIODevice::ReadOnly)) {
            QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
            f.close();
            if (doc.isObject())
                secret = doc.object().value("secret_access_key").toString();
        }
        if (secret.isEmpty()) {
            fprintf(stderr, "[Backend] saveS3Credentials: no secret provided and "
                            "none on file\n");
            return false;
        }
    }

    QJsonObject o;
    o["access_key_id"]     = access;
    o["secret_access_key"] = secret;
    o["bucket"]            = buck;
    o["endpoint"]          = endp;
    o["region"]            = reg;
    if (!keyPrefix.trimmed().isEmpty())
        o["key_prefix"] = keyPrefix.trimmed();
    // Transport/signing options -- only emit when set to keep the file minimal.
    if (signPayload)
        o["sign_payload"] = true;
    if (allowInsecureHttp)
        o["allow_insecure_http"] = true;
    if (allowInsecureTls)
        o["allow_insecure_tls"] = true;
    if (!caCertPath.trimmed().isEmpty())
        o["ca_cert_path"] = caCertPath.trimmed();

    QDir().mkpath(crConfigDir());

    // Atomic write with 0600 perms (credentials are sensitive), mirroring the
    // R2 credential writer above.
    const QByteArray data = QJsonDocument(o).toJson();
    const QString tempPath = credPath + ".tmp";
    int fd = open(tempPath.toUtf8().constData(),
                  O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        fprintf(stderr, "[Backend] saveS3Credentials: cannot open temp file\n");
        return false;
    }
    qint64 written = 0;
    while (written < data.size()) {
        ssize_t n = ::write(fd, data.constData() + written, data.size() - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            unlink(tempPath.toUtf8().constData());
            fprintf(stderr, "[Backend] saveS3Credentials: write failed\n");
            return false;
        }
        written += n;
    }
    ::close(fd);
    if (rename(tempPath.toUtf8().constData(), credPath.toUtf8().constData()) != 0) {
        unlink(tempPath.toUtf8().constData());
        fprintf(stderr, "[Backend] saveS3Credentials: rename failed\n");
        return false;
    }

    // Register the credential path in config so the native side resolves it even
    // if the convention filename ever changes.
    const QString configPath = crConfigDir() + "/config.json";
    QJsonObject cfg;
    QFile cf(configPath);
    if (cf.open(QIODevice::ReadOnly)) {
        QJsonDocument d = QJsonDocument::fromJson(cf.readAll());
        cf.close();
        if (d.isObject())
            cfg = d.object();
    }
    QJsonObject tokenPaths = cfg.value("token_paths").toObject();
    tokenPaths["s3"] = credPath;
    cfg["token_paths"] = tokenPaths;
    {
        const QByteArray cfgData = QJsonDocument(cfg).toJson();
        const QString cfgTemp = configPath + ".tmp";
        QFile w(cfgTemp);
        if (w.open(QIODevice::WriteOnly)) {
            w.write(cfgData);
            w.close();
            if (!QFile::rename(cfgTemp, configPath)) {
                QFile::remove(configPath);
                QFile::rename(cfgTemp, configPath);
            }
        }
    }

    // Refresh cached auth flag and notify QML.
    m_providerAuthenticated = (m_providerName == "s3");
    emit settingsChanged();
    return true;
}

bool Backend::shouldOfferAutoUpdates() const
{
    // Only relevant inside a Flatpak
    if (!QFile::exists("/.flatpak-info"))
        return false;

    if (!flatpakRepoDescriptorHasGpgKey())
        return false;

    // Check if user already dismissed
    QString configPath = crConfigDir() + "/config.json";
    QFile f(configPath);
    if (f.open(QIODevice::ReadOnly)) {
        QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
        f.close();
        if (doc.isObject() && doc.object().value("auto_update_prompted").toBool())
            return false;
    }

    // Check if a repo is already configured for this app
    QProcess proc;
    proc.start("flatpak-spawn", {"--host", "flatpak", "remote-list", "--user", "--columns=name,url"});
    proc.waitForFinished(5000);
    QString output = proc.readAllStandardOutput();
    if (output.contains("cloudredirect") || output.contains("CloudRedirect-Unified"))
        return false;

    return true;
}

void Backend::enableAutoUpdates()
{
    QString repoFile = flatpakRepoDescriptorPath();
    if (!QFile::exists(repoFile)) {
        fprintf(stderr, "[Backend] Flatpak repo descriptor missing; not adding update remote\n");
        dismissAutoUpdatePrompt();
        return;
    }
    if (!flatpakRepoDescriptorHasGpgKey()) {
        fprintf(stderr, "[Backend] Flatpak repo descriptor has no GPG key; not adding update remote\n");
        dismissAutoUpdatePrompt();
        return;
    }

    // Use the hosted .flatpakrepo URL; the local file is inside the sandbox
    // and inaccessible to the host flatpak process via flatpak-spawn.
    QString repoUrl = "https://selectively11.github.io/CloudRedirect/cloudredirect.flatpakrepo";

    QProcess proc;
    proc.start("flatpak-spawn", {"--host", "flatpak", "remote-add", "--user", "--if-not-exists", "cloudredirect", repoUrl});
    proc.waitForFinished(15000);

    if (proc.exitCode() == 0) {
        fprintf(stderr, "[Backend] Added cloudredirect Flatpak remote\n");
    } else {
        fprintf(stderr, "[Backend] Failed to add remote: %s\n",
                proc.readAllStandardError().constData());
    }

    dismissAutoUpdatePrompt();
}

void Backend::dismissAutoUpdatePrompt()
{
    // Set flag in config
    QString configPath = crConfigDir() + "/config.json";
    QJsonObject obj;

    QFile f(configPath);
    if (f.open(QIODevice::ReadOnly)) {
        QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
        f.close();
        if (doc.isObject()) obj = doc.object();
    }

    obj["auto_update_prompted"] = true;

    QDir().mkpath(crConfigDir());
    QString tempPath = configPath + ".tmp";
    QFile tmp(tempPath);
    if (tmp.open(QIODevice::WriteOnly)) {
        tmp.write(QJsonDocument(obj).toJson());
        tmp.close();
        if (!QFile::rename(tempPath, configPath)) {
            QFile::remove(configPath);
            QFile::rename(tempPath, configPath);
        }
    }
}

static QString runFlatpakHostCommand(const QStringList &args, int timeoutMs = 15000)
{
    QProcess proc;
    if (QFile::exists("/.flatpak-info")) {
        proc.start("flatpak-spawn", QStringList{"--host", "flatpak"} + args);
    } else {
        proc.start("flatpak", args);
    }
    proc.waitForFinished(timeoutMs);
    return proc.readAllStandardOutput();
}

void Backend::checkForFlatpakUpdate()
{
    // Only relevant inside or alongside a Flatpak install
    QString remotes = runFlatpakHostCommand({"remote-list", "--user", "--columns=name"});
    if (!remotes.contains("cloudredirect"))
        return;

    // Get remote version and compare against running version
    QString info = runFlatpakHostCommand({"remote-info", "--user", "cloudredirect", "org.cloudredirect.CloudRedirect"});
    QString remoteVersion;
    for (const QString &line : info.split('\n')) {
        if (line.trimmed().startsWith("Version:")) {
            remoteVersion = line.mid(line.indexOf(':') + 1).trimmed();
            break;
        }
    }

    if (remoteVersion.isEmpty())
        return;

    // Compare versions: only notify if remote is strictly newer
    QString current = QCoreApplication::applicationVersion();
    auto parseVer = [](const QString &v) -> QList<int> {
        // Strip prerelease suffix (e.g. "-TEST4") for comparison
        QString base = v.section('-', 0, 0);
        QList<int> parts;
        for (const QString &p : base.split('.'))
            parts.append(p.toInt());
        while (parts.size() < 3) parts.append(0);
        return parts;
    };

    QList<int> rv = parseVer(remoteVersion);
    QList<int> cv = parseVer(current);
    bool remoteNewer = false;
    for (int i = 0; i < 3; ++i) {
        if (rv[i] > cv[i]) { remoteNewer = true; break; }
        if (rv[i] < cv[i]) break;
    }

    if (remoteNewer)
        emit flatpakUpdateAvailable();
}

void Backend::applyFlatpakUpdate()
{
    QString output = runFlatpakHostCommand({"update", "--user", "-y", "org.cloudredirect.CloudRedirect"}, 120000);
    bool ok = (output.contains("org.cloudredirect.CloudRedirect") && !output.contains("error:"));
    emit flatpakUpdateCompleted(ok);
}

// ── Cloud provider migration ────────────────────────────────────────────

QString Backend::providerLabel(const QString &provider) const
{
    if (provider == "gdrive")   return "Google Drive";
    if (provider == "onedrive") return "OneDrive";
    if (provider == "r2")       return "Cloudflare R2";
    if (provider == "s3")       return "S3 Compatible";
    if (provider == "folder")   return "Custom Folder";
    if (provider == "local")    return "Local Storage";
    return provider;
}

QString Backend::activeProvider() const
{
    return m_providerName;
}

// Resolve <provider>'s token path: token_paths registry, then active
// provider's token_path, then convention filename. Mirrors the native side.
QString Backend::resolveTokenPath(const QString &provider) const
{
    const QString configPath = crConfigDir() + "/config.json";
    QFile f(configPath);
    if (f.open(QIODevice::ReadOnly)) {
        QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
        f.close();
        if (doc.isObject()) {
            QJsonObject root = doc.object();

            // 1) Per-provider registry (survives provider switches).
            QJsonObject tps = root.value("token_paths").toObject();
            QString perProv = tps.value(provider).toString();
            if (!perProv.isEmpty())
                return perProv;

            // 2) Active provider's token_path.
            if (root.value("provider").toString() == provider) {
                QString tp = root.value("token_path").toString();
                if (!tp.isEmpty())
                    return tp;
            }
        }
    }

    // 3) Convention fallback: Linux writes tokens_<provider>.json (defaultTokenPath).
    if (provider == "r2")
        return crConfigDir() + "/r2_credentials.json";
    if (provider == "s3")
        return crConfigDir() + "/s3_credentials.json";
    return defaultTokenPath(provider);
}

QVariantMap Backend::checkProviderCredentials(const QString &provider) const
{
    QVariantMap out;
    QString tokenPath = resolveTokenPath(provider);
    if (tokenPath.isEmpty()) {
        out["ok"] = false;
        out["message"] = "Cannot determine credential path";
        return out;
    }
    QFileInfo fi(tokenPath);
    if (!fi.exists()) {
        out["ok"] = false;
        out["message"] = "Credential file not found.\nExpected: " + tokenPath;
        return out;
    }
    if (fi.size() == 0) {
        out["ok"] = false;
        out["message"] = "Credential file is empty: " + fi.fileName();
        return out;
    }
    out["ok"] = true;
    out["message"] = "Credentials found";
    return out;
}

// Locate the deployed CLI (crDataDir()/cloud_redirect_cli). It's a 32-bit
// binary run on the host via flatpak-spawn, so resolve the host path.
QString Backend::cliExecutablePath() const
{
    QString deployed = crDataDir() + "/cloud_redirect_cli";
    if (QFile::exists(deployed))
        return deployed;

    // Not deployed; outside a flatpak, try local candidates.
    if (!inFlatpak()) {
        const QString bundledEnv = qEnvironmentVariable("CR_BUNDLED_CLI");
        if (!bundledEnv.isEmpty() && QFile::exists(bundledEnv))
            return bundledEnv;
        const QStringList candidates = {
            QCoreApplication::applicationDirPath() + "/cloud_redirect_cli",
            xdgDataHome() + "/cloud_redirect/cloud_redirect_cli",
        };
        for (const QString &c : candidates) {
            if (QFile::exists(c))
                return c;
        }
    }
    return QString();
}

// Build the (program, args) to launch the CLI: via flatpak-spawn on the host
// inside a flatpak, directly otherwise.
void Backend::cliLaunch(const QString &cliPath, const QStringList &cliArgs,
                        QString &program, QStringList &args) const
{
    if (inFlatpak()) {
        program = "flatpak-spawn";
        args = QStringList{"--host", cliPath} + cliArgs;
    } else {
        program = cliPath;
        args = cliArgs;
    }
}

void Backend::scanProvider(const QString &provider)
{
    // Cancel any previous scan.
    if (m_scanProc) {
        m_scanProc->disconnect(this);
        m_scanProc->kill();
        m_scanProc->deleteLater();
        m_scanProc = nullptr;
    }

    emit migrationScanStarted();

    QString cli = cliExecutablePath();
    if (cli.isEmpty()) {
        emit migrationScanFinished(QVariantList(), "CLI executable not available. Deploy CloudRedirect first.");
        return;
    }

    auto *proc = new QProcess(this);
    m_scanProc = proc;
    proc->setProcessChannelMode(QProcess::SeparateChannels);

    connect(proc, &QProcess::errorOccurred, this, [this, proc](QProcess::ProcessError) {
        if (proc != m_scanProc) return;
        emit migrationScanFinished(QVariantList(), "Failed to launch CLI: " + proc->errorString());
        m_scanProc = nullptr;
        proc->deleteLater();
    });

    connect(proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, [this, proc](int exitCode, QProcess::ExitStatus) {
        if (proc != m_scanProc) return;
        m_scanProc = nullptr;
        const QByteArray out = proc->readAllStandardOutput();
        proc->deleteLater();

        QJsonParseError perr;
        QJsonDocument doc = QJsonDocument::fromJson(out, &perr);
        if (perr.error != QJsonParseError::NoError || !doc.isObject()) {
            emit migrationScanFinished(QVariantList(),
                exitCode == 0 ? "Invalid CLI response" : "CLI exited with code " + QString::number(exitCode));
            return;
        }
        QJsonObject root = doc.object();
        if (root.contains("error")) {
            emit migrationScanFinished(QVariantList(), root.value("error").toString("Unknown error"));
            return;
        }

        QVariantList apps;
        QSet<uint32_t> pending;
        for (const QJsonValue &v : root.value("apps").toArray()) {
            QJsonObject o = v.toObject();
            QString appId = o.value("app_id").toString();
            QString accountId = o.value("account_id").toString();
            if (appId.isEmpty() || appId == "0")
                continue;
            QVariantMap m;
            m["appId"] = appId;
            m["accountId"] = accountId;
            apps.append(m);
            bool ok = false;
            uint32_t id = appId.toUInt(&ok);
            if (ok && id != 0 && !m_nameCache.contains(id))
                pending.insert(id);
        }

        // Seed placeholders and kick off name/art resolution for uncached apps.
        for (uint32_t id : pending) {
            AppInfo info;
            info.appId = id;
            info.name = QString("App %1").arg(id);
            bool already = false;
            for (const auto &a : m_apps) { if (a.appId == id) { already = true; break; } }
            if (!already)
                m_apps.append(info);
        }
        if (!pending.isEmpty())
            QTimer::singleShot(0, this, &Backend::resolveAppNames);

        emit migrationScanFinished(apps, QString());
    });

    QString scanProg;
    QStringList scanArgs;
    cliLaunch(cli, {"scan-all", provider}, scanProg, scanArgs);
    proc->start(scanProg, scanArgs);
}

void Backend::testProviderConnection(const QString &provider)
{
    // Cancel any previous test.
    if (m_testProc) {
        m_testProc->disconnect(this);
        m_testProc->kill();
        m_testProc->deleteLater();
        m_testProc = nullptr;
    }

    QString cli = cliExecutablePath();
    if (cli.isEmpty()) {
        emit providerTestFinished(provider, false,
            "CLI not available. Deploy CloudRedirect first.");
        return;
    }

    auto *proc = new QProcess(this);
    m_testProc = proc;
    proc->setProcessChannelMode(QProcess::SeparateChannels);

    // A wrong endpoint can hang on connect; bound the wait and treat it as a
    // failed test rather than leaving the UI stuck.
    auto *timeout = new QTimer(proc);
    timeout->setSingleShot(true);
    connect(timeout, &QTimer::timeout, this, [this, proc, provider]() {
        if (proc != m_testProc) return;
        m_testProc = nullptr;
        proc->disconnect(this);
        proc->kill();
        proc->deleteLater();
        emit providerTestFinished(provider, false,
            "Timed out reaching the endpoint. Check the endpoint and port.");
    });
    timeout->start(30000);

    connect(proc, &QProcess::errorOccurred, this, [this, proc, provider](QProcess::ProcessError) {
        if (proc != m_testProc) return;
        m_testProc = nullptr;
        emit providerTestFinished(provider, false, "Failed to launch CLI: " + proc->errorString());
        proc->deleteLater();
    });

    connect(proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, [this, proc, provider, timeout](int exitCode, QProcess::ExitStatus) {
        if (proc != m_testProc) return;
        timeout->stop();
        m_testProc = nullptr;
        const QByteArray out = proc->readAllStandardOutput();
        proc->deleteLater();

        // The CLI emits log lines before the JSON; take the last JSON object.
        QByteArray json;
        int brace = out.lastIndexOf('{');
        if (brace >= 0)
            json = out.mid(brace);

        QJsonParseError perr;
        QJsonDocument doc = QJsonDocument::fromJson(json, &perr);
        if (perr.error != QJsonParseError::NoError || !doc.isObject()) {
            emit providerTestFinished(provider, false,
                exitCode == 0 ? "Could not reach the endpoint. Check the endpoint, port and keys."
                              : "Connection test failed (exit " + QString::number(exitCode) + ").");
            return;
        }

        QJsonObject o = doc.object();
        if (o.value("success").toBool()) {
            emit providerTestFinished(provider, true, QString());
        } else {
            const QString err = o.value("error").toString(
                "Could not reach the endpoint. Check the endpoint, port and keys.");
            emit providerTestFinished(provider, false, err);
        }
    });

    // A real bucket op (account 0) -- unlike auth-status, this fails on a bad
    // endpoint because it actually lists objects.
    QString prog;
    QStringList args;
    cliLaunch(cli, {"list-remote-app-ids", provider, "0"}, prog, args);
    proc->start(prog, args);
}

void Backend::startMigration(const QString &src, const QString &dst)
{
    if (m_migrateProc) {
        // A migration is already running; ignore.
        return;
    }

    QString cli = cliExecutablePath();
    if (cli.isEmpty()) {
        QVariantMap r;
        r["error"] = "CLI executable not available. Deploy CloudRedirect first.";
        emit migrationFinished(r);
        return;
    }

    // Reset accumulators.
    m_migrateSrc = src;
    m_migrateDst = dst;
    m_migrateBuf.clear();
    m_migrateCancelled = false;
    m_migMigrated = m_migSkipped = m_migFailed = m_migDone = m_migTotal = 0;
    m_migTotalBytes = 0;
    m_migCompleted = false;
    m_migError.clear();
    m_migLastError.clear();

    auto *proc = new QProcess(this);
    m_migrateProc = proc;
    proc->setProcessChannelMode(QProcess::SeparateChannels);

    connect(proc, &QProcess::readyReadStandardOutput, this, [this, proc]() {
        if (proc != m_migrateProc) return;
        m_migrateBuf += proc->readAllStandardOutput();
        int nl;
        while ((nl = m_migrateBuf.indexOf('\n')) >= 0) {
            QByteArray line = m_migrateBuf.left(nl);
            m_migrateBuf.remove(0, nl + 1);
            if (!line.trimmed().isEmpty())
                handleMigrationLine(line);
        }
    });

    connect(proc, &QProcess::errorOccurred, this, [this, proc](QProcess::ProcessError) {
        if (proc != m_migrateProc) return;
        if (m_migError.isEmpty() && !m_migrateCancelled)
            m_migError = "Failed to launch CLI: " + proc->errorString();
    });

    connect(proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, [this, proc, dst](int exitCode, QProcess::ExitStatus) {
        if (proc != m_migrateProc) return;
        m_migrateProc = nullptr;

        // Flush any trailing buffered line.
        if (!m_migrateBuf.trimmed().isEmpty())
            handleMigrationLine(m_migrateBuf);
        m_migrateBuf.clear();

        // A nonzero exit with a "complete" line is partial success (some files
        // failed) -- NOT fatal. Only surface stderr as a hard error when the
        // run never completed and no error was streamed.
        if (exitCode != 0 && !m_migCompleted && m_migError.isEmpty() && !m_migrateCancelled) {
            QString err = QString::fromUtf8(proc->readAllStandardError()).trimmed();
            m_migError = err.isEmpty() ? ("CLI exited with code " + QString::number(exitCode)) : err;
        }
        proc->deleteLater();

        QVariantMap r;
        r["migrated"]   = m_migMigrated;
        r["skipped"]    = m_migSkipped;
        r["failed"]     = m_migFailed;
        r["totalBytes"] = m_migTotalBytes;
        r["completed"]  = m_migCompleted;
        r["cancelled"]  = m_migrateCancelled;
        r["error"]      = m_migError;
        r["lastError"]  = m_migLastError;

        // Switch to the destination provider once any data moved.
        bool switched = false;
        if (!m_migrateCancelled && m_migError.isEmpty() &&
            (m_migMigrated > 0 || m_migSkipped > 0)) {
            switched = switchActiveProvider(dst);
        }
        r["switched"] = switched;

        emit migrationFinished(r);
    });

    QString migProg;
    QStringList migArgs;
    cliLaunch(cli, {"migrate", src, dst}, migProg, migArgs);
    proc->start(migProg, migArgs);
}

void Backend::handleMigrationLine(const QByteArray &line)
{
    QJsonParseError perr;
    QJsonDocument doc = QJsonDocument::fromJson(line, &perr);
    if (perr.error != QJsonParseError::NoError || !doc.isObject())
        return;
    QJsonObject o = doc.object();
    const QString type = o.value("type").toString();

    if (type == "status") {
        emit migrationStatus(
            o.value("message").toString(),
            o.contains("done")  ? o.value("done").toInt()  : -1,
            o.contains("total") ? o.value("total").toInt() : -1,
            o.contains("found") ? o.value("found").toInt() : -1);
    } else if (type == "start") {
        m_migTotal = o.value("total").toInt();
        emit migrationStarted(m_migTotal);
    } else if (type == "progress" || type == "skip" ||
               (type == "error" && o.contains("file"))) {
        // Per-file line; use the CLI's monotonic "done" counter directly.
        if (o.contains("done"))
            m_migDone = o.value("done").toInt();
        if (type == "progress") {
            m_migMigrated++;
            m_migTotalBytes += static_cast<qint64>(o.value("bytes").toDouble());
        } else if (type == "skip") {
            m_migSkipped++;
        } else {  // per-file error
            m_migFailed++;
            m_migLastError = o.value("message").toString("Unknown error");
        }
        emit migrationProgress(m_migDone, m_migTotal, o.value("file").toString(), m_migTotalBytes);
    } else if (type == "error") {
        // No "file" field -> fatal error.
        m_migError = o.value("message").toString("Unknown error");
    } else if (type == "complete") {
        // Authoritative final tally from the CLI overrides the running counts.
        m_migMigrated  = o.value("migrated").toInt(m_migMigrated);
        m_migSkipped   = o.value("skipped").toInt(m_migSkipped);
        m_migFailed    = o.value("failed").toInt(m_migFailed);
        m_migTotalBytes= static_cast<qint64>(o.value("total_bytes").toDouble());
        m_migCompleted = true;
    }
}

void Backend::cancelMigration()
{
    m_migrateCancelled = true;
    if (m_scanProc) {
        m_scanProc->disconnect(this);
        m_scanProc->kill();
        m_scanProc->deleteLater();
        m_scanProc = nullptr;
        emit migrationScanFinished(QVariantList(), QString());
    }
    if (m_migrateProc) {
        // Kill promptly so in-flight API calls die.
        m_migrateProc->kill();
    }
}

// Write provider + token_path into config.json, preserving unknown keys.
bool Backend::switchActiveProvider(const QString &provider)
{
    QString tokenPath = resolveTokenPath(provider);
    if (tokenPath.isEmpty())
        return false;

    const QString configPath = crConfigDir() + "/config.json";
    QJsonObject cfg;
    QFile cf(configPath);
    if (cf.open(QIODevice::ReadOnly)) {
        QJsonDocument d = QJsonDocument::fromJson(cf.readAll());
        cf.close();
        if (d.isObject())
            cfg = d.object();
    }
    cfg["provider"]   = provider;
    cfg["token_path"] = tokenPath;

    // Register in token_paths so the resolver survives later switches.
    QJsonObject tokenPaths = cfg.value("token_paths").toObject();
    tokenPaths[provider] = tokenPath;
    cfg["token_paths"] = tokenPaths;

    QDir().mkpath(crConfigDir());
    const QByteArray data = QJsonDocument(cfg).toJson();
    const QString tempPath = configPath + ".tmp";
    QFile w(tempPath);
    if (!w.open(QIODevice::WriteOnly))
        return false;
    w.write(data);
    w.close();
    if (!QFile::rename(tempPath, configPath)) {
        QFile::remove(configPath);
        if (!QFile::rename(tempPath, configPath)) {
            QFile::remove(tempPath);
            return false;
        }
    }

    // Reflect in the in-memory state + notify QML bindings.
    m_providerName = provider;
    m_providerPath = tokenPath;
    emit settingsChanged();
    return true;
}

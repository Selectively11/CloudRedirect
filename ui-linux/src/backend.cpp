#include "backend.h"
#include "proton_auth.h"
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
#include <unistd.h>

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
    return QDir::cleanPath(realHomePath() + "/.config/CloudRedirect/backups/" + accountId);
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

    m_storagePath = home + "/.config/CloudRedirect/storage";

    m_deployed = false;
    QString crPath = home + "/.local/share/CloudRedirect/cloud_redirect.so";
    m_deployed = QFile::exists(crPath);

    // Parse account ID from loginusers.vdf
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
            }
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
        home + "/.config/SLSsteam/config.yaml",
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
    QString configPath = realHomePath() + "/.config/CloudRedirect/config.json";
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
    fprintf(stderr, "[Backend] loadConfig: provider=%s syncFolder=%s notifications=%s\n",
        m_providerName.toUtf8().constData(), m_syncFolderPath.toUtf8().constData(),
        m_notificationsEnabled ? "true" : "false");

    m_providerAuthenticated = false;
    if (m_providerName == "gdrive" || m_providerName == "onedrive" || m_providerName == "proton") {
        QString tokenPath = defaultTokenPath(m_providerName);
        if (QFile::exists(tokenPath)) {
            m_providerAuthenticated = true;
        }
    } else if (m_providerName == "folder" && !m_syncFolderPath.isEmpty()) {
        m_providerAuthenticated = QDir(m_syncFolderPath).exists();
    }

    // Load store cache (names and header URLs)
    QString cachePath = realHomePath() + "/.config/CloudRedirect/store_cache.json";
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
    QString configDir = realHomePath() + "/.config/CloudRedirect";
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
    QString backupRoot = realHomePath() + "/.config/CloudRedirect/backups/" + m_accountId;
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
        QString cachePath = realHomePath() + "/.config/CloudRedirect/store_cache.json";
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
    return realHomePath() + "/.config/CloudRedirect/tokens_" + provider + ".json";
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
    QString logPath = realHomePath() + "/.config/CloudRedirect/cloud_redirect.log";
    if (QFile::exists(logPath)) {
        QDesktopServices::openUrl(QUrl::fromLocalFile(logPath));
    }
}

void Backend::openConfigFolder()
{
    QString configPath = realHomePath() + "/.config/CloudRedirect";
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
    if (m_providerName != "gdrive" && m_providerName != "onedrive" && m_providerName != "proton") {
        fprintf(stderr, "[Backend] provider is not gdrive/onedrive/proton, skipping\n");
        emit remoteAppsFetched();
        return;
    }

    if (m_providerName == "proton") {
        fetchProtonDriveApps();
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

void Backend::fetchProtonDriveApps()
{
    auto *auth = new ProtonAuthService(this);
    connect(auth, &ProtonAuthService::remoteAppsListed, this,
            [this, auth](const QList<uint32_t> &appIds) {
                auth->deleteLater();
                m_remoteAppIds.clear();
                for (uint32_t id : appIds) {
                    if (id > 0 && !kHiddenAppIds.contains(id))
                        m_remoteAppIds.insert(id);
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
                fprintf(stderr, "[Backend] Proton remote apps: %d remote IDs, %d total apps\n",
                        (int)m_remoteAppIds.size(), (int)m_apps.size());
                emit appsChanged();
                emit remoteAppsFetched();
                QTimer::singleShot(0, this, &Backend::resolveAppNames);
            });
    connect(auth, &ProtonAuthService::failed, this,
            [this, auth](const QString &err) {
                fprintf(stderr, "[Backend] Proton remote listing failed: %s\n",
                        err.toUtf8().constData());
                auth->deleteLater();
                emit remoteAppsFetched();
            });
    auth->listRemoteApps(defaultTokenPath("proton"), m_accountId);
}

void Backend::deleteCloudAppData(uint appId)
{
    if (m_providerName == "proton") {
        fprintf(stderr, "[Backend] Proton Drive delete not yet implemented\n");
        return;
    }

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

bool Backend::isProviderAuthenticated(const QString &provider) const
{
    // OAuth-based providers only - "folder" and "local" don't use OAuth
    if (provider == "local" || provider == "folder")
        return false;
    
    QString tokenPath = defaultTokenPath(provider);
    return QFile::exists(tokenPath);
}

bool Backend::shouldOfferAutoUpdates() const
{
    // Only relevant inside a Flatpak
    if (!QFile::exists("/.flatpak-info"))
        return false;

    if (!flatpakRepoDescriptorHasGpgKey())
        return false;

    // Check if user already dismissed
    QString configPath = realHomePath() + "/.config/CloudRedirect/config.json";
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
    QString configPath = realHomePath() + "/.config/CloudRedirect/config.json";
    QJsonObject obj;

    QFile f(configPath);
    if (f.open(QIODevice::ReadOnly)) {
        QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
        f.close();
        if (doc.isObject()) obj = doc.object();
    }

    obj["auto_update_prompted"] = true;

    QDir().mkpath(realHomePath() + "/.config/CloudRedirect");
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

    QString updates = runFlatpakHostCommand({"remote-ls", "--user", "--updates", "--app", "cloudredirect"});
    if (updates.contains("org.cloudredirect.CloudRedirect")) {
        emit flatpakUpdateAvailable();
    }
}

void Backend::applyFlatpakUpdate()
{
    QString output = runFlatpakHostCommand({"update", "--user", "-y", "org.cloudredirect.CloudRedirect"}, 120000);
    bool ok = (output.contains("org.cloudredirect.CloudRedirect") && !output.contains("error:"));
    emit flatpakUpdateCompleted(ok);
}

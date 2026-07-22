#pragma once
#include <QObject>
#include <QString>
#include <QStringList>
#include <QVariantList>
#include <QVariantMap>
#include <QNetworkAccessManager>
#include <QSet>

class QProcess;

class Backend : public QObject
{
    Q_OBJECT

    Q_PROPERTY(int managedAppCount READ managedAppCount NOTIFY appsChanged)
    Q_PROPERTY(int remoteOnlyAppCount READ remoteOnlyAppCount NOTIFY appsChanged)
    Q_PROPERTY(QString steamPath READ steamPath NOTIFY statusChanged)
    Q_PROPERTY(QString storagePath READ storagePath NOTIFY statusChanged)
    Q_PROPERTY(bool deployed READ isDeployed NOTIFY statusChanged)
    Q_PROPERTY(QString providerName READ providerName WRITE setProviderName NOTIFY settingsChanged)
    Q_PROPERTY(QString providerPath READ providerPath WRITE setProviderPath NOTIFY settingsChanged)
    Q_PROPERTY(QString syncFolderPath READ syncFolderPath WRITE setSyncFolderPath NOTIFY settingsChanged)
    Q_PROPERTY(bool providerAuthenticated READ providerAuthenticated NOTIFY settingsChanged)
    Q_PROPERTY(bool notificationsEnabled READ notificationsEnabled WRITE setNotificationsEnabled NOTIFY settingsChanged)
    Q_PROPERTY(bool statsSyncEnabled READ statsSyncEnabled WRITE setStatsSyncEnabled NOTIFY settingsChanged)

    Q_PROPERTY(bool syncPlaytime READ syncPlaytime WRITE setSyncPlaytime NOTIFY settingsChanged)
    Q_PROPERTY(QString accountId READ accountId NOTIFY statusChanged)
    Q_PROPERTY(QString accountName READ accountName NOTIFY statusChanged)
    Q_PROPERTY(QString version READ version CONSTANT)

public:
    explicit Backend(QObject *parent = nullptr);

    int managedAppCount() const;
    int remoteOnlyAppCount() const;
    QString steamPath() const;
    QString storagePath() const;
    bool isDeployed() const;
    QString accountId() const;
    QString accountName() const;
    QString version() const;

    QString providerName() const;
    void setProviderName(const QString &name);
    QString providerPath() const;
    void setProviderPath(const QString &path);
    QString syncFolderPath() const;
    void setSyncFolderPath(const QString &path);
    bool providerAuthenticated() const;
    bool notificationsEnabled() const;
    void setNotificationsEnabled(bool enabled);
    bool statsSyncEnabled() const;
    void setStatsSyncEnabled(bool enabled);

    bool syncPlaytime() const;
    void setSyncPlaytime(bool enabled);

    Q_INVOKABLE QVariantList getManagedApps();
    Q_INVOKABLE QVariantList getAppDetails();
    Q_INVOKABLE void deleteAppData(uint appId);
    Q_INVOKABLE void resolveAppNames();
    Q_INVOKABLE void refreshStatus();
    Q_INVOKABLE void saveConfig();
    Q_INVOKABLE void startOAuth(const QString &provider);
    Q_INVOKABLE QString defaultTokenPath(const QString &provider) const;
    Q_INVOKABLE void openLogFile();
    Q_INVOKABLE void openConfigFolder();
    Q_INVOKABLE QString formatSize(qint64 bytes) const;
    Q_INVOKABLE QVariantList scanOrphans();
    Q_INVOKABLE void fetchRemoteApps();
    Q_INVOKABLE QVariantList listBackups();
    Q_INVOKABLE QString restoreBackup(const QString &backupPath);
    Q_INVOKABLE void deleteBackup(const QString &backupPath);
    Q_INVOKABLE QString getAppName(uint appId) const;
    Q_INVOKABLE QString getAppHeaderUrl(uint appId) const;
    Q_INVOKABLE bool isProviderAuthenticated(const QString &provider) const;

    Q_INVOKABLE QString r2CredentialPath() const;
    Q_INVOKABLE QVariantMap getR2Credentials() const;
    Q_INVOKABLE bool saveR2Credentials(const QString &accountId,
                                       const QString &accessKeyId,
                                       const QString &secretAccessKey,
                                       const QString &bucket,
                                       const QString &keyPrefix,
                                       const QString &endpoint);

    Q_INVOKABLE QString s3CredentialPath() const;
    Q_INVOKABLE QVariantMap getS3Credentials() const;
    Q_INVOKABLE bool saveS3Credentials(const QString &accessKeyId,
                                       const QString &secretAccessKey,
                                       const QString &bucket,
                                       const QString &endpoint,
                                       const QString &region,
                                       const QString &keyPrefix,
                                       bool signPayload,
                                       bool allowInsecureHttp,
                                       bool allowInsecureTls,
                                       const QString &caCertPath);
    Q_INVOKABLE bool shouldOfferAutoUpdates() const;
    Q_INVOKABLE void enableAutoUpdates();
    Q_INVOKABLE void dismissAutoUpdatePrompt();
    Q_INVOKABLE void checkForFlatpakUpdate();
    Q_INVOKABLE void applyFlatpakUpdate();

    // The provider currently active in config.json (empty if none/local).
    Q_INVOKABLE QString activeProvider() const;
    // Human-readable label for a provider key ("gdrive" -> "Google Drive").
    Q_INVOKABLE QString providerLabel(const QString &provider) const;
    // Pre-flight check that <provider>'s credential file exists and is non-empty.
    Q_INVOKABLE QVariantMap checkProviderCredentials(const QString &provider) const;
    // Scans a provider's cloud storage via `cli scan-all`.
    Q_INVOKABLE void scanProvider(const QString &provider);
    // Verifies a provider can reach its bucket. Emits providerTestFinished.
    Q_INVOKABLE void testProviderConnection(const QString &provider);
    // Runs `cli migrate <src> <dst>`, streaming NDJSON progress.
    Q_INVOKABLE void startMigration(const QString &src, const QString &dst);
    // Cancels an in-flight scan or migration.
    Q_INVOKABLE void cancelMigration();

signals:
    void statusChanged();
    void appsChanged();
    void settingsChanged();
    void appNamesResolved();
    void remoteAppsFetched();
    void packageAppsResolved();
    void flatpakUpdateAvailable();
    void flatpakUpdateCompleted(bool success);

    void migrationScanStarted();
    void migrationScanFinished(const QVariantList &apps, const QString &error);
    // Pre-enumeration phase; numeric fields are -1 when unknown.
    void migrationStatus(const QString &message, int done, int total, int found);
    void migrationStarted(int total);
    void migrationProgress(int done, int total, const QString &file, qint64 totalBytes);
    // Terminal; result carries the migrated/skipped/failed tallies and status.
    void migrationFinished(const QVariantMap &result);

    void providerTestFinished(const QString &provider, bool ok, const QString &error);

private:
    QString resolveTokenPath(const QString &provider) const;
    QString cliExecutablePath() const;
    void cliLaunch(const QString &cliPath, const QStringList &cliArgs,
                   QString &program, QStringList &args) const;
    bool switchActiveProvider(const QString &provider);
    void handleMigrationLine(const QByteArray &line);
    void loadConfig();
    void loadSLSsteamApps();
    void resolvePackageApps();
    void detectSteamPath();
    void scanStorageForApps();
    QString getAccountId() const;
    QString readAccessToken() const;
    void fetchGoogleDriveApps(const QString &token);
    void fetchOneDriveApps(const QString &token);
    void fetchCliRemoteApps(const QString &provider);
    void refreshAndFetch();
    void deleteCloudAppData(uint appId);
    void deleteGoogleDriveAppData(uint appId, const QString &token);
    void deleteOneDriveAppData(uint appId, const QString &token);
    void listAndDeleteOneDriveFiles(const QString &folderId, const QString &token, uint appId);
    void deleteOneDriveItem(const QString &itemId, const QString &token, uint appId);

    QNetworkAccessManager *m_nam = nullptr;
    QString m_steamPath;
    QString m_storagePath;
    QString m_accountId;
    QString m_accountName;
    bool m_deployed = false;

    QString m_providerName = "local";
    QString m_providerPath;
    QString m_syncFolderPath;
    bool m_providerAuthenticated = false;
    bool m_notificationsEnabled = true;
    // Stats sync -- master switch for playtime sync (achievement schema is
    // handled by SLSsteam, not by CR).
    bool m_statsSyncEnabled = true;
    bool m_syncPlaytime = false;

    struct AppInfo {
        uint32_t appId;
        QString name;
        QString headerUrl;
        QString saveRoot;  // e.g., %WinAppDataLocalLow%
        int fileCount = 0;
        qint64 totalSize = 0;
        bool isLocal = true;   // exists in local storage
        bool isRemote = false; // exists in cloud storage
    };
    QList<AppInfo> m_apps;
    QSet<uint32_t> m_remoteAppIds;  // app IDs found in cloud
    QList<uint32_t> m_pendingPackages;  // package IDs to resolve
    QMap<uint32_t, QString> m_nameCache;
    QMap<uint32_t, QString> m_headerCache;

    QProcess *m_scanProc = nullptr;       // in-flight `scan-all`
    QProcess *m_migrateProc = nullptr;    // in-flight `migrate`
    QProcess *m_testProc = nullptr;       // in-flight connection test
    QByteArray m_migrateBuf;              // partial NDJSON line buffer
    QString m_migrateSrc;
    QString m_migrateDst;
    bool m_migrateCancelled = false;
    // Accumulated result across the stream.
    int m_migMigrated = 0;
    int m_migSkipped = 0;
    int m_migFailed = 0;
    int m_migDone = 0;      // CLI's authoritative processed-file counter
    int m_migTotal = 0;
    qint64 m_migTotalBytes = 0;
    bool m_migCompleted = false;
    QString m_migError;
    QString m_migLastError;
};

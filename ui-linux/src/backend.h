#pragma once
#include <QObject>
#include <QString>
#include <QStringList>
#include <QVariantList>
#include <QVariantMap>
#include <QNetworkAccessManager>
#include <QSet>

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
    Q_INVOKABLE bool shouldOfferAutoUpdates() const;
    Q_INVOKABLE void enableAutoUpdates();
    Q_INVOKABLE void dismissAutoUpdatePrompt();
    Q_INVOKABLE void checkForFlatpakUpdate();
    Q_INVOKABLE void applyFlatpakUpdate();

signals:
    void statusChanged();
    void appsChanged();
    void settingsChanged();
    void appNamesResolved();
    void remoteAppsFetched();
    void packageAppsResolved();
    void flatpakUpdateAvailable();
    void flatpakUpdateCompleted(bool success);

private:
    void loadConfig();
    void loadSLSsteamApps();
    void resolvePackageApps();
    void detectSteamPath();
    void scanStorageForApps();
    QString getAccountId() const;
    QString readAccessToken() const;
    void fetchGoogleDriveApps(const QString &token);
    void fetchOneDriveApps(const QString &token);
    void fetchProtonDriveApps();
    void deleteProtonDriveAppData(uint appId);
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
};

#pragma once
#include <QObject>
#include <QString>
#include <QStringList>

class Deployer : public QObject
{
    Q_OBJECT

    Q_PROPERTY(bool slssteamInstalled READ slssteamInstalled NOTIFY checkCompleted)
    Q_PROPERTY(bool headcrabInstalled READ headcrabInstalled NOTIFY checkCompleted)
    Q_PROPERTY(bool alreadyDeployed READ alreadyDeployed NOTIFY checkCompleted)
    Q_PROPERTY(bool updateAvailable READ updateAvailable NOTIFY checkCompleted)
    Q_PROPERTY(bool slsCloudBlocked READ slsCloudBlocked NOTIFY checkCompleted)
    Q_PROPERTY(QString statusMessage READ statusMessage NOTIFY statusMessageChanged)
    Q_PROPERTY(QString bundledVersion READ bundledVersion NOTIFY checkCompleted)
    Q_PROPERTY(QString deployedVersion READ deployedVersion NOTIFY checkCompleted)

public:
    explicit Deployer(QObject *parent = nullptr);

    bool slssteamInstalled() const;
    bool headcrabInstalled() const;
    bool alreadyDeployed() const;
    bool updateAvailable() const;
    bool slsCloudBlocked() const;
    QString statusMessage() const;
    QString bundledVersion() const;
    QString deployedVersion() const;

    Q_INVOKABLE void checkPrerequisites();
    Q_INVOKABLE bool deploy();
    Q_INVOKABLE bool undeploy();
    Q_INVOKABLE bool update();
    Q_INVOKABLE bool purgeAll();

signals:
    void checkCompleted();
    void statusMessageChanged();
    void deployCompleted(bool success);

private:
    bool m_slssteamInstalled = false;
    bool m_headcrabInstalled = false;
    bool m_alreadyDeployed = false;
    bool m_updateAvailable = false;
    bool m_slsCloudBlocked = true;
    QString m_statusMessage;
    QString m_soSourcePath;
    QString m_soDeployPath;
    QString m_cliSourcePath;
    QString m_cliDeployPath;
    QString m_bundledVersion;
    QString m_deployedVersion;
};

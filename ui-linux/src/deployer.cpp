#include "deployer.h"
#include "utils.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QCoreApplication>
#include <QTextStream>
#include <QProcessEnvironment>
#include <QSaveFile>
#include <QCryptographicHash>
#include <unistd.h>

#define ELF_MAGIC 0x464C457F
#define ELFCLASS32 1
#define ELFCLASS64 2

static QString getSoVersion(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return QString();

    QByteArray data = f.readAll();
    f.close();

    const char* p = data.constData();
    const char* end = p + data.size() - 20;
    
    for (; p < end; ++p) {
        if (p[0] >= '0' && p[0] <= '9' &&
            p[1] == '.' &&
            p[2] >= '0' && p[2] <= '9' &&
            p[3] == '.' &&
            p[4] >= '0' && p[4] <= '9' &&
            p[5] == '+') {
            const char* start = p;
            const char* q = p + 6;
            int hexCount = 0;
            while (q < data.constData() + data.size() && 
                   ((*q >= '0' && *q <= '9') || (*q >= 'a' && *q <= 'f'))) {
                ++hexCount;
                ++q;
            }
            if (hexCount == 7) {
                if (q + 6 <= data.constData() + data.size() && 
                    strncmp(q, "-dirty", 6) == 0) {
                    q += 6;
                }
                return QString::fromLatin1(start, q - start);
            }
            if (strncmp(p + 6, "unknown", 7) == 0) {
                return QString::fromLatin1(start, 13);
            }
        }
    }

    return QString();
}

static bool isElf32Bit(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return false;
    
    unsigned char header[5];
    if (f.read(reinterpret_cast<char*>(header), 5) != 5)
        return false;
    
    if (header[0] != 0x7F || header[1] != 'E' || header[2] != 'L' || header[3] != 'F')
        return false;
    
    return header[4] == ELFCLASS32;
}

Deployer::Deployer(QObject *parent)
    : QObject(parent)
{
    checkPrerequisites();
}

bool Deployer::slssteamInstalled() const { return m_slssteamInstalled; }
bool Deployer::headcrabInstalled() const { return m_headcrabInstalled; }
bool Deployer::alreadyDeployed() const { return m_alreadyDeployed; }
bool Deployer::updateAvailable() const { return m_updateAvailable; }
bool Deployer::slsCloudBlocked() const { return m_slsCloudBlocked; }
QString Deployer::statusMessage() const { return m_statusMessage; }
QString Deployer::bundledVersion() const { return m_bundledVersion; }
QString Deployer::deployedVersion() const { return m_deployedVersion; }

void Deployer::checkPrerequisites()
{
    QString home = realHomePath();

    QString slsDir = home + "/.local/share/SLSsteam";
    m_slssteamInstalled = QFile::exists(slsDir + "/SLSsteam.so");

    m_slsCloudBlocked = true;
    if (m_slssteamInstalled) {
        QStringList configPaths = {
            home + "/.config/SLSsteam/config.yaml",
            home + "/.var/app/com.valvesoftware.Steam/.config/SLSsteam/config.yaml",
        };
        for (const auto &configPath : configPaths) {
            QFile f(configPath);
            if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
                continue;
            QTextStream in(&f);
            while (!in.atEnd()) {
                QString line = in.readLine();
                QString trimmed = line.trimmed();
                if (trimmed.startsWith("DisableCloud")) {
                    int colonIdx = trimmed.indexOf(':');
                    if (colonIdx >= 0) {
                        QString value = trimmed.mid(colonIdx + 1).trimmed();
                        int commentIdx = value.indexOf('#');
                        if (commentIdx >= 0) value = value.left(commentIdx).trimmed();
                        if (value.compare("no", Qt::CaseInsensitive) == 0 ||
                            value.compare("false", Qt::CaseInsensitive) == 0 ||
                            value == "0") {
                            m_slsCloudBlocked = false;
                        }
                    }
                    break;
                }
            }
            f.close();
            break;
        }
    }

    QString crDir = home + "/.local/share/CloudRedirect";
    m_soDeployPath = crDir + "/cloud_redirect.so";
    m_cliDeployPath = crDir + "/cloud_redirect_cli";

    QString appDir = QCoreApplication::applicationDirPath();
    QString bundledSo = QProcessEnvironment::systemEnvironment().value("CR_BUNDLED_SO");
    QString bundledCli = QProcessEnvironment::systemEnvironment().value("CR_BUNDLED_CLI");

    if (!bundledSo.isEmpty() && QFile::exists(bundledSo))
        m_soSourcePath = bundledSo;
    else if (QFile::exists(appDir + "/cloud_redirect.so"))
        m_soSourcePath = appDir + "/cloud_redirect.so";
    else if (QFile::exists("/app/share/cloud_redirect/cloud_redirect.so"))
        m_soSourcePath = "/app/share/cloud_redirect/cloud_redirect.so";
    else if (QFile::exists(home + "/.local/share/cloud_redirect/cloud_redirect.so"))
        m_soSourcePath = home + "/.local/share/cloud_redirect/cloud_redirect.so";

    if (!bundledCli.isEmpty() && QFile::exists(bundledCli))
        m_cliSourcePath = bundledCli;
    else if (QFile::exists(appDir + "/cloud_redirect_cli"))
        m_cliSourcePath = appDir + "/cloud_redirect_cli";
    else if (QFile::exists("/app/share/cloud_redirect/cloud_redirect_cli"))
        m_cliSourcePath = "/app/share/cloud_redirect/cloud_redirect_cli";
    else if (QFile::exists(home + "/.local/share/cloud_redirect/cloud_redirect_cli"))
        m_cliSourcePath = home + "/.local/share/cloud_redirect/cloud_redirect_cli";

    m_alreadyDeployed = QFile::exists(m_soDeployPath);

    m_headcrabInstalled = false;
    QString steamSh;
    QString shPath1 = home + "/.local/share/Steam/steam.sh";
    QString shPath2 = home + "/.steam/steam/steam.sh";
    QString shPath3 = home + "/.var/app/com.valvesoftware.Steam/.local/share/Steam/steam.sh";
    if (QFile::exists(shPath1))
        steamSh = shPath1;
    else if (QFile::exists(shPath2))
        steamSh = shPath2;
    else if (QFile::exists(shPath3))
        steamSh = shPath3;

    if (!steamSh.isEmpty()) {
        QFile f(steamSh);
        if (f.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QString content = f.readAll();
            f.close();
            if (content.contains("LD_AUDIT") && content.contains("SLSsteam.so"))
                m_headcrabInstalled = true;
        }
    }

    m_updateAvailable = false;
    m_bundledVersion = getSoVersion(m_soSourcePath);
    m_deployedVersion = getSoVersion(m_soDeployPath);
    
    if (m_alreadyDeployed && !m_soSourcePath.isEmpty()) {
        if (!QFile::exists(m_soDeployPath)) {
            m_updateAvailable = true;
        } else if (m_bundledVersion.isEmpty() || m_deployedVersion.isEmpty()) {
            QFile srcFile(m_soSourcePath);
            QFile dstFile(m_soDeployPath);
            if (srcFile.open(QIODevice::ReadOnly) && dstFile.open(QIODevice::ReadOnly)) {
                QByteArray srcHash = QCryptographicHash::hash(srcFile.readAll(), QCryptographicHash::Sha256);
                QByteArray dstHash = QCryptographicHash::hash(dstFile.readAll(), QCryptographicHash::Sha256);
                if (srcHash != dstHash)
                    m_updateAvailable = true;
            }
        } else if (m_bundledVersion != m_deployedVersion) {
            m_updateAvailable = true;
        }
    }

    if (!m_slssteamInstalled) {
        m_statusMessage = "SLSsteam is not installed. Please install SLSsteam first.";
    } else if (!m_headcrabInstalled) {
        m_statusMessage = "h3adcr-b not installed. Did you run h3adcr-b first?";
    } else if (m_updateAvailable) {
        m_statusMessage = "Update available. A newer version is bundled with this app.";
    } else if (m_alreadyDeployed) {
        m_statusMessage = "CloudRedirect is deployed and active.";
    } else if (m_soSourcePath.isEmpty()) {
        m_statusMessage = "cloud_redirect.so not found. Installation may be corrupted.";
    } else {
        m_statusMessage = "Ready to deploy.";
    }

    emit checkCompleted();
    emit statusMessageChanged();
}

bool Deployer::deploy()
{
    if (!m_slssteamInstalled) {
        m_statusMessage = "Cannot deploy: SLSsteam is not installed.";
        emit statusMessageChanged();
        emit deployCompleted(false);
        return false;
    }

    if (!m_headcrabInstalled) {
        m_statusMessage = "Failed to deploy. Did you run h3adcr-b first?";
        emit statusMessageChanged();
        emit deployCompleted(false);
        return false;
    }

    if (m_soSourcePath.isEmpty()) {
        m_statusMessage = "Cannot deploy: cloud_redirect.so not found. Installation may be corrupted.";
        emit statusMessageChanged();
        emit deployCompleted(false);
        return false;
    }

    if (!isElf32Bit(m_soSourcePath)) {
        m_statusMessage = "Cannot deploy: cloud_redirect.so is not 32-bit, your compile is bad.";
        emit statusMessageChanged();
        emit deployCompleted(false);
        return false;
    }

    QString crDir = realHomePath() + "/.local/share/CloudRedirect";
    QDir().mkpath(crDir);

    if (QFile::exists(m_soDeployPath)) {
        if (!QFile::remove(m_soDeployPath)) {
            m_statusMessage = "Failed to remove existing " + m_soDeployPath + " (file may be in use by Steam)";
            emit statusMessageChanged();
            emit deployCompleted(false);
            return false;
        }
    }

    if (!QFile::copy(m_soSourcePath, m_soDeployPath)) {
        m_statusMessage = "Failed to copy cloud_redirect.so to " + m_soDeployPath;
        emit statusMessageChanged();
        emit deployCompleted(false);
        return false;
    }

    QFile::setPermissions(m_soDeployPath,
        QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner |
        QFileDevice::ReadGroup | QFileDevice::ExeGroup |
        QFileDevice::ReadOther | QFileDevice::ExeOther);

    if (!m_cliSourcePath.isEmpty()) {
        if (QFile::exists(m_cliDeployPath))
            QFile::remove(m_cliDeployPath);

        if (!QFile::copy(m_cliSourcePath, m_cliDeployPath)) {
            qWarning("Failed to copy cloud_redirect_cli to %s", qPrintable(m_cliDeployPath));
        } else {
            QFile::setPermissions(m_cliDeployPath,
                QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner |
                QFileDevice::ReadGroup | QFileDevice::ExeGroup |
                QFileDevice::ReadOther | QFileDevice::ExeOther);
        }
    }

    QString configDir = realHomePath() + "/.config/CloudRedirect";
    QDir().mkpath(configDir);

    m_alreadyDeployed = true;
    m_statusMessage = "CloudRedirect deployed to " + crDir + ". Restart Steam to activate.";
    emit statusMessageChanged();
    emit checkCompleted();
    emit deployCompleted(true);
    return true;
}

bool Deployer::update()
{
    if (m_soSourcePath.isEmpty()) {
        m_statusMessage = "No bundled .so found to update from.";
        emit statusMessageChanged();
        return false;
    }

    if (!isElf32Bit(m_soSourcePath)) {
        m_statusMessage = "Cannot update: cloud_redirect.so is not 32-bit, your compile is bad.";
        emit statusMessageChanged();
        return false;
    }

    QString crDir = realHomePath() + "/.local/share/CloudRedirect";
    QDir().mkpath(crDir);

    if (QFile::exists(m_soDeployPath)) {
        if (!QFile::remove(m_soDeployPath)) {
            m_statusMessage = "Cannot update: existing cloud_redirect.so is in use. Close Steam first.";
            emit statusMessageChanged();
            return false;
        }
    }

    if (!QFile::copy(m_soSourcePath, m_soDeployPath)) {
        m_statusMessage = "Failed to update cloud_redirect.so";
        emit statusMessageChanged();
        return false;
    }
    QFile::setPermissions(m_soDeployPath,
        QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner |
        QFileDevice::ReadGroup | QFileDevice::ExeGroup |
        QFileDevice::ReadOther | QFileDevice::ExeOther);

    if (!m_cliSourcePath.isEmpty()) {
        if (QFile::exists(m_cliDeployPath))
            QFile::remove(m_cliDeployPath);
        if (QFile::copy(m_cliSourcePath, m_cliDeployPath)) {
            QFile::setPermissions(m_cliDeployPath,
                QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner |
                QFileDevice::ReadGroup | QFileDevice::ExeGroup |
                QFileDevice::ReadOther | QFileDevice::ExeOther);
        }
    }

    m_updateAvailable = false;
    m_statusMessage = "Updated successfully. Restart Steam to use the new version.";
    emit statusMessageChanged();
    emit checkCompleted();
    return true;
}

bool Deployer::undeploy()
{
    if (QFile::exists(m_soDeployPath))
        QFile::remove(m_soDeployPath);
    if (QFile::exists(m_cliDeployPath))
        QFile::remove(m_cliDeployPath);

    m_alreadyDeployed = false;
    m_statusMessage = "CloudRedirect removed. Restart Steam to deactivate.";
    emit statusMessageChanged();
    emit checkCompleted();
    return true;
}

bool Deployer::purgeAll()
{
    undeploy();

    QString configDir = realHomePath() + "/.config/CloudRedirect";
    QDir configQDir(configDir);
    if (configQDir.exists()) {
        configQDir.removeRecursively();
    }

    QString dataDir = realHomePath() + "/.local/share/CloudRedirect";
    QDir dataQDir(dataDir);
    if (dataQDir.exists()) {
        dataQDir.removeRecursively();
    }

    m_statusMessage = "All CloudRedirect data has been removed.";
    emit statusMessageChanged();
    emit checkCompleted();
    return true;
}

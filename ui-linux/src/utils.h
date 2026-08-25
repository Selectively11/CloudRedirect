#pragma once
#include <QString>
#include <QDir>
#include <QFile>
#include <QStringList>
#include <unistd.h>
#include <cstdlib>

// Real home dir (Flatpak remaps QDir::homePath to the sandbox).
inline QString realHomePath()
{
    if (QFile::exists("/.flatpak-info")) {
        // Try HOST_HOME environment variable first
        const char* hostHome = std::getenv("HOST_HOME");
        if (hostHome && hostHome[0])
            return QString::fromUtf8(hostHome);

        // Parse real home from /etc/passwd
        QFile passwd("/etc/passwd");
        if (passwd.open(QIODevice::ReadOnly | QIODevice::Text)) {
            uid_t uid = getuid();
            while (!passwd.atEnd()) {
                QString line = passwd.readLine();
                QStringList fields = line.split(':');
                if (fields.size() >= 6 && fields[2].toULongLong() == static_cast<qulonglong>(uid))
                    return fields[5];
            }
        }

        // Last resort: strip the .var/app/<app-id> suffix
        QString sandboxHome = QDir::homePath();
        int varAppIdx = sandboxHome.indexOf("/.var/app/");
        if (varAppIdx > 0)
            return sandboxHome.left(varAppIdx);
    }
    return QDir::homePath();
}

inline bool inFlatpak()
{
    static const bool cached = QFile::exists("/.flatpak-info");
    return cached;
}

inline QString xdgConfigHome()
{
    if (!inFlatpak()) {
        const char* xdg = std::getenv("XDG_CONFIG_HOME");
        if (xdg && xdg[0] == '/')
            return QString::fromUtf8(xdg);
    }
    return realHomePath() + "/.config";
}

inline QString xdgDataHome()
{
    if (!inFlatpak()) {
        const char* xdg = std::getenv("XDG_DATA_HOME");
        if (xdg && xdg[0] == '/')
            return QString::fromUtf8(xdg);
    }
    return realHomePath() + "/.local/share";
}

inline QString crConfigDir()
{
    return xdgConfigHome() + "/CloudRedirect";
}

inline QString crDataDir()
{
    return xdgDataHome() + "/CloudRedirect";
}

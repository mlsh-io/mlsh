#pragma once

#include <QObject>
#include <QString>

class QNetworkAccessManager;

/// Polls GitHub Releases for a newer mlsh build (parity with the macOS
/// UpdateChecker). Looks for the Windows installer asset
/// `mlsh-<version>-windows-amd64-setup.exe`.
class UpdateChecker : public QObject
{
    Q_OBJECT
public:
    struct Release {
        QString tag;        // e.g. "v0.2.4"
        QString version;    // e.g. "0.2.4"
        QString htmlUrl;    // release page
        QString assetUrl;   // direct installer download (may be empty)
    };

    explicit UpdateChecker(QObject *parent = nullptr);

    /// Kick off a check. `currentVersion` is the running version (e.g. "0.2.0").
    /// Emits updateAvailable() only if a strictly newer release is found.
    void check(const QString &currentVersion);

    /// Compare two semver-ish strings; true if `remote` > `current`.
    static bool isNewer(const QString &remote, const QString &current);

signals:
    void updateAvailable(const UpdateChecker::Release &release);

private:
    QNetworkAccessManager *m_nam = nullptr;
    QString m_currentVersion;
};

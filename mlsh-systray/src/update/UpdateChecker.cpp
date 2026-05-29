#include "update/UpdateChecker.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QUrl>

namespace {
constexpr char kReleasesUrl[] = "https://api.github.com/repos/mlsh-io/mlsh/releases/latest";
} // namespace

UpdateChecker::UpdateChecker(QObject *parent)
    : QObject(parent)
    , m_nam(new QNetworkAccessManager(this))
{
}

bool UpdateChecker::isNewer(const QString &remote, const QString &current)
{
    // Strip any git-describe suffix ("0.2.0-2-gabc123" → "0.2.0").
    const QString r = remote.section(QLatin1Char('-'), 0, 0);
    const QString c = current.section(QLatin1Char('-'), 0, 0);

    const QStringList rp = r.split(QLatin1Char('.'), Qt::SkipEmptyParts);
    const QStringList cp = c.split(QLatin1Char('.'), Qt::SkipEmptyParts);

    const int n = qMax(rp.size(), cp.size());
    for (int i = 0; i < n; ++i) {
        const int rv = i < rp.size() ? rp.at(i).toInt() : 0;
        const int cv = i < cp.size() ? cp.at(i).toInt() : 0;
        if (rv > cv)
            return true;
        if (rv < cv)
            return false;
    }
    return false;
}

void UpdateChecker::check(const QString &currentVersion)
{
    m_currentVersion = currentVersion;

    QNetworkRequest req{QUrl(QString::fromLatin1(kReleasesUrl))};
    req.setHeader(QNetworkRequest::UserAgentHeader, QStringLiteral("mlsh-systray"));
    req.setRawHeader("Accept", "application/vnd.github+json");
    req.setTransferTimeout(10000);

    QNetworkReply *reply = m_nam->get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        if (reply->error() != QNetworkReply::NoError)
            return;

        const QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        if (!doc.isObject())
            return;
        const QJsonObject obj = doc.object();

        const QString tag = obj.value(QStringLiteral("tag_name")).toString();
        const QString htmlUrl = obj.value(QStringLiteral("html_url")).toString();
        if (tag.isEmpty())
            return;

        const QString remoteVersion =
            tag.startsWith(QLatin1Char('v')) ? tag.mid(1) : tag;
        if (!isNewer(remoteVersion, m_currentVersion))
            return;

        Release rel;
        rel.tag = tag;
        rel.version = remoteVersion;
        rel.htmlUrl = htmlUrl;

        // Find the Windows installer asset.
        const QJsonArray assets = obj.value(QStringLiteral("assets")).toArray();
        for (const QJsonValue &v : assets) {
            const QJsonObject a = v.toObject();
            const QString name = a.value(QStringLiteral("name")).toString();
            if (name.contains(QStringLiteral("windows"), Qt::CaseInsensitive)
                && name.endsWith(QStringLiteral(".exe"), Qt::CaseInsensitive)) {
                rel.assetUrl =
                    a.value(QStringLiteral("browser_download_url")).toString();
                break;
            }
        }

        emit updateAvailable(rel);
    });
}

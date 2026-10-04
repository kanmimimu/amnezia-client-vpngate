#include "vpnGateController.h"

#include <QHostAddress>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QSet>
#include <QUrl>
#include <algorithm>

#include "amneziaApplication.h"
#include "logger.h"

using namespace amnezia;

namespace
{
    Logger logger("VpnGateController");

    const QUrl kServerListUrl(QStringLiteral("https://www.vpngate.net/api/iphone/"));
    constexpr int kRequestTimeoutMsecs = 30000;
    constexpr qint64 kMaxResponseSize = 16 * 1024 * 1024;

    // HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,
    // Operator,Message,OpenVPN_ConfigData_Base64
    enum Column {
        ColHostName,
        ColIp,
        ColScore,
        ColPing,
        ColSpeed,
        ColCountryLong,
        ColCountryShort,
        ColNumVpnSessions,
        ColUptime,
        ColTotalUsers,
        ColTotalTraffic,
        ColLogType,
        ColOperator,
        ColMessage,
        ColConfig,
        ColumnCount
    };

    QString toDisplayText(const QByteArray &raw, int maxLength = 64)
    {
        // These strings are written by volunteers and rendered by QML with auto-detected text format,
        // so drop everything that could be interpreted as markup or used to spoof the text direction.
        static const QRegularExpression unsafeChars(QStringLiteral("[<>&\"\\p{Cc}\\p{Cf}]"));

        QString text = QString::fromUtf8(raw);
        text.remove(unsafeChars);
        return text.trimmed().left(maxLength);
    }

    int toInt(const QByteArray &raw, int fallback)
    {
        bool ok = false;
        const int value = raw.trimmed().toInt(&ok);
        return ok ? value : fallback;
    }

    qint64 toLongLong(const QByteArray &raw, qint64 fallback)
    {
        bool ok = false;
        const qint64 value = raw.trimmed().toLongLong(&ok);
        return ok ? value : fallback;
    }
} // namespace

VpnGateController::VpnGateController(QObject *parent) : QObject(parent)
{
}

void VpnGateController::fetchServers()
{
    if (m_reply) {
        return;
    }

    QNetworkRequest request(kServerListUrl);
    request.setTransferTimeout(kRequestTimeoutMsecs);

    QNetworkReply *reply = amnApp->networkManager()->get(request);
    m_reply = reply;

    // the whole body is buffered in memory, so stop an unexpectedly large response while it is downloaded
    connect(reply, &QNetworkReply::downloadProgress, reply, [reply](qint64 received, qint64) {
        if (received > kMaxResponseSize) {
            logger.error() << "The VPN Gate server list is unexpectedly large:" << received;
            reply->abort();
        }
    });

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        m_reply = nullptr;

        if (reply->error() != QNetworkReply::NoError) {
            logger.error() << "Failed to fetch the VPN Gate server list:" << reply->errorString();
            emit fetchFailed(ErrorCode::VpnGateFetchError);
            return;
        }

        const QVector<VpnGateServer> servers = parseServerList(reply->readAll());
        if (servers.isEmpty()) {
            logger.error() << "The VPN Gate server list does not contain any usable server";
            emit fetchFailed(ErrorCode::VpnGateServerListEmptyError);
            return;
        }

        emit serversFetched(servers);
    });
}

QVector<VpnGateServer> VpnGateController::parseServerList(const QByteArray &csv)
{
    QVector<VpnGateServer> servers;

    const QList<QByteArray> lines = csv.split('\n');
    for (const QByteArray &rawLine : lines) {
        const QByteArray line = rawLine.trimmed();

        // "*vpn_servers" and "*" frame the data, the header row starts with "#"
        if (line.isEmpty() || line.startsWith('*') || line.startsWith('#')) {
            continue;
        }

        // Operator and Message are free text and may contain commas,
        // so only the leading columns and the last one (base64 never contains commas) are trusted by position
        const QList<QByteArray> fields = line.split(',');
        if (fields.size() < ColumnCount) {
            continue;
        }

        VpnGateServer server;

        server.ip = QString::fromLatin1(fields[ColIp]).trimmed();
        const QHostAddress address(server.ip);
        if (address.isNull()) {
            continue;
        }

        server.config = sanitizeOpenVpnConfig(QString::fromUtf8(QByteArray::fromBase64(fields.last())));
        if (server.config.isEmpty()) {
            logger.warning() << "Skipping the VPN Gate server" << server.ip
                             << "because of an unsupported OpenVPN profile";
            continue;
        }

        // the profile must lead to the address that is shown to the user
        static const QRegularExpression remoteRegExp(QStringLiteral("^remote\\s+(\\S+)"),
                                                     QRegularExpression::MultilineOption);
        if (QHostAddress(remoteRegExp.match(server.config).captured(1)) != address) {
            logger.warning() << "Skipping the VPN Gate server" << server.ip << "because its profile points elsewhere";
            continue;
        }

        static const QRegularExpression protoRegExp(QStringLiteral("^proto\\s+(\\S+)"),
                                                    QRegularExpression::MultilineOption);
        const QString proto = protoRegExp.match(server.config).captured(1);
        server.protocol = proto.startsWith(QLatin1String("udp")) ? QStringLiteral("UDP") : QStringLiteral("TCP");

        server.countryName = toDisplayText(fields[ColCountryLong]);
        server.countryCode = toDisplayText(fields[ColCountryShort], 8);
        server.score = toInt(fields[ColScore], 0);
        server.pingMs = toInt(fields[ColPing], -1);
        server.speedBps = toLongLong(fields[ColSpeed], 0);
        server.sessions = toInt(fields[ColNumVpnSessions], 0);
        server.uptimeMs = toLongLong(fields[ColUptime], 0);

        servers.push_back(server);
    }

    std::stable_sort(servers.begin(), servers.end(),
                     [](const VpnGateServer &left, const VpnGateServer &right) { return left.score > right.score; });

    return servers;
}

QString VpnGateController::sanitizeOpenVpnConfig(const QString &config)
{
    static const QSet<QString> allowedDirectives = { "client", "dev",          "proto",       "remote",
                                                     "cipher", "data-ciphers", "auth",        "resolv-retry",
                                                     "nobind", "persist-key",  "persist-tun", "verb" };
    static const QSet<QString> allowedBlocks = { "ca", "cert", "key" };
    static const QRegularExpression whitespace(QStringLiteral("\\s+"));
    static const QRegularExpression argumentRegExp(QStringLiteral("^[A-Za-z0-9._:\\-]+$"));
    static const QRegularExpression pemLineRegExp(QStringLiteral("^[A-Za-z0-9+/=\\- ]*$"));
    constexpr int maxArgumentsCount = 4;

    QStringList result;
    QString openBlock;
    bool hasClient = false;
    bool hasDevTun = false;
    bool hasRemote = false;

    const QStringList lines = config.split('\n');
    for (const QString &rawLine : lines) {
        const QString line = rawLine.trimmed();

        if (!openBlock.isEmpty()) {
            if (line == QStringLiteral("</%1>").arg(openBlock)) {
                openBlock.clear();
            } else if (!pemLineRegExp.match(line).hasMatch()) {
                return { };
            }
            result << line;
            continue;
        }

        if (line.isEmpty() || line.startsWith('#') || line.startsWith(';')) {
            continue;
        }

        if (line.startsWith('<')) {
            const QString tag = line.endsWith('>') ? line.mid(1, line.size() - 2) : QString();
            if (!allowedBlocks.contains(tag)) {
                return { };
            }
            openBlock = tag;
            result << line;
            continue;
        }

        QStringList tokens = line.split(whitespace, Qt::SkipEmptyParts);
        const QString directive = tokens.takeFirst();
        if (!allowedDirectives.contains(directive) || tokens.size() > maxArgumentsCount) {
            return { };
        }
        for (const QString &argument : std::as_const(tokens)) {
            if (!argumentRegExp.match(argument).hasMatch()) {
                return { };
            }
        }

        if (directive == QLatin1String("cipher") || directive == QLatin1String("data-ciphers")
            || directive == QLatin1String("auth")) {
            // "none" / "null" switch the encryption or the authentication of the tunnel off
            for (const QString &argument : std::as_const(tokens)) {
                const QStringList names = argument.split(':');
                for (const QString &name : names) {
                    if (name.compare(QLatin1String("none"), Qt::CaseInsensitive) == 0
                        || name.compare(QLatin1String("null"), Qt::CaseInsensitive) == 0) {
                        return { };
                    }
                }
            }
        }

        hasClient |= (directive == QLatin1String("client"));
        hasRemote |= (directive == QLatin1String("remote"));
        hasDevTun |= (directive == QLatin1String("dev") && tokens == QStringList { "tun" });

        result << line.simplified();
    }

    if (!openBlock.isEmpty() || !hasClient || !hasDevTun || !hasRemote) {
        return { };
    }

    return result.join('\n') + '\n';
}

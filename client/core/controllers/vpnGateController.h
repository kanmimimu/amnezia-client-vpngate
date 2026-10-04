#ifndef VPNGATECONTROLLER_H
#define VPNGATECONTROLLER_H

#include <QByteArray>
#include <QObject>
#include <QString>
#include <QVector>

#include "core/utils/errorCodes.h"

class QNetworkReply;

// One public relay from the VPN Gate project (https://www.vpngate.net).
// The text fields that are shown in the UI are stripped of markup characters because they are
// provided by volunteers; `config` is the validated plain-text OpenVPN profile.
struct VpnGateServer
{
    QString ip;
    QString countryName;
    QString countryCode;
    QString protocol; // "UDP" or "TCP"
    int score = 0;
    int pingMs = -1; // -1 if unknown
    qint64 speedBps = 0;
    int sessions = 0;
    qint64 uptimeMs = 0;
    QString config;
};

class VpnGateController : public QObject
{
    Q_OBJECT

public:
    explicit VpnGateController(QObject *parent = nullptr);

    void fetchServers();

    // Parses the CSV served by the VPN Gate API. Rows without a usable OpenVPN profile are skipped.
    // The result is sorted by score, best first.
    static QVector<VpnGateServer> parseServerList(const QByteArray &csv);

    // Rebuilds the profile from a strict allow list of directives. Returns an empty string if the profile
    // contains anything that is not allowed, because it comes from an untrusted party and is run by a
    // privileged service (e.g. `up`, `script-security`, `plugin` could execute programs).
    static QString sanitizeOpenVpnConfig(const QString &config);

signals:
    void serversFetched(const QVector<VpnGateServer> &servers);
    void fetchFailed(amnezia::ErrorCode errorCode);

private:
    QNetworkReply *m_reply = nullptr;
};

#endif // VPNGATECONTROLLER_H

#include "vpnGateModel.h"

#include <QMap>
#include <algorithm>
#include <limits>

VpnGateModel::VpnGateModel(QObject *parent) : QAbstractListModel(parent)
{
}

int VpnGateModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent)
    return static_cast<int>(m_servers.size());
}

QVariant VpnGateModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= rowCount()) {
        return QVariant();
    }

    const VpnGateServer &server = m_servers.at(index.row());

    switch (role) {
    case CountryNameRole: return server.countryName;
    case CountryCodeRole: return server.countryCode;
    case IpRole: return server.ip;
    case ScoreRole: return server.score;
    case PingRole: return server.pingMs;
    // servers without a measured ping go last when sorting by ping
    case PingSortRole: return server.pingMs >= 0 ? server.pingMs : std::numeric_limits<int>::max();
    case SpeedMbpsRole: return static_cast<double>(server.speedBps) / 1000000.0;
    case SessionsRole: return server.sessions;
    case UptimeMsRole: return static_cast<double>(server.uptimeMs);
    case ProtocolRole: return server.protocol;
    }

    return QVariant();
}

void VpnGateModel::updateModel(const QVector<VpnGateServer> &servers)
{
    beginResetModel();
    m_servers = servers;
    endResetModel();
}

QString VpnGateModel::configAt(int row) const
{
    if (row < 0 || row >= rowCount()) {
        return QString();
    }
    return m_servers.at(row).config;
}

QString VpnGateModel::descriptionAt(int row) const
{
    if (row < 0 || row >= rowCount()) {
        return QString();
    }

    const VpnGateServer &server = m_servers.at(row);
    const QString location = server.countryName.isEmpty() ? server.countryCode : server.countryName;
    return QStringLiteral("VPN Gate %1 (%2)").arg(location, server.ip).simplified();
}

QVariantList VpnGateModel::countryOptions() const
{
    struct Country
    {
        QString name;
        int count = 0;
    };

    QMap<QString, Country> countries; // by country code
    for (const VpnGateServer &server : m_servers) {
        if (server.countryCode.isEmpty()) {
            continue;
        }
        Country &country = countries[server.countryCode];
        country.name = server.countryName.isEmpty() ? server.countryCode : server.countryName;
        ++country.count;
    }

    QList<QString> codes = countries.keys();
    std::stable_sort(codes.begin(), codes.end(), [&countries](const QString &left, const QString &right) {
        return countries[left].count > countries[right].count;
    });

    QVariantList options;
    for (const QString &code : std::as_const(codes)) {
        const Country &country = countries[code];
        const QString name = QStringLiteral("%1 (%2)").arg(country.name).arg(country.count);
        options.push_back(QVariantMap { { QStringLiteral("name"), name }, { QStringLiteral("code"), code } });
    }
    return options;
}

QHash<int, QByteArray> VpnGateModel::roleNames() const
{
    QHash<int, QByteArray> roles;
    roles[CountryNameRole] = "countryName";
    roles[CountryCodeRole] = "countryCode";
    roles[IpRole] = "ip";
    roles[ScoreRole] = "score";
    roles[PingRole] = "ping";
    roles[PingSortRole] = "pingSort";
    roles[SpeedMbpsRole] = "speedMbps";
    roles[SessionsRole] = "sessions";
    roles[UptimeMsRole] = "uptimeMs";
    roles[ProtocolRole] = "protocol";
    return roles;
}

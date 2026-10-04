#ifndef VPNGATEMODEL_H
#define VPNGATEMODEL_H

#include <QAbstractListModel>
#include <QVariantList>
#include <QVector>

#include "core/controllers/vpnGateController.h"

class VpnGateModel : public QAbstractListModel
{
    Q_OBJECT

public:
    enum Roles {
        CountryNameRole = Qt::UserRole + 1,
        CountryCodeRole,
        IpRole,
        ScoreRole,
        PingRole,
        PingSortRole,
        SpeedMbpsRole,
        SessionsRole,
        UptimeMsRole,
        ProtocolRole
    };

    explicit VpnGateModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    void updateModel(const QVector<VpnGateServer> &servers);

    QString configAt(int row) const;
    QString descriptionAt(int row) const;

    // [{ name: "Japan (56)", code: "JP" }, ...], the most populated countries first
    Q_INVOKABLE QVariantList countryOptions() const;

protected:
    QHash<int, QByteArray> roleNames() const override;

private:
    QVector<VpnGateServer> m_servers;
};

#endif // VPNGATEMODEL_H

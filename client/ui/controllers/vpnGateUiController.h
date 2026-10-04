#ifndef VPNGATEUICONTROLLER_H
#define VPNGATEUICONTROLLER_H

#include <QObject>

#include "core/controllers/vpnGateController.h"
#include "core/utils/errorCodes.h"

class ImportUiController;
class VpnGateModel;

class VpnGateUiController : public QObject
{
    Q_OBJECT

public:
    explicit VpnGateUiController(VpnGateController *vpnGateController, VpnGateModel *vpnGateModel,
                                 ImportUiController *importUiController, QObject *parent = nullptr);

public slots:
    void fetchServers();
    bool selectServer(int row);

signals:
    void serversFetched();
    void errorOccurred(amnezia::ErrorCode errorCode);

private:
    VpnGateController *m_vpnGateController;
    VpnGateModel *m_vpnGateModel;
    ImportUiController *m_importUiController;
};

#endif // VPNGATEUICONTROLLER_H

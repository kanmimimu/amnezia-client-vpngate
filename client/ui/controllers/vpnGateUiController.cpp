#include "vpnGateUiController.h"

#include "ui/controllers/importUiController.h"
#include "ui/models/vpnGateModel.h"

using namespace amnezia;

VpnGateUiController::VpnGateUiController(VpnGateController *vpnGateController, VpnGateModel *vpnGateModel,
                                         ImportUiController *importUiController, QObject *parent)
    : QObject(parent),
      m_vpnGateController(vpnGateController),
      m_vpnGateModel(vpnGateModel),
      m_importUiController(importUiController)
{
    connect(m_vpnGateController, &VpnGateController::serversFetched, this,
            [this](const QVector<VpnGateServer> &servers) {
                m_vpnGateModel->updateModel(servers);
                emit serversFetched();
            });
    connect(m_vpnGateController, &VpnGateController::fetchFailed, this, &VpnGateUiController::errorOccurred);
}

void VpnGateUiController::fetchServers()
{
    m_vpnGateController->fetchServers();
}

bool VpnGateUiController::selectServer(int row)
{
    const QString config = m_vpnGateModel->configAt(row);
    if (config.isEmpty()) {
        emit errorOccurred(ErrorCode::ImportInvalidConfigError);
        return false;
    }

    // on failure the import controller reports the error itself
    if (!m_importUiController->extractConfigFromData(config)) {
        return false;
    }

    m_importUiController->setConfigDescription(m_vpnGateModel->descriptionAt(row));
    return true;
}

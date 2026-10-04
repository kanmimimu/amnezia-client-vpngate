import QtQuick

import SortFilterProxyModel 0.2

// Filters the VPN Gate servers by country and sorts them by the selected key
SortFilterProxyModel {
    id: root

    // empty value shows all the countries
    property string countryCode: ""
    // "score", "speed", "ping", "sessions" or "uptime"
    property string sortKey: "score"

    filters: ValueFilter {
        roleName: "countryCode"
        value: root.countryCode
        enabled: root.countryCode !== ""
    }

    sorters: [
        RoleSorter { roleName: "speedMbps"; sortOrder: Qt.DescendingOrder; priority: 1; enabled: root.sortKey === "speed" },
        RoleSorter { roleName: "pingSort"; sortOrder: Qt.AscendingOrder; priority: 1; enabled: root.sortKey === "ping" },
        RoleSorter { roleName: "sessions"; sortOrder: Qt.AscendingOrder; priority: 1; enabled: root.sortKey === "sessions" },
        RoleSorter { roleName: "uptimeMs"; sortOrder: Qt.DescendingOrder; priority: 1; enabled: root.sortKey === "uptime" },
        RoleSorter { roleName: "score"; sortOrder: Qt.DescendingOrder; priority: 0 }
    ]
}

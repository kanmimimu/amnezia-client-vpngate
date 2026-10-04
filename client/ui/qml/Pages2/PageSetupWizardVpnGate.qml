import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import PageEnum 1.0
import Style 1.0

import "./"
import "../Controls2"
import "../Controls2/TextTypes"
import "../Config"
import "../Components"

PageType {
    id: root

    property string selectedCountryCode: ""
    property string selectedCountryName: qsTr("All countries")
    property int selectedCountryIndex: 0
    property string sortKey: "score"
    property int selectedSortIndex: 0

    function formatUptime(milliseconds) {
        var minutes = Math.floor(milliseconds / 60000)
        if (minutes < 60) {
            return qsTr("%1 min").arg(minutes)
        }
        var hours = Math.floor(minutes / 60)
        if (hours < 24) {
            return qsTr("%1 h").arg(hours)
        }
        return qsTr("%1 d").arg(Math.floor(hours / 24))
    }

    function updateCountryOptions() {
        countryOptions.clear()
        countryOptions.append({ "name": qsTr("All countries"), "code": "" })

        var countries = VpnGateModel.countryOptions()
        for (var i = 0; i < countries.length; i++) {
            countryOptions.append({ "name": countries[i].name, "code": countries[i].code })
        }

        // the selected country may be gone from the refreshed list, then all the countries are shown
        var index = 0
        for (var j = 0; j < countryOptions.count; j++) {
            if (countryOptions.get(j).code === root.selectedCountryCode) {
                index = j
                break
            }
        }
        root.selectedCountryIndex = index
        root.selectedCountryCode = countryOptions.get(index).code
        root.selectedCountryName = countryOptions.get(index).name
    }

    function refreshServers() {
        PageController.showBusyIndicator(true)
        VpnGateController.fetchServers()
    }

    Connections {
        target: VpnGateController

        function onServersFetched() {
            PageController.showBusyIndicator(false)
            root.updateCountryOptions()
        }

        function onErrorOccurred(errorCode) {
            PageController.showBusyIndicator(false)
        }
    }

    ListModel {
        id: countryOptions
    }

    ListModel {
        id: sortOptions

        ListElement { name: qsTr("Recommended"); key: "score" }
        ListElement { name: qsTr("Speed: fastest first"); key: "speed" }
        ListElement { name: qsTr("Ping: lowest first"); key: "ping" }
        ListElement { name: qsTr("Sessions: fewest first"); key: "sessions" }
        ListElement { name: qsTr("Uptime: longest first"); key: "uptime" }
    }

    VpnGateProxyModel {
        id: proxyVpnGateModel

        sourceModel: VpnGateModel
        countryCode: root.selectedCountryCode
        sortKey: root.sortKey
    }

    Component.onCompleted: updateCountryOptions()

    BackButtonType {
        id: backButton

        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.topMargin: 20 + PageController.safeAreaTopMargin

        onActiveFocusChanged: {
            if (backButton.enabled && backButton.activeFocus) {
                listView.positionViewAtBeginning()
            }
        }
    }

    ListViewType {
        id: listView

        anchors.top: backButton.bottom
        anchors.right: parent.right
        anchors.left: parent.left
        anchors.bottom: parent.bottom
        anchors.topMargin: 16

        header: ColumnLayout {
            width: listView.width

            HeaderTypeWithButton {
                Layout.fillWidth: true
                Layout.rightMargin: 16
                Layout.leftMargin: 16
                Layout.bottomMargin: 16

                headerText: qsTr("VPN Gate")
                descriptionText: qsTr("Free public VPN servers run by volunteers. Choose a server to add it as a connection.")

                actionButtonImage: "qrc:/images/controls/refresh-cw.svg"
                actionButtonFunction: function() {
                    root.refreshServers()
                }
            }

            WarningType {
                Layout.fillWidth: true
                Layout.rightMargin: 16
                Layout.leftMargin: 16
                Layout.bottomMargin: 24

                textString: qsTr("Anyone can run a VPN Gate server. The server owner may see and record your traffic, so do not use these servers for sensitive services.")

                iconPath: "qrc:/images/controls/alert-circle.svg"
            }

            DropDownType {
                id: countryDropDown

                Layout.fillWidth: true
                Layout.rightMargin: 16
                Layout.leftMargin: 16

                descriptionText: qsTr("Country")
                headerText: qsTr("Country")
                text: root.selectedCountryName

                drawerParent: root

                listView: ListViewWithRadioButtonType {
                    id: countryListView

                    rootWidth: root.width

                    model: countryOptions

                    // the list assigns selectedIndex on a click, which would break a plain binding
                    Binding {
                        target: countryListView
                        property: "selectedIndex"
                        value: root.selectedCountryIndex
                    }

                    clickedFunction: function() {
                        root.selectedCountryName = countryListView.selectedText
                        root.selectedCountryIndex = countryListView.selectedIndex
                        root.selectedCountryCode = countryOptions.get(countryListView.selectedIndex).code
                        countryDropDown.closeTriggered()
                    }
                }
            }

            DropDownType {
                id: sortDropDown

                Layout.fillWidth: true
                Layout.topMargin: 16
                Layout.rightMargin: 16
                Layout.leftMargin: 16

                descriptionText: qsTr("Sort by")
                headerText: qsTr("Sort by")
                text: sortOptions.get(root.selectedSortIndex).name

                drawerParent: root
                fitContent: true

                listView: ListViewWithRadioButtonType {
                    id: sortListView

                    rootWidth: root.width

                    model: sortOptions
                    selectedIndex: root.selectedSortIndex

                    clickedFunction: function() {
                        root.selectedSortIndex = sortListView.selectedIndex
                        root.sortKey = sortOptions.get(sortListView.selectedIndex).key
                        sortDropDown.closeTriggered()
                    }
                }
            }

            CaptionTextType {
                Layout.fillWidth: true
                Layout.topMargin: 16
                Layout.bottomMargin: 8
                Layout.rightMargin: 16
                Layout.leftMargin: 16

                color: AmneziaStyle.color.mutedGray
                text: qsTr("%1 servers").arg(proxyVpnGateModel.count)
            }
        }

        spacing: 0

        model: proxyVpnGateModel

        delegate: ColumnLayout {
            width: listView.width

            CardWithIconsType {
                Layout.fillWidth: true
                Layout.rightMargin: 16
                Layout.leftMargin: 16
                Layout.bottomMargin: 16

                headerText: countryName !== "" ? countryName + " · " + ip : ip
                bodyText: qsTr("%1 Mbps, ping %2 ms").arg(speedMbps.toFixed(1)).arg(ping >= 0 ? ping : "-")
                footerText: qsTr("%1 sessions, uptime %2, %3").arg(sessions).arg(root.formatUptime(uptimeMs)).arg(protocol)

                rightImageSource: "qrc:/images/controls/chevron-right.svg"

                onClicked: {
                    if (VpnGateController.selectServer(proxyVpnGateModel.mapToSource(index))) {
                        PageController.goToPage(PageEnum.PageSetupWizardViewConfig)
                    }
                }

                Keys.onEnterPressed: this.clicked()
                Keys.onReturnPressed: this.clicked()
            }
        }
    }
}

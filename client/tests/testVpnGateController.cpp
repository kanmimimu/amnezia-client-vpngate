#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QQmlComponent>
#include <QQmlEngine>
#include <QSignalSpy>
#include <QTest>
#include <QUuid>
#include <memory>

#include "core/controllers/vpnGateController.h"
#include "core/utils/constants/configKeys.h"
#include "secureQSettings.h"
#include "ui/controllers/importUiController.h"
#include "ui/controllers/vpnGateUiController.h"
#include "ui/models/vpnGateModel.h"
#include "utils/testCoreController.h"
#include "vpnConnection.h"

using namespace amnezia;

class TestVpnGateController : public QObject
{
    Q_OBJECT

private:
    TestCoreController *m_coreController = nullptr;
    SecureQSettings *m_settings = nullptr;

    static QByteArray profile(const QByteArray &extraDirective = QByteArray())
    {
        QByteArray result = "###############\r\n"
                            "# SoftEther sample\r\n"
                            "dev tun\r\n"
                            "proto udp\r\n"
                            "remote 1.2.3.4 1194\r\n"
                            ";http-proxy [proxy server] [proxy port]\r\n"
                            "cipher AES-128-CBC\r\n"
                            "data-ciphers AES-128-CBC\r\n"
                            "auth SHA1\r\n"
                            "resolv-retry infinite\r\n"
                            "nobind\r\n"
                            "persist-key\r\n"
                            "persist-tun\r\n"
                            "client\r\n"
                            "verb 3\r\n"
                            "#auth-user-pass\r\n";
        if (!extraDirective.isEmpty()) {
            result += extraDirective + "\r\n";
        }
        result += "<ca>\r\n"
                  "-----BEGIN CERTIFICATE-----\r\n"
                  "MIIDcjCCAlqgAwIBAgIBADANBgkq+/==\r\n"
                  "-----END CERTIFICATE-----\r\n"
                  "</ca>\r\n"
                  "\r\n"
                  "<key>\r\n"
                  "-----BEGIN RSA PRIVATE KEY-----\r\n"
                  "MIIEpAIBAAKCAQEA0000\r\n"
                  "-----END RSA PRIVATE KEY-----\r\n"
                  "</key>\r\n";
        return result;
    }

    static QByteArray row(const QByteArray &hostName, const QByteArray &ip, const QByteArray &score,
                          const QByteArray &country, const QByteArray &freeText, const QByteArray &config)
    {
        // HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,
        // LogType,Operator,Message,Config
        // the profile has to lead to the listed address, like the ones of VPN Gate do
        QByteArray adjusted = config;
        adjusted.replace("remote 1.2.3.4 ", "remote " + ip + " ");
        return hostName + "," + ip + "," + score + ",5,12000000," + country + ",JP,3,1000,10,10,2weeks," + freeText
                + ",message," + adjusted.toBase64() + "\r\n";
    }

    static QByteArray csv(const QList<QByteArray> &rows)
    {
        QByteArray result =
                "*vpn_servers\r\n"
                "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,"
                "LogType,Operator,Message,OpenVPN_ConfigData_Base64\r\n";
        for (const QByteArray &item : rows) {
            result += item;
        }
        result += "*\r\n";
        return result;
    }

private slots:
    void initTestCase()
    {
        const QString testOrg = "AmneziaVPN-Test-" + QUuid::createUuid().toString();
        m_settings = new SecureQSettings(testOrg, "amnezia-client", nullptr, false);

        auto vpnConnection = QSharedPointer<VpnConnection>::create(nullptr, nullptr);
        m_coreController = new TestCoreController(vpnConnection, m_settings, nullptr, this);
    }

    void cleanupTestCase()
    {
        m_settings->clearSettings();
        delete m_coreController;
        delete m_settings;
    }

    void sanitizeAcceptsVpnGateProfile()
    {
        const QString result = VpnGateController::sanitizeOpenVpnConfig(QString::fromUtf8(profile()));

        QVERIFY(!result.isEmpty());
        QVERIFY(result.contains("remote 1.2.3.4 1194\n"));
        QVERIFY(result.contains("<ca>\n-----BEGIN CERTIFICATE-----\n"));
        QVERIFY(result.contains("</key>\n"));
        QVERIFY2(!result.contains('\r'), "line endings must be normalized");
        QVERIFY2(!result.contains('#') && !result.contains(';'), "comments must be dropped");
    }

    void sanitizeRejectsForbiddenDirectives_data()
    {
        QTest::addColumn<QByteArray>("directive");

        QTest::newRow("up") << QByteArray("up \"cmd.exe /c calc\"");
        QTest::newRow("down") << QByteArray("down evil.bat");
        QTest::newRow("script-security") << QByteArray("script-security 2");
        QTest::newRow("plugin") << QByteArray("plugin evil.dll");
        QTest::newRow("route-up") << QByteArray("route-up evil.bat");
        QTest::newRow("tls-verify") << QByteArray("tls-verify evil.bat");
        QTest::newRow("up with dashes") << QByteArray("--up evil.bat");
        QTest::newRow("up with leading spaces") << QByteArray("   up evil.bat");
        QTest::newRow("management") << QByteArray("management 127.0.0.1 7505");
        QTest::newRow("setenv") << QByteArray("setenv FOO bar");
        QTest::newRow("config") << QByteArray("config other.ovpn");
        QTest::newRow("auth-user-pass") << QByteArray("auth-user-pass");
        QTest::newRow("cipher none") << QByteArray("cipher none");
        QTest::newRow("cipher NULL") << QByteArray("cipher NULL");
        QTest::newRow("data-ciphers with none") << QByteArray("data-ciphers AES-128-GCM:none");
        QTest::newRow("auth none") << QByteArray("auth none");
    }

    void sanitizeRejectsForbiddenDirectives()
    {
        QFETCH(QByteArray, directive);
        QVERIFY(VpnGateController::sanitizeOpenVpnConfig(QString::fromUtf8(profile(directive))).isEmpty());
    }

    void sanitizeRejectsShellMetacharactersInArguments_data()
    {
        QTest::addColumn<QByteArray>("directive");

        QTest::newRow("semicolon") << QByteArray("remote 1.2.3.4;calc 1194");
        QTest::newRow("quote") << QByteArray("remote \"1.2.3.4\" 1194");
        QTest::newRow("backslash") << QByteArray("remote c:\\evil 1194");
        QTest::newRow("too many arguments") << QByteArray("remote 1.2.3.4 1194 udp a b");
    }

    void sanitizeRejectsShellMetacharactersInArguments()
    {
        QFETCH(QByteArray, directive);
        QVERIFY(VpnGateController::sanitizeOpenVpnConfig(QString::fromUtf8(profile(directive))).isEmpty());
    }

    void sanitizeRejectsBrokenBlocks()
    {
        const QString header = "client\ndev tun\nremote 1.2.3.4 1194\n";

        QVERIFY2(!VpnGateController::sanitizeOpenVpnConfig(header + "<ca>\nAAAA\n</ca>\n").isEmpty(), "sanity check");
        QVERIFY2(VpnGateController::sanitizeOpenVpnConfig(header + "<ca>\nAAAA\n").isEmpty(), "unterminated block");
        QVERIFY2(VpnGateController::sanitizeOpenVpnConfig(header + "<tls-auth>\nAAAA\n</tls-auth>\n").isEmpty(),
                 "unexpected block");
        QVERIFY2(VpnGateController::sanitizeOpenVpnConfig(header + "<ca>\nup evil.bat; calc\n</ca>\n").isEmpty(),
                 "non-PEM content in a block");
        QVERIFY2(VpnGateController::sanitizeOpenVpnConfig(header + "<ca>\nAAAA\n</ca>\n</ca>\n").isEmpty(),
                 "stray closing tag");
        QVERIFY2(VpnGateController::sanitizeOpenVpnConfig(header + "<ca>\nAAAA\n</key>\n</ca>\n").isEmpty(),
                 "wrong closing tag");
    }

    void sanitizeRejectsIncompleteProfiles()
    {
        QVERIFY(VpnGateController::sanitizeOpenVpnConfig("").isEmpty());
        QVERIFY2(VpnGateController::sanitizeOpenVpnConfig("dev tun\nremote 1.2.3.4 1194\n").isEmpty(), "no client");
        QVERIFY2(VpnGateController::sanitizeOpenVpnConfig("client\nremote 1.2.3.4 1194\n").isEmpty(), "no dev");
        QVERIFY2(VpnGateController::sanitizeOpenVpnConfig("client\ndev tap\nremote 1.2.3.4 1194\n").isEmpty(),
                 "tap is not supported");
        QVERIFY2(VpnGateController::sanitizeOpenVpnConfig("client\ndev tun\n").isEmpty(), "no remote");
    }

    void parseReadsColumns()
    {
        const auto servers = VpnGateController::parseServerList(
                csv({ row("vpn1", "1.2.3.4", "100", "Japan", "Some Operator", profile()) }));

        QCOMPARE(servers.size(), 1);
        const VpnGateServer &server = servers.first();
        QCOMPARE(server.ip, QString("1.2.3.4"));
        QCOMPARE(server.countryName, QString("Japan"));
        QCOMPARE(server.countryCode, QString("JP"));
        QCOMPARE(server.protocol, QString("UDP"));
        QCOMPARE(server.score, 100);
        QCOMPARE(server.pingMs, 5);
        QCOMPARE(server.speedBps, qint64(12000000));
        QCOMPARE(server.sessions, 3);
        QCOMPARE(server.uptimeMs, qint64(1000));
        QVERIFY(server.config.contains("remote 1.2.3.4 1194"));
    }

    void parseDetectsTcpProfiles()
    {
        const auto servers = VpnGateController::parseServerList(csv({ row(
                "vpn1", "1.2.3.4", "100", "Japan", "Some Operator", profile().replace("proto udp", "proto tcp")) }));

        QCOMPARE(servers.size(), 1);
        QCOMPARE(servers.first().protocol, QString("TCP"));
    }

    void parseSkipsProfilesPointingElsewhere()
    {
        const auto servers = VpnGateController::parseServerList(csv({
                row("elsewhere", "1.2.3.4", "1", "Japan", "x", profile().replace("remote 1.2.3.4", "remote 6.6.6.6")),
                row("hostname", "2.2.2.2", "2", "Japan", "x",
                    profile().replace("remote 1.2.3.4", "remote example.com")),
                row("ok", "3.3.3.3", "3", "Japan", "x", profile()),
        }));

        QCOMPARE(servers.size(), 1);
        QCOMPARE(servers.first().ip, QString("3.3.3.3"));
    }

    void parseHandlesCommasInFreeText()
    {
        const auto servers = VpnGateController::parseServerList(
                csv({ row("vpn1", "1.2.3.4", "100", "Japan", "Alice, Inc.,hello, world", profile()) }));

        QCOMPARE(servers.size(), 1);
        QVERIFY(servers.first().config.contains("remote 1.2.3.4 1194"));
    }

    void parseSkipsUnusableRows()
    {
        const auto servers = VpnGateController::parseServerList(csv({
                row("ok", "1.2.3.4", "1", "Japan", "x", profile()),
                row("bad-ip", "not-an-ip", "2", "Japan", "x", profile()),
                row("bad-profile", "5.6.7.8", "3", "Japan", "x", profile("up evil.bat")),
                row("no-profile", "9.9.9.9", "4", "Japan", "x", QByteArray()),
                QByteArray("truncated,1.1.1.1,5\r\n"),
        }));

        QCOMPARE(servers.size(), 1);
        QCOMPARE(servers.first().ip, QString("1.2.3.4"));
    }

    void parseSortsByScoreDescending()
    {
        const auto servers = VpnGateController::parseServerList(csv({
                row("low", "1.1.1.1", "10", "Japan", "x", profile()),
                row("high", "2.2.2.2", "300", "Japan", "x", profile()),
                row("mid", "3.3.3.3", "20", "Japan", "x", profile()),
        }));

        QCOMPARE(servers.size(), 3);
        QCOMPARE(servers.at(0).ip, QString("2.2.2.2"));
        QCOMPARE(servers.at(1).ip, QString("3.3.3.3"));
        QCOMPARE(servers.at(2).ip, QString("1.1.1.1"));
    }

    void parseStripsMarkupFromDisplayedFields()
    {
        const auto servers = VpnGateController::parseServerList(
                csv({ row("vpn1", "1.2.3.4", "1", "<img src=\"http://example.com/x.png\">Jap&an", "x", profile()) }));

        QCOMPARE(servers.size(), 1);
        const QString text = servers.first().countryName;
        QVERIFY2(!text.contains('<') && !text.contains('>') && !text.contains('&') && !text.contains('"'),
                 qPrintable(text));
        QVERIFY(text.contains("Japan") || text.contains("Jap"));
    }

    void modelExposesSortableRoles()
    {
        VpnGateServer known;
        known.ip = "1.1.1.1";
        known.pingMs = 12;
        known.speedBps = 25500000;
        known.uptimeMs = 3600000;
        known.protocol = "UDP";

        VpnGateServer unknownPing = known;
        unknownPing.ip = "2.2.2.2";
        unknownPing.pingMs = -1;

        VpnGateModel model;
        model.updateModel({ known, unknownPing });

        QCOMPARE(model.rowCount(), 2);
        QCOMPARE(model.data(model.index(0), VpnGateModel::PingRole).toInt(), 12);
        QCOMPARE(model.data(model.index(0), VpnGateModel::SpeedMbpsRole).toDouble(), 25.5);
        QCOMPARE(model.data(model.index(0), VpnGateModel::UptimeMsRole).toDouble(), 3600000.0);
        QCOMPARE(model.data(model.index(0), VpnGateModel::ProtocolRole).toString(), QString("UDP"));
        QCOMPARE(model.data(model.index(1), VpnGateModel::PingRole).toInt(), -1);
        QVERIFY2(model.data(model.index(1), VpnGateModel::PingSortRole).toInt()
                         > model.data(model.index(0), VpnGateModel::PingSortRole).toInt(),
                 "an unknown ping must sort last");

        const QHash<int, QByteArray> roles = static_cast<const QAbstractItemModel &>(model).roleNames();
        for (const QByteArray &name :
             { "countryCode", "ip", "score", "ping", "pingSort", "speedMbps", "sessions", "uptimeMs", "protocol" }) {
            QVERIFY2(roles.values().contains(name), name.constData());
        }
    }

    void modelListsCountriesByPopulation()
    {
        auto server = [](const QString &code, const QString &name) {
            VpnGateServer result;
            result.countryCode = code;
            result.countryName = name;
            return result;
        };

        VpnGateModel model;
        model.updateModel({ server("KR", "Korea Republic of"), server("JP", "Japan"), server("JP", "Japan"),
                            server("US", "United States"), server("", "Nowhere") });

        const QVariantList options = model.countryOptions();
        QCOMPARE(options.size(), 3);
        QCOMPARE(options.at(0).toMap().value("name").toString(), QString("Japan (2)"));
        QCOMPARE(options.at(0).toMap().value("code").toString(), QString("JP"));
        QCOMPARE(options.at(1).toMap().value("code").toString(), QString("KR"));
        QCOMPARE(options.at(2).toMap().value("code").toString(), QString("US"));
    }

    void parseReturnsEmptyListForGarbage()
    {
        QVERIFY(VpnGateController::parseServerList("").isEmpty());
        QVERIFY(VpnGateController::parseServerList("<html>Service Unavailable</html>").isEmpty());
        QVERIFY(VpnGateController::parseServerList("*vpn_servers\r\n#HostName,IP\r\n*\r\n").isEmpty());
    }

    void parsesRealServerList()
    {
        // optional: a copy of https://www.vpngate.net/api/iphone/
        const QString path = qEnvironmentVariable("VPN_GATE_SAMPLE_CSV");
        if (path.isEmpty()) {
            QSKIP("Set VPN_GATE_SAMPLE_CSV to a downloaded VPN Gate server list");
        }

        QFile file(path);
        QVERIFY2(file.open(QIODevice::ReadOnly), qPrintable(file.errorString()));

        const auto servers = VpnGateController::parseServerList(file.readAll());
        QVERIFY(!servers.isEmpty());
        qInfo() << "VPN Gate servers accepted:" << servers.size();

        for (const VpnGateServer &server : servers) {
            const auto result = m_coreController->m_importCoreController->extractConfigFromData(server.config);
            QVERIFY2(result.errorCode == ErrorCode::NoError, qPrintable(server.ip));
            QCOMPARE(result.config.value(configKey::hostName).toString(), server.ip);
        }
    }

    void proxyModelFiltersAndSorts()
    {
        auto server = [](const QString &ip, const QString &countryCode, int score, int pingMs, qint64 speedMbps,
                         int sessions, qint64 uptimeMs) {
            VpnGateServer result;
            result.ip = ip;
            result.countryCode = countryCode;
            result.score = score;
            result.pingMs = pingMs;
            result.speedBps = speedMbps * 1000000;
            result.sessions = sessions;
            result.uptimeMs = uptimeMs;
            return result;
        };

        // deliberately not in any of the expected orders
        VpnGateModel model;
        model.updateModel({ server("3.3.3.3", "KR", 100, 10, 30, 9, 3000),
                            server("2.2.2.2", "JP", 200, -1, 50, 1, 5000),
                            server("1.1.1.1", "JP", 300, 30, 10, 5, 1000) });

        QQmlEngine engine;
        QQmlComponent component(&engine,
                                QUrl::fromLocalFile(QFINDTESTDATA("../ui/qml/Components/VpnGateProxyModel.qml")));
        QVERIFY2(component.status() == QQmlComponent::Ready, qPrintable(component.errorString()));

        std::unique_ptr<QObject> object(component.createWithInitialProperties(
                { { "sourceModel", QVariant::fromValue(static_cast<QAbstractItemModel *>(&model)) } }));
        QVERIFY2(object, qPrintable(component.errorString()));
        auto *proxy = qobject_cast<QAbstractItemModel *>(object.get());
        QVERIFY(proxy);

        auto ips = [proxy]() {
            QStringList result;
            for (int row = 0; row < proxy->rowCount(); ++row) {
                result << proxy->data(proxy->index(row, 0), VpnGateModel::IpRole).toString();
            }
            return result;
        };
        auto sortBy = [&object](const QString &key) { object->setProperty("sortKey", key); };
        auto filterBy = [&object](const QString &countryCode) { object->setProperty("countryCode", countryCode); };

        QCOMPARE(ips(), QStringList({ "1.1.1.1", "2.2.2.2", "3.3.3.3" })); // score, the default

        sortBy("speed");
        QCOMPARE(ips(), QStringList({ "2.2.2.2", "3.3.3.3", "1.1.1.1" }));
        sortBy("ping");
        QCOMPARE(ips(), QStringList({ "3.3.3.3", "1.1.1.1", "2.2.2.2" })); // the unknown ping goes last
        sortBy("sessions");
        QCOMPARE(ips(), QStringList({ "2.2.2.2", "1.1.1.1", "3.3.3.3" }));
        sortBy("uptime");
        QCOMPARE(ips(), QStringList({ "2.2.2.2", "3.3.3.3", "1.1.1.1" }));

        filterBy("JP");
        QCOMPARE(ips(), QStringList({ "2.2.2.2", "1.1.1.1" })); // still sorted by uptime
        sortBy("score");
        QCOMPARE(ips(), QStringList({ "1.1.1.1", "2.2.2.2" }));
        filterBy("KR");
        QCOMPARE(ips(), QStringList({ "3.3.3.3" }));
        filterBy("");
        QCOMPARE(ips().size(), 3);

        // the list is replaced when it is refreshed
        model.updateModel({ server("9.9.9.9", "US", 1, 1, 1, 1, 1), server("8.8.8.8", "US", 2, 1, 1, 1, 1) });
        QCOMPARE(ips(), QStringList({ "8.8.8.8", "9.9.9.9" }));
        filterBy("JP");
        QVERIFY(ips().isEmpty());
    }

    void selectServerFeedsTheOpenVpnImport()
    {
        ImportUiController importUiController(m_coreController->m_importCoreController);
        VpnGateController vpnGateController;
        VpnGateModel model;
        VpnGateUiController uiController(&vpnGateController, &model, &importUiController);
        QSignalSpy errorSpy(&uiController, &VpnGateUiController::errorOccurred);

        model.updateModel(VpnGateController::parseServerList(
                csv({ row("vpn1", "1.2.3.4", "100", "Japan", "Operator", profile()) })));
        QCOMPARE(model.rowCount(), 1);

        QVERIFY(uiController.selectServer(0));
        QCOMPARE(errorSpy.count(), 0);

        const QJsonObject config = QJsonDocument::fromJson(importUiController.getConfig().toUtf8()).object();
        QCOMPARE(config.value(configKey::description).toString(), QString("VPN Gate Japan (1.2.3.4)"));
        QCOMPARE(config.value(configKey::hostName).toString(), QString("1.2.3.4"));
        QCOMPARE(config.value(configKey::defaultContainer).toString(), QString(configKey::amneziaOpenvpn));
        QVERIFY(!importUiController.getMaliciousWarningText().isEmpty());

        QVERIFY(!uiController.selectServer(1));
        QCOMPARE(errorSpy.count(), 1);
    }
};

QTEST_MAIN(TestVpnGateController)
#include "testVpnGateController.moc"

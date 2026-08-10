#pragma once

#include "network/HostDiscovery.h"
#include "network/NetworkScanner.h"

#include <QHash>
#include <QMainWindow>

class QComboBox;
class QLabel;
class QLineEdit;
class QProgressBar;
class QPushButton;
class QSpinBox;
class QTableWidget;
class QTableWidgetItem;

struct HostUiState
{
    QString address;
    QString hostName;
    QString status = QStringLiteral("Scanning");
    QString discoveryMethod;
    qint64 responseTimeMs = -1;
    QList<quint16> openPorts;
};

class MainWindow final : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

private:
    QWidget *createScannerTab();
    QWidget *createPortWatchTab();
    void populateLocalSubnets();
    void startScan();
    void cancelScan();
    void updateHost(const NetworkHostResult &host);
    void updateDiscovery(const HostDiscoveryResult &result);
    void markTcpResponsive(const QString &address, qint64 responseTimeMs);
    void setHostName(const QString &address, const QString &hostName);
    void ensureHost(const QString &address);
    void renderHost(const QString &address);
    void updateCombinedProgress();
    void scanPartFinished(bool cancelled);
    void applyHostFilter(const QString &text);
    void showHostContextMenu(const QPoint &position);
    void refreshLocalPorts();
    void loadSettings();
    void saveSettings() const;
    static QList<quint16> parsePorts(const QString &text, QString *error);
    static QString serviceName(quint16 port);
    static QString formatPorts(const QList<quint16> &ports);

    NetworkScanner m_scanner;
    HostDiscovery m_discovery;
    QComboBox *m_targetCombo = nullptr;
    QLineEdit *m_portsEdit = nullptr;
    QLineEdit *m_filterEdit = nullptr;
    QSpinBox *m_timeoutSpin = nullptr;
    QPushButton *m_scanButton = nullptr;
    QPushButton *m_cancelButton = nullptr;
    QTableWidget *m_hostsTable = nullptr;
    QProgressBar *m_scanProgress = nullptr;
    QLabel *m_scanStatus = nullptr;
    QTableWidget *m_portsTable = nullptr;
    QLabel *m_portsStatus = nullptr;
    QHash<QString, HostUiState> m_hosts;
    QHash<QString, QTableWidgetItem *> m_hostItems;
    qint64 m_discoveryCompleted = 0;
    qint64 m_discoveryTotal = 0;
    qint64 m_portsCompleted = 0;
    qint64 m_portsTotal = 0;
    int m_pendingScanParts = 0;
    bool m_scanCancelled = false;
};

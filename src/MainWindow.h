#pragma once

#include "network/NetworkScanner.h"

#include <QHash>
#include <QMainWindow>

class QLabel;
class QLineEdit;
class QProgressBar;
class QPushButton;
class QSpinBox;
class QTableWidget;

class MainWindow final : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);

private:
    QWidget *createScannerTab();
    QWidget *createPortWatchTab();
    void startScan();
    void updateHost(const NetworkHostResult &host);
    void refreshLocalPorts();
    static QList<quint16> parsePorts(const QString &text, QString *error);

    NetworkScanner m_scanner;
    QLineEdit *m_targetEdit = nullptr;
    QLineEdit *m_portsEdit = nullptr;
    QSpinBox *m_timeoutSpin = nullptr;
    QPushButton *m_scanButton = nullptr;
    QPushButton *m_cancelButton = nullptr;
    QTableWidget *m_hostsTable = nullptr;
    QProgressBar *m_scanProgress = nullptr;
    QLabel *m_scanStatus = nullptr;
    QTableWidget *m_portsTable = nullptr;
    QLabel *m_portsStatus = nullptr;
    QHash<QString, int> m_hostRows;
};


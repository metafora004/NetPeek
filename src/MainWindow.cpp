#include "MainWindow.h"

#include "network/Ipv4Range.h"
#include "ports/LocalPortsProvider.h"

#include <QAbstractItemView>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QProgressBar>
#include <QPushButton>
#include <QRegularExpression>
#include <QSpinBox>
#include <QTabWidget>
#include <QTableWidget>
#include <QVBoxLayout>
#include <algorithm>
#include <limits>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle(QStringLiteral("NetPeek — Network Inspector"));
    resize(980, 650);
    setMinimumSize(760, 480);

    auto *tabs = new QTabWidget(this);
    tabs->addTab(createScannerTab(), QStringLiteral("Сканер сети"));
    tabs->addTab(createPortWatchTab(), QStringLiteral("Локальные порты"));
    setCentralWidget(tabs);

    connect(&m_scanner, &NetworkScanner::hostUpdated, this, &MainWindow::updateHost);
    connect(&m_scanner, &NetworkScanner::progressChanged, this, [this](const qint64 completed, const qint64 total) {
        m_scanProgress->setMaximum(static_cast<int>(qMin<qint64>(total, std::numeric_limits<int>::max())));
        m_scanProgress->setValue(static_cast<int>(qMin<qint64>(completed, std::numeric_limits<int>::max())));
        m_scanStatus->setText(QStringLiteral("Проверено %1 из %2 соединений · найдено узлов: %3")
                                  .arg(completed).arg(total).arg(m_hostRows.size()));
    });
    connect(&m_scanner, &NetworkScanner::finished, this, [this](const bool cancelled) {
        m_scanButton->setEnabled(true);
        m_cancelButton->setEnabled(false);
        m_scanStatus->setText(cancelled
            ? QStringLiteral("Сканирование остановлено · найдено узлов: %1").arg(m_hostRows.size())
            : QStringLiteral("Готово · найдено узлов: %1").arg(m_hostRows.size()));
    });
}

QWidget *MainWindow::createScannerTab()
{
    auto *page = new QWidget;
    auto *layout = new QVBoxLayout(page);
    layout->setContentsMargins(18, 18, 18, 18);
    layout->setSpacing(12);

    auto *title = new QLabel(QStringLiteral("Обнаружение узлов и открытых TCP-портов"));
    QFont titleFont = title->font();
    titleFont.setPointSize(15);
    titleFont.setBold(true);
    title->setFont(titleFont);
    layout->addWidget(title);

    auto *form = new QFormLayout;
    m_targetEdit = new QLineEdit(QStringLiteral("192.168.1.0/24"));
    m_targetEdit->setPlaceholderText(QStringLiteral("192.168.1.0/24 или 192.168.1.1-254"));
    m_portsEdit = new QLineEdit(QStringLiteral("22, 80, 443, 445, 3389, 8080"));
    m_portsEdit->setPlaceholderText(QStringLiteral("22, 80, 443 или 1-1024"));
    m_timeoutSpin = new QSpinBox;
    m_timeoutSpin->setRange(50, 10000);
    m_timeoutSpin->setValue(350);
    m_timeoutSpin->setSuffix(QStringLiteral(" мс"));
    form->addRow(QStringLiteral("Цель:"), m_targetEdit);
    form->addRow(QStringLiteral("TCP-порты:"), m_portsEdit);
    form->addRow(QStringLiteral("Тайм-аут:"), m_timeoutSpin);
    layout->addLayout(form);

    auto *buttons = new QHBoxLayout;
    m_scanButton = new QPushButton(QStringLiteral("Начать сканирование"));
    m_cancelButton = new QPushButton(QStringLiteral("Остановить"));
    m_cancelButton->setEnabled(false);
    buttons->addWidget(m_scanButton);
    buttons->addWidget(m_cancelButton);
    buttons->addStretch();
    layout->addLayout(buttons);

    m_hostsTable = new QTableWidget(0, 3);
    m_hostsTable->setHorizontalHeaderLabels({QStringLiteral("IP-адрес"), QStringLiteral("Имя хоста"),
                                             QStringLiteral("Открытые TCP-порты")});
    m_hostsTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_hostsTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_hostsTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    m_hostsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_hostsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_hostsTable->setAlternatingRowColors(true);
    layout->addWidget(m_hostsTable, 1);

    m_scanProgress = new QProgressBar;
    m_scanProgress->setValue(0);
    m_scanStatus = new QLabel(QStringLiteral("Готов к сканированию"));
    layout->addWidget(m_scanProgress);
    layout->addWidget(m_scanStatus);

    connect(m_scanButton, &QPushButton::clicked, this, &MainWindow::startScan);
    connect(m_cancelButton, &QPushButton::clicked, &m_scanner, &NetworkScanner::cancel);
    return page;
}

QWidget *MainWindow::createPortWatchTab()
{
    auto *page = new QWidget;
    auto *layout = new QVBoxLayout(page);
    layout->setContentsMargins(18, 18, 18, 18);
    layout->setSpacing(12);

    auto *top = new QHBoxLayout;
    auto *title = new QLabel(QStringLiteral("Порты, открытые на этом компьютере"));
    QFont titleFont = title->font();
    titleFont.setPointSize(15);
    titleFont.setBold(true);
    title->setFont(titleFont);
    auto *refresh = new QPushButton(QStringLiteral("Обновить"));
    top->addWidget(title);
    top->addStretch();
    top->addWidget(refresh);
    layout->addLayout(top);

    m_portsTable = new QTableWidget(0, 5);
    m_portsTable->setHorizontalHeaderLabels({QStringLiteral("Протокол"), QStringLiteral("Локальный адрес"),
        QStringLiteral("Порт"), QStringLiteral("PID"), QStringLiteral("Процесс")});
    m_portsTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_portsTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_portsTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_portsTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    m_portsTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    m_portsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_portsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_portsTable->setAlternatingRowColors(true);
    layout->addWidget(m_portsTable, 1);
    m_portsStatus = new QLabel;
    layout->addWidget(m_portsStatus);

    connect(refresh, &QPushButton::clicked, this, &MainWindow::refreshLocalPorts);
    refreshLocalPorts();
    return page;
}

QList<quint16> MainWindow::parsePorts(const QString &text, QString *error)
{
    QSet<quint16> unique;
    const QStringList groups = text.split(QRegularExpression(QStringLiteral("[,;\\s]+")), Qt::SkipEmptyParts);
    for (const QString &group : groups) {
        const QStringList range = group.split(QLatin1Char('-'));
        bool firstOk = false;
        bool lastOk = false;
        const uint first = range.value(0).toUInt(&firstOk);
        const uint last = range.size() == 1 ? first : range.value(1).toUInt(&lastOk);
        if (range.size() == 1) lastOk = firstOk;
        if (range.size() > 2 || !firstOk || !lastOk || first == 0 || last > 65535 || last < first) {
            if (error) *error = QStringLiteral("Некорректный порт или диапазон: %1").arg(group);
            return {};
        }
        for (uint port = first; port <= last; ++port) {
            unique.insert(static_cast<quint16>(port));
            if (unique.size() > 1024) {
                if (error) *error = QStringLiteral("За один запуск можно проверить не более 1024 портов.");
                return {};
            }
        }
    }
    QList<quint16> ports = unique.values();
    std::sort(ports.begin(), ports.end());
    if (ports.isEmpty() && error) *error = QStringLiteral("Укажите хотя бы один TCP-порт.");
    return ports;
}

void MainWindow::startScan()
{
    QString error;
    const QVector<QHostAddress> addresses = Ipv4Range::parse(m_targetEdit->text(), &error);
    if (addresses.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("NetPeek"), error);
        return;
    }
    const QList<quint16> ports = parsePorts(m_portsEdit->text(), &error);
    if (ports.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("NetPeek"), error);
        return;
    }

    const qint64 jobs = static_cast<qint64>(addresses.size()) * ports.size();
    if (jobs > 250000) {
        const auto answer = QMessageBox::question(this, QStringLiteral("Большое сканирование"),
            QStringLiteral("Будет выполнено %1 TCP-проверок. Продолжить?").arg(jobs));
        if (answer != QMessageBox::Yes)
            return;
    }

    m_hostsTable->setRowCount(0);
    m_hostRows.clear();
    m_scanButton->setEnabled(false);
    m_cancelButton->setEnabled(true);
    m_scanner.start(addresses, ports, m_timeoutSpin->value());
}

void MainWindow::updateHost(const NetworkHostResult &host)
{
    int row = m_hostRows.value(host.address, -1);
    if (row < 0) {
        row = m_hostsTable->rowCount();
        m_hostsTable->insertRow(row);
        m_hostRows.insert(host.address, row);
        m_hostsTable->setItem(row, 0, new QTableWidgetItem(host.address));
        m_hostsTable->setItem(row, 1, new QTableWidgetItem);
        m_hostsTable->setItem(row, 2, new QTableWidgetItem);
    }

    QStringList portNames;
    for (const quint16 port : host.openPorts)
        portNames.append(QString::number(port));
    m_hostsTable->item(row, 1)->setText(host.hostName.isEmpty() ? QStringLiteral("—") : host.hostName);
    m_hostsTable->item(row, 2)->setText(portNames.join(QStringLiteral(", ")));
}

void MainWindow::refreshLocalPorts()
{
    QString error;
    const QList<LocalPortEntry> entries = LocalPortsProvider::query(&error);
    m_portsTable->setRowCount(entries.size());
    for (int row = 0; row < entries.size(); ++row) {
        const auto &entry = entries[row];
        m_portsTable->setItem(row, 0, new QTableWidgetItem(entry.protocol));
        m_portsTable->setItem(row, 1, new QTableWidgetItem(entry.localAddress));
        auto *portItem = new QTableWidgetItem;
        portItem->setData(Qt::DisplayRole, entry.port);
        m_portsTable->setItem(row, 2, portItem);
        auto *pidItem = new QTableWidgetItem;
        pidItem->setData(Qt::DisplayRole, entry.pid >= 0 ? QVariant(entry.pid) : QVariant(QStringLiteral("—")));
        m_portsTable->setItem(row, 3, pidItem);
        m_portsTable->setItem(row, 4, new QTableWidgetItem(entry.processName.isEmpty() ? QStringLiteral("—") : entry.processName));
    }
    m_portsStatus->setText(error.isEmpty()
        ? QStringLiteral("Найдено локальных сокетов: %1").arg(entries.size())
        : error);
}

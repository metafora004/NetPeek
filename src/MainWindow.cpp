#include "MainWindow.h"

#include "network/Ipv4Range.h"
#include "network/NetworkInterfaces.h"
#include "ports/LocalPortsProvider.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QClipboard>
#include <QColor>
#include <QComboBox>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QProgressBar>
#include <QPushButton>
#include <QRegularExpression>
#include <QSettings>
#include <QSet>
#include <QSpinBox>
#include <QTabWidget>
#include <QTableWidget>
#include <QVBoxLayout>
#include <algorithm>
#include <limits>

namespace {

class IpAddressItem final : public QTableWidgetItem
{
public:
    explicit IpAddressItem(const QString &address)
        : QTableWidgetItem(address)
    {
        QHostAddress host(address);
        setData(Qt::UserRole, host.toIPv4Address());
    }

    bool operator<(const QTableWidgetItem &other) const override
    {
        return data(Qt::UserRole).toUInt() < other.data(Qt::UserRole).toUInt();
    }
};

} // namespace

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle(QStringLiteral("NetPeek 0.2.0 — Network Inspector"));
    resize(1120, 700);
    setMinimumSize(820, 520);

    auto *tabs = new QTabWidget(this);
    tabs->addTab(createScannerTab(), QStringLiteral("Сканер сети"));
    tabs->addTab(createPortWatchTab(), QStringLiteral("Локальные порты"));
    setCentralWidget(tabs);
    loadSettings();

    connect(&m_scanner, &NetworkScanner::hostUpdated, this, &MainWindow::updateHost);
    connect(&m_scanner, &NetworkScanner::hostResponsive, this, &MainWindow::markTcpResponsive);
    connect(&m_scanner, &NetworkScanner::progressChanged, this,
            [this](qint64 completed, qint64 total) {
        m_portsCompleted = completed;
        m_portsTotal = total;
        updateCombinedProgress();
    });
    connect(&m_scanner, &NetworkScanner::finished, this, &MainWindow::scanPartFinished);

    connect(&m_discovery, &HostDiscovery::hostChecked, this, &MainWindow::updateDiscovery);
    connect(&m_discovery, &HostDiscovery::hostNameResolved, this, &MainWindow::setHostName);
    connect(&m_discovery, &HostDiscovery::progressChanged, this,
            [this](qint64 completed, qint64 total) {
        m_discoveryCompleted = completed;
        m_discoveryTotal = total;
        updateCombinedProgress();
    });
    connect(&m_discovery, &HostDiscovery::finished, this, &MainWindow::scanPartFinished);
}

MainWindow::~MainWindow()
{
    saveSettings();
}

QWidget *MainWindow::createScannerTab()
{
    auto *page = new QWidget;
    auto *layout = new QVBoxLayout(page);
    layout->setContentsMargins(18, 18, 18, 18);
    layout->setSpacing(12);

    auto *title = new QLabel(QStringLiteral("Обнаружение устройств и открытых TCP-портов"));
    QFont titleFont = title->font();
    titleFont.setPointSize(15);
    titleFont.setBold(true);
    title->setFont(titleFont);
    layout->addWidget(title);

    auto *form = new QFormLayout;
    auto *targetRow = new QHBoxLayout;
    m_targetCombo = new QComboBox;
    m_targetCombo->setEditable(true);
    m_targetCombo->setInsertPolicy(QComboBox::NoInsert);
    m_targetCombo->setPlaceholderText(QStringLiteral("192.168.1.0/24 или 192.168.1.1-254"));
    auto *refreshNetworks = new QPushButton(QStringLiteral("Обновить сети"));
    targetRow->addWidget(m_targetCombo, 1);
    targetRow->addWidget(refreshNetworks);
    m_portsEdit = new QLineEdit(QStringLiteral("22, 80, 443, 445, 3389, 8080"));
    m_portsEdit->setPlaceholderText(QStringLiteral("22, 80, 443 или 1-1024"));
    m_timeoutSpin = new QSpinBox;
    m_timeoutSpin->setRange(100, 10000);
    m_timeoutSpin->setValue(500);
    m_timeoutSpin->setSuffix(QStringLiteral(" мс"));
    form->addRow(QStringLiteral("Локальная сеть / цель:"), targetRow);
    form->addRow(QStringLiteral("TCP-порты:"), m_portsEdit);
    form->addRow(QStringLiteral("Тайм-аут:"), m_timeoutSpin);
    layout->addLayout(form);

    auto *buttons = new QHBoxLayout;
    m_scanButton = new QPushButton(QStringLiteral("Начать сканирование"));
    m_cancelButton = new QPushButton(QStringLiteral("Остановить"));
    m_cancelButton->setEnabled(false);
    m_filterEdit = new QLineEdit;
    m_filterEdit->setPlaceholderText(QStringLiteral("Поиск по результатам…"));
    m_filterEdit->setClearButtonEnabled(true);
    buttons->addWidget(m_scanButton);
    buttons->addWidget(m_cancelButton);
    buttons->addStretch();
    buttons->addWidget(m_filterEdit, 1);
    layout->addLayout(buttons);

    m_hostsTable = new QTableWidget(0, 6);
    m_hostsTable->setHorizontalHeaderLabels({QStringLiteral("IP-адрес"), QStringLiteral("Статус"),
        QStringLiteral("Отклик"), QStringLiteral("Имя хоста"), QStringLiteral("Метод"),
        QStringLiteral("Открытые TCP-порты / сервисы")});
    for (int column = 0; column < 5; ++column)
        m_hostsTable->horizontalHeader()->setSectionResizeMode(column, QHeaderView::ResizeToContents);
    m_hostsTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    m_hostsTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    m_hostsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_hostsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_hostsTable->setAlternatingRowColors(true);
    m_hostsTable->setSortingEnabled(true);
    m_hostsTable->sortItems(0, Qt::AscendingOrder);
    m_hostsTable->setContextMenuPolicy(Qt::CustomContextMenu);
    layout->addWidget(m_hostsTable, 1);

    m_scanProgress = new QProgressBar;
    m_scanProgress->setValue(0);
    m_scanStatus = new QLabel(QStringLiteral("Готов к сканированию"));
    layout->addWidget(m_scanProgress);
    layout->addWidget(m_scanStatus);

    connect(refreshNetworks, &QPushButton::clicked, this, &MainWindow::populateLocalSubnets);
    connect(m_scanButton, &QPushButton::clicked, this, &MainWindow::startScan);
    connect(m_cancelButton, &QPushButton::clicked, this, &MainWindow::cancelScan);
    connect(m_filterEdit, &QLineEdit::textChanged, this, &MainWindow::applyHostFilter);
    connect(m_hostsTable, &QTableWidget::customContextMenuRequested,
            this, &MainWindow::showHostContextMenu);
    populateLocalSubnets();
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
    m_portsTable->setSortingEnabled(true);
    layout->addWidget(m_portsTable, 1);
    m_portsStatus = new QLabel;
    layout->addWidget(m_portsStatus);
    connect(refresh, &QPushButton::clicked, this, &MainWindow::refreshLocalPorts);
    refreshLocalPorts();
    return page;
}

void MainWindow::populateLocalSubnets()
{
    const QString current = m_targetCombo->currentText();
    m_targetCombo->clear();
    const QList<LocalSubnet> subnets = NetworkInterfaces::ipv4Subnets();
    for (const LocalSubnet &subnet : subnets) {
        m_targetCombo->addItem(subnet.cidr);
        const int index = m_targetCombo->count() - 1;
        m_targetCombo->setItemData(index,
            QStringLiteral("%1 · адрес интерфейса %2").arg(subnet.interfaceName, subnet.address),
            Qt::ToolTipRole);
    }
    if (!current.isEmpty())
        m_targetCombo->setCurrentText(current);
    else if (m_targetCombo->count() == 0)
        m_targetCombo->setCurrentText(QStringLiteral("192.168.1.0/24"));
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
    const QVector<QHostAddress> addresses = Ipv4Range::parse(m_targetCombo->currentText(), &error);
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
    if (jobs > 250000 && QMessageBox::question(this, QStringLiteral("Большое сканирование"),
        QStringLiteral("Будет выполнено %1 TCP-проверок и %2 ICMP-проверок. Продолжить?")
            .arg(jobs).arg(addresses.size())) != QMessageBox::Yes) {
        return;
    }

    saveSettings();
    m_hostsTable->setSortingEnabled(false);
    m_hostsTable->setRowCount(0);
    m_hosts.clear();
    m_hostItems.clear();
    for (const QHostAddress &address : addresses)
        ensureHost(address.toString());
    m_hostsTable->setSortingEnabled(true);
    m_hostsTable->sortItems(0, Qt::AscendingOrder);
    applyHostFilter(m_filterEdit->text());

    m_discoveryCompleted = 0;
    m_discoveryTotal = addresses.size();
    m_portsCompleted = 0;
    m_portsTotal = jobs;
    m_pendingScanParts = 2;
    m_scanCancelled = false;
    m_scanButton->setEnabled(false);
    m_cancelButton->setEnabled(true);
    m_discovery.start(addresses, m_timeoutSpin->value());
    m_scanner.start(addresses, ports, m_timeoutSpin->value());
}

void MainWindow::cancelScan()
{
    m_scanCancelled = true;
    m_discovery.cancel();
    m_scanner.cancel();
}

void MainWindow::ensureHost(const QString &address)
{
    if (m_hosts.contains(address))
        return;
    HostUiState state;
    state.address = address;
    m_hosts.insert(address, state);
    const int row = m_hostsTable->rowCount();
    m_hostsTable->insertRow(row);
    auto *ipItem = new IpAddressItem(address);
    m_hostItems.insert(address, ipItem);
    m_hostsTable->setItem(row, 0, ipItem);
    for (int column = 1; column < m_hostsTable->columnCount(); ++column)
        m_hostsTable->setItem(row, column, new QTableWidgetItem);
    renderHost(address);
}

void MainWindow::updateHost(const NetworkHostResult &host)
{
    ensureHost(host.address);
    auto &state = m_hosts[host.address];
    state.status = QStringLiteral("Online");
    state.discoveryMethod = state.discoveryMethod.isEmpty() ? QStringLiteral("TCP") : state.discoveryMethod;
    if (!host.hostName.isEmpty())
        state.hostName = host.hostName;
    state.openPorts = host.openPorts;
    renderHost(host.address);
}

void MainWindow::updateDiscovery(const HostDiscoveryResult &result)
{
    ensureHost(result.address);
    auto &state = m_hosts[result.address];
    if (result.online) {
        state.status = QStringLiteral("Online");
        state.discoveryMethod = result.method;
        state.responseTimeMs = result.responseTimeMs;
    } else if (state.status != QStringLiteral("Online")) {
        state.status = QStringLiteral("No response");
    }
    renderHost(result.address);
}

void MainWindow::markTcpResponsive(const QString &address, const qint64 responseTimeMs)
{
    ensureHost(address);
    auto &state = m_hosts[address];
    state.status = QStringLiteral("Online");
    if (state.discoveryMethod.isEmpty())
        state.discoveryMethod = QStringLiteral("TCP");
    if (state.responseTimeMs < 0 || responseTimeMs < state.responseTimeMs)
        state.responseTimeMs = responseTimeMs;
    renderHost(address);
}

void MainWindow::setHostName(const QString &address, const QString &hostName)
{
    if (!m_hosts.contains(address))
        return;
    m_hosts[address].hostName = hostName;
    renderHost(address);
}

void MainWindow::renderHost(const QString &address)
{
    QTableWidgetItem *ipItem = m_hostItems.value(address);
    if (!ipItem)
        return;
    const int row = ipItem->row();
    const HostUiState &host = m_hosts[address];
    auto set = [this, row](int column, const QString &value) {
        m_hostsTable->item(row, column)->setText(value);
    };
    set(1, host.status);
    set(2, host.responseTimeMs >= 0 ? QStringLiteral("%1 мс").arg(host.responseTimeMs) : QStringLiteral("—"));
    set(3, host.hostName.isEmpty() ? QStringLiteral("—") : host.hostName);
    set(4, host.discoveryMethod.isEmpty() ? QStringLiteral("—") : host.discoveryMethod);
    set(5, formatPorts(host.openPorts));

    const QColor color = host.status == QStringLiteral("Online") ? QColor(34, 211, 164)
                       : host.status == QStringLiteral("No response") ? QColor(148, 163, 184)
                       : QColor(250, 204, 21);
    m_hostsTable->item(row, 1)->setForeground(color);
}

void MainWindow::updateCombinedProgress()
{
    const qint64 completed = m_discoveryCompleted + m_portsCompleted;
    const qint64 total = m_discoveryTotal + m_portsTotal;
    m_scanProgress->setMaximum(static_cast<int>(qMin<qint64>(total, std::numeric_limits<int>::max())));
    m_scanProgress->setValue(static_cast<int>(qMin<qint64>(completed, std::numeric_limits<int>::max())));
    const int online = std::count_if(m_hosts.cbegin(), m_hosts.cend(), [](const HostUiState &host) {
        return host.status == QStringLiteral("Online");
    });
    m_scanStatus->setText(QStringLiteral("Проверено %1 из %2 · доступно устройств: %3")
                              .arg(completed).arg(total).arg(online));
}

void MainWindow::scanPartFinished(const bool cancelled)
{
    m_scanCancelled = m_scanCancelled || cancelled;
    if (--m_pendingScanParts > 0)
        return;
    m_scanButton->setEnabled(true);
    m_cancelButton->setEnabled(false);
    const int online = std::count_if(m_hosts.cbegin(), m_hosts.cend(), [](const HostUiState &host) {
        return host.status == QStringLiteral("Online");
    });
    m_scanStatus->setText(m_scanCancelled
        ? QStringLiteral("Сканирование остановлено · доступно устройств: %1").arg(online)
        : QStringLiteral("Готово · доступно устройств: %1 из %2").arg(online).arg(m_hosts.size()));
}

void MainWindow::applyHostFilter(const QString &text)
{
    const QString needle = text.trimmed();
    for (int row = 0; row < m_hostsTable->rowCount(); ++row) {
        bool matches = needle.isEmpty();
        for (int column = 0; !matches && column < m_hostsTable->columnCount(); ++column)
            matches = m_hostsTable->item(row, column)->text().contains(needle, Qt::CaseInsensitive);
        m_hostsTable->setRowHidden(row, !matches);
    }
}

void MainWindow::showHostContextMenu(const QPoint &position)
{
    const QModelIndex index = m_hostsTable->indexAt(position);
    if (!index.isValid())
        return;
    const int row = index.row();
    QMenu menu(this);
    QAction *copyIp = menu.addAction(QStringLiteral("Копировать IP-адрес"));
    QAction *copyName = menu.addAction(QStringLiteral("Копировать имя хоста"));
    QAction *copyPorts = menu.addAction(QStringLiteral("Копировать порты"));
    QAction *selected = menu.exec(m_hostsTable->viewport()->mapToGlobal(position));
    if (!selected)
        return;
    const int column = selected == copyIp ? 0 : selected == copyName ? 3 : 5;
    QApplication::clipboard()->setText(m_hostsTable->item(row, column)->text());
}

QString MainWindow::serviceName(const quint16 port)
{
    static const QHash<quint16, QString> services{
        {20, QStringLiteral("FTP data")}, {21, QStringLiteral("FTP")}, {22, QStringLiteral("SSH")},
        {23, QStringLiteral("Telnet")}, {25, QStringLiteral("SMTP")}, {53, QStringLiteral("DNS")},
        {67, QStringLiteral("DHCP")}, {68, QStringLiteral("DHCP")}, {80, QStringLiteral("HTTP")},
        {110, QStringLiteral("POP3")}, {123, QStringLiteral("NTP")}, {135, QStringLiteral("RPC")},
        {139, QStringLiteral("NetBIOS")}, {143, QStringLiteral("IMAP")}, {389, QStringLiteral("LDAP")},
        {443, QStringLiteral("HTTPS")}, {445, QStringLiteral("SMB")}, {465, QStringLiteral("SMTPS")},
        {587, QStringLiteral("SMTP submission")}, {636, QStringLiteral("LDAPS")},
        {993, QStringLiteral("IMAPS")}, {995, QStringLiteral("POP3S")},
        {1433, QStringLiteral("MSSQL")}, {1521, QStringLiteral("Oracle")},
        {3306, QStringLiteral("MySQL")}, {3389, QStringLiteral("RDP")},
        {5432, QStringLiteral("PostgreSQL")}, {5900, QStringLiteral("VNC")},
        {6379, QStringLiteral("Redis")}, {8080, QStringLiteral("HTTP-alt")},
        {8443, QStringLiteral("HTTPS-alt")}, {27017, QStringLiteral("MongoDB")}
    };
    return services.value(port);
}

QString MainWindow::formatPorts(const QList<quint16> &ports)
{
    if (ports.isEmpty())
        return QStringLiteral("—");
    QStringList result;
    for (quint16 port : ports) {
        const QString service = serviceName(port);
        result.append(service.isEmpty() ? QString::number(port)
                                       : QStringLiteral("%1 (%2)").arg(port).arg(service));
    }
    return result.join(QStringLiteral(", "));
}

void MainWindow::refreshLocalPorts()
{
    QString error;
    const QList<LocalPortEntry> entries = LocalPortsProvider::query(&error);
    m_portsTable->setSortingEnabled(false);
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
    m_portsTable->setSortingEnabled(true);
    m_portsStatus->setText(error.isEmpty()
        ? QStringLiteral("Найдено локальных сокетов: %1").arg(entries.size()) : error);
}

void MainWindow::loadSettings()
{
    QSettings settings;
    m_targetCombo->setCurrentText(settings.value(QStringLiteral("scanner/target"),
                                                  m_targetCombo->currentText()).toString());
    m_portsEdit->setText(settings.value(QStringLiteral("scanner/ports"), m_portsEdit->text()).toString());
    m_timeoutSpin->setValue(settings.value(QStringLiteral("scanner/timeout"), 500).toInt());
    restoreGeometry(settings.value(QStringLiteral("window/geometry")).toByteArray());
}

void MainWindow::saveSettings() const
{
    QSettings settings;
    settings.setValue(QStringLiteral("scanner/target"), m_targetCombo->currentText());
    settings.setValue(QStringLiteral("scanner/ports"), m_portsEdit->text());
    settings.setValue(QStringLiteral("scanner/timeout"), m_timeoutSpin->value());
    settings.setValue(QStringLiteral("window/geometry"), saveGeometry());
}

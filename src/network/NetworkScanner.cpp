#include "NetworkScanner.h"

#include <QHostInfo>
#include <QDateTime>
#include <QTcpSocket>
#include <QTimer>
#include <algorithm>

NetworkScanner::NetworkScanner(QObject *parent)
    : QObject(parent)
{
}

void NetworkScanner::start(const QVector<QHostAddress> &addresses, const QList<quint16> &ports,
                           const int timeoutMs, const int maximumConnections)
{
    if (m_running || addresses.isEmpty() || ports.isEmpty())
        return;

    m_addresses = addresses;
    m_ports = ports;
    m_results.clear();
    m_resolving.clear();
    m_nextJob = 0;
    m_completedJobs = 0;
    m_activeJobs = 0;
    m_timeoutMs = qBound(50, timeoutMs, 10000);
    m_maximumConnections = qBound(1, maximumConnections, 512);
    m_totalJobs = static_cast<qint64>(m_addresses.size()) * m_ports.size();
    m_running = true;
    m_cancelled = false;
    ++m_generation;
    emit progressChanged(0, m_totalJobs);
    launchMore();
}

void NetworkScanner::cancel()
{
    if (!m_running)
        return;
    m_cancelled = true;
    const auto sockets = findChildren<QTcpSocket *>();
    for (QTcpSocket *socket : sockets)
        socket->abort();
}

void NetworkScanner::launchMore()
{
    while (m_running && !m_cancelled && m_activeJobs < m_maximumConnections && m_nextJob < m_totalJobs)
        startJob(m_nextJob++);

    if (m_running && m_activeJobs == 0 && (m_cancelled || m_nextJob >= m_totalJobs)) {
        m_running = false;
        emit finished(m_cancelled);
    }
}

void NetworkScanner::startJob(const qint64 index)
{
    const qint64 portCount = m_ports.size();
    const QString address = m_addresses.at(index / portCount).toString();
    const quint16 port = m_ports.at(index % portCount);

    auto *socket = new QTcpSocket(this);
    auto *timer = new QTimer(socket);
    timer->setSingleShot(true);
    socket->setProperty("netpeek.address", address);
    socket->setProperty("netpeek.port", port);
    socket->setProperty("netpeek.completed", false);
    socket->setProperty("netpeek.started", QDateTime::currentMSecsSinceEpoch());
    ++m_activeJobs;

    connect(socket, &QTcpSocket::connected, this, [this, socket] {
        completeJob(socket, true, true);
    });
    connect(socket, &QTcpSocket::errorOccurred, this, [this, socket](QAbstractSocket::SocketError error) {
        completeJob(socket, false, error == QAbstractSocket::ConnectionRefusedError);
    });
    connect(timer, &QTimer::timeout, this, [this, socket] {
        socket->abort();
        completeJob(socket, false, false);
    });

    timer->start(m_timeoutMs);
    socket->connectToHost(address, port);
}

void NetworkScanner::completeJob(QTcpSocket *socket, const bool isOpen, const bool isResponsive)
{
    if (socket->property("netpeek.completed").toBool())
        return;
    socket->setProperty("netpeek.completed", true);

    const QString address = socket->property("netpeek.address").toString();
    const quint16 port = socket->property("netpeek.port").value<quint16>();
    if (isResponsive && !m_cancelled) {
        const qint64 elapsed = QDateTime::currentMSecsSinceEpoch()
                             - socket->property("netpeek.started").toLongLong();
        emit hostResponsive(address, elapsed);
        const bool firstResponse = !m_results.contains(address);
        auto &host = m_results[address];
        host.address = address;
        if (firstResponse)
            emit hostUpdated(host);
        resolveHostName(address);
    }
    if (isOpen && !m_cancelled) {
        auto &host = m_results[address];
        host.address = address;
        if (!host.openPorts.contains(port)) {
            host.openPorts.append(port);
            std::sort(host.openPorts.begin(), host.openPorts.end());
        }
        emit hostUpdated(host);
        resolveHostName(address);
    }

    socket->disconnect(this);
    socket->abort();
    socket->deleteLater();
    --m_activeJobs;
    ++m_completedJobs;
    emit progressChanged(m_completedJobs, m_totalJobs);
    launchMore();
}

void NetworkScanner::resolveHostName(const QString &address)
{
    if (m_resolving.contains(address) || !m_results.value(address).hostName.isEmpty())
        return;
    m_resolving.insert(address);

    const quint64 generation = m_generation;
    QHostInfo::lookupHost(address, this, [this, address, generation](const QHostInfo &info) {
        if (generation != m_generation)
            return;
        m_resolving.remove(address);
        if (!m_results.contains(address))
            return;
        if (info.error() == QHostInfo::NoError && !info.hostName().isEmpty())
            m_results[address].hostName = info.hostName();
        emit hostUpdated(m_results[address]);
    });
}

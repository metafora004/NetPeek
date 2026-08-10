#include "HostDiscovery.h"

#include <QDateTime>
#include <QHostInfo>
#include <QProcess>
#include <QTimer>

HostDiscovery::HostDiscovery(QObject *parent)
    : QObject(parent)
{
}

void HostDiscovery::start(const QVector<QHostAddress> &addresses, const int timeoutMs,
                          const int maximumProcesses)
{
    if (m_running || addresses.isEmpty())
        return;
    m_addresses = addresses;
    m_next = 0;
    m_completed = 0;
    m_active = 0;
    m_timeoutMs = qBound(100, timeoutMs, 10000);
    m_maximumProcesses = qBound(1, maximumProcesses, 64);
    m_running = true;
    m_cancelled = false;
    ++m_generation;
    emit progressChanged(0, m_addresses.size());
    launchMore();
}

void HostDiscovery::cancel()
{
    if (!m_running)
        return;
    m_cancelled = true;
    const auto processes = findChildren<QProcess *>();
    for (QProcess *process : processes)
        process->kill();
}

void HostDiscovery::launchMore()
{
    while (m_running && !m_cancelled && m_active < m_maximumProcesses
           && m_next < m_addresses.size()) {
        startPing(m_addresses.at(m_next++).toString());
    }

    if (m_running && m_active == 0 && (m_cancelled || m_next >= m_addresses.size())) {
        m_running = false;
        emit finished(m_cancelled);
    }
}

void HostDiscovery::startPing(const QString &address)
{
    auto *process = new QProcess(this);
    auto *timer = new QTimer(process);
    timer->setSingleShot(true);
    process->setProcessChannelMode(QProcess::MergedChannels);
    process->setProperty("netpeek.address", address);
    process->setProperty("netpeek.started", QDateTime::currentMSecsSinceEpoch());
    process->setProperty("netpeek.completed", false);
    ++m_active;

    connect(process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
            [this, process](const int exitCode, QProcess::ExitStatus status) {
        completePing(process, status == QProcess::NormalExit && exitCode == 0);
    });
    connect(process, &QProcess::errorOccurred, this, [this, process](QProcess::ProcessError error) {
        if (error == QProcess::FailedToStart)
            completePing(process, false);
    });
    connect(timer, &QTimer::timeout, this, [this, process] {
        process->kill();
        completePing(process, false);
    });

#ifdef Q_OS_WIN
    const QStringList arguments{QStringLiteral("-n"), QStringLiteral("1"),
                                QStringLiteral("-w"), QString::number(m_timeoutMs), address};
#elif defined(Q_OS_MACOS)
    const QStringList arguments{QStringLiteral("-n"), QStringLiteral("-c"), QStringLiteral("1"),
                                QStringLiteral("-W"), QString::number(m_timeoutMs), address};
#else
    const int seconds = qMax(1, (m_timeoutMs + 999) / 1000);
    const QStringList arguments{QStringLiteral("-n"), QStringLiteral("-c"), QStringLiteral("1"),
                                QStringLiteral("-W"), QString::number(seconds), address};
#endif
    timer->start(m_timeoutMs + 250);
    process->start(QStringLiteral("ping"), arguments);
}

void HostDiscovery::completePing(QProcess *process, const bool online)
{
    if (process->property("netpeek.completed").toBool())
        return;
    process->setProperty("netpeek.completed", true);
    const QString address = process->property("netpeek.address").toString();
    const qint64 elapsed = QDateTime::currentMSecsSinceEpoch()
                         - process->property("netpeek.started").toLongLong();

    if (!m_cancelled) {
        emit hostChecked({address, online, online ? elapsed : -1,
                          online ? QStringLiteral("ICMP") : QString()});
        if (online)
            resolveName(address);
    }

    process->disconnect(this);
    process->deleteLater();
    --m_active;
    ++m_completed;
    emit progressChanged(m_completed, m_addresses.size());
    launchMore();
}

void HostDiscovery::resolveName(const QString &address)
{
    const quint64 generation = m_generation;
    QHostInfo::lookupHost(address, this, [this, address, generation](const QHostInfo &info) {
        if (generation != m_generation || info.error() != QHostInfo::NoError)
            return;
        if (!info.hostName().isEmpty())
            emit hostNameResolved(address, info.hostName());
    });
}

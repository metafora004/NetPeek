#pragma once

#include <QHostAddress>
#include <QObject>
#include <QVector>

class QProcess;

struct HostDiscoveryResult
{
    QString address;
    bool online = false;
    qint64 responseTimeMs = -1;
    QString method;
};

Q_DECLARE_METATYPE(HostDiscoveryResult)

class HostDiscovery final : public QObject
{
    Q_OBJECT

public:
    explicit HostDiscovery(QObject *parent = nullptr);

    bool isRunning() const { return m_running; }
    void start(const QVector<QHostAddress> &addresses, int timeoutMs, int maximumProcesses = 32);
    void cancel();

signals:
    void hostChecked(const HostDiscoveryResult &result);
    void hostNameResolved(const QString &address, const QString &hostName);
    void progressChanged(qint64 completed, qint64 total);
    void finished(bool cancelled);

private:
    void launchMore();
    void startPing(const QString &address);
    void completePing(QProcess *process, bool online);
    void resolveName(const QString &address);

    QVector<QHostAddress> m_addresses;
    qint64 m_next = 0;
    qint64 m_completed = 0;
    int m_active = 0;
    int m_timeoutMs = 500;
    int m_maximumProcesses = 32;
    bool m_running = false;
    bool m_cancelled = false;
    quint64 m_generation = 0;
};

#pragma once

#include <QHash>
#include <QHostAddress>
#include <QList>
#include <QObject>
#include <QSet>
#include <QString>
#include <QVector>

class QTcpSocket;

struct NetworkHostResult
{
    QString address;
    QString hostName;
    QList<quint16> openPorts;
};

Q_DECLARE_METATYPE(NetworkHostResult)

class NetworkScanner final : public QObject
{
    Q_OBJECT

public:
    explicit NetworkScanner(QObject *parent = nullptr);

    bool isRunning() const { return m_running; }
    void start(const QVector<QHostAddress> &addresses, const QList<quint16> &ports,
               int timeoutMs, int maximumConnections = 128);
    void cancel();

signals:
    void hostUpdated(const NetworkHostResult &host);
    void hostResponsive(const QString &address, qint64 responseTimeMs);
    void progressChanged(qint64 completed, qint64 total);
    void finished(bool cancelled);

private:
    void launchMore();
    void startJob(qint64 index);
    void completeJob(QTcpSocket *socket, bool isOpen, bool isResponsive);
    void resolveHostName(const QString &address);

    QVector<QHostAddress> m_addresses;
    QList<quint16> m_ports;
    QHash<QString, NetworkHostResult> m_results;
    QSet<QString> m_resolving;
    qint64 m_nextJob = 0;
    qint64 m_completedJobs = 0;
    qint64 m_totalJobs = 0;
    int m_activeJobs = 0;
    int m_timeoutMs = 350;
    int m_maximumConnections = 128;
    bool m_running = false;
    bool m_cancelled = false;
    quint64 m_generation = 0;
};

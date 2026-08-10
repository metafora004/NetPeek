#include "LocalPortsProvider.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QHostAddress>
#include <QProcess>
#include <QRegularExpression>
#include <algorithm>
#include <iterator>

#ifdef Q_OS_WIN
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#endif

namespace {

void sortEntries(QList<LocalPortEntry> &entries)
{
    std::sort(entries.begin(), entries.end(), [](const LocalPortEntry &a, const LocalPortEntry &b) {
        if (a.port != b.port) return a.port < b.port;
        if (a.protocol != b.protocol) return a.protocol < b.protocol;
        return a.pid < b.pid;
    });
}

#ifdef Q_OS_LINUX

struct ProcessInfo { qint64 pid = -1; QString name; };

QHash<QString, ProcessInfo> linuxSocketOwners()
{
    QHash<QString, ProcessInfo> owners;
    const QRegularExpression numeric(QStringLiteral("^[0-9]+$"));
    const QRegularExpression socketPattern(QStringLiteral("^socket:\\[([0-9]+)\\]$"));
    const QDir proc(QStringLiteral("/proc"));

    for (const QString &pidText : proc.entryList(QDir::Dirs | QDir::NoDotAndDotDot)) {
        if (!numeric.match(pidText).hasMatch())
            continue;
        QFile comm(proc.filePath(pidText + QStringLiteral("/comm")));
        QString name;
        if (comm.open(QIODevice::ReadOnly))
            name = QString::fromUtf8(comm.readAll()).trimmed();

        const QDir fd(proc.filePath(pidText + QStringLiteral("/fd")));
        for (const QFileInfo &entry : fd.entryInfoList(QDir::Files | QDir::System | QDir::NoDotAndDotDot)) {
            const auto match = socketPattern.match(entry.symLinkTarget());
            if (match.hasMatch())
                owners.insert(match.captured(1), {pidText.toLongLong(), name});
        }
    }
    return owners;
}

QString linuxAddress(const QString &hex, const bool ipv6)
{
    if (!ipv6) {
        bool ok = false;
        const quint32 raw = hex.toUInt(&ok, 16);
        if (!ok) return QStringLiteral("?");
        const quint32 value = ((raw & 0x000000ffU) << 24) | ((raw & 0x0000ff00U) << 8)
                            | ((raw & 0x00ff0000U) >> 8) | ((raw & 0xff000000U) >> 24);
        return QHostAddress(value).toString();
    }

    if (hex.size() != 32)
        return QStringLiteral("?");
    Q_IPV6ADDR bytes{};
    for (int word = 0; word < 4; ++word) {
        for (int byte = 0; byte < 4; ++byte) {
            bool ok = false;
            bytes.c[word * 4 + byte] = static_cast<quint8>(hex.mid(word * 8 + (3 - byte) * 2, 2).toUInt(&ok, 16));
            if (!ok) return QStringLiteral("?");
        }
    }
    return QHostAddress(bytes).toString();
}

void readLinuxTable(const QString &path, const QString &protocol, const bool ipv6,
                    const QHash<QString, ProcessInfo> &owners, QList<LocalPortEntry> &result)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
        return;
    file.readLine();
    while (!file.atEnd()) {
        const QString line = QString::fromLatin1(file.readLine()).trimmed();
        const QStringList fields = line.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
        if (fields.size() < 10)
            continue;
        if (protocol.startsWith(QStringLiteral("TCP")) && fields[3] != QStringLiteral("0A"))
            continue;

        const QStringList endpoint = fields[1].split(QLatin1Char(':'));
        if (endpoint.size() != 2)
            continue;
        bool portOk = false;
        const uint port = endpoint[1].toUInt(&portOk, 16);
        if (!portOk || port > 65535)
            continue;

        const ProcessInfo owner = owners.value(fields[9]);
        result.append({protocol, linuxAddress(endpoint[0], ipv6), static_cast<quint16>(port),
                       owner.pid, owner.name});
    }
}

#endif

#ifdef Q_OS_WIN

QString windowsProcessName(const DWORD pid)
{
    const HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process)
        return {};
    wchar_t buffer[32768];
    DWORD size = static_cast<DWORD>(std::size(buffer));
    QString name;
    if (QueryFullProcessImageNameW(process, 0, buffer, &size))
        name = QFileInfo(QString::fromWCharArray(buffer, static_cast<int>(size))).fileName();
    CloseHandle(process);
    return name;
}

void readWindowsTcp4(QList<LocalPortEntry> &result)
{
    ULONG size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
    QByteArray data;
    data.resize(static_cast<qsizetype>(size));
    auto *table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(data.data());
    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0) != NO_ERROR)
        return;
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto &row = table->table[i];
        result.append({QStringLiteral("TCP"), QHostAddress(ntohl(row.dwLocalAddr)).toString(),
                       ntohs(static_cast<u_short>(row.dwLocalPort)), row.dwOwningPid,
                       windowsProcessName(row.dwOwningPid)});
    }
}

void readWindowsUdp4(QList<LocalPortEntry> &result)
{
    ULONG size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    QByteArray data;
    data.resize(static_cast<qsizetype>(size));
    auto *table = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(data.data());
    if (GetExtendedUdpTable(table, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != NO_ERROR)
        return;
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto &row = table->table[i];
        result.append({QStringLiteral("UDP"), QHostAddress(ntohl(row.dwLocalAddr)).toString(),
                       ntohs(static_cast<u_short>(row.dwLocalPort)), row.dwOwningPid,
                       windowsProcessName(row.dwOwningPid)});
    }
}

#endif

#ifdef Q_OS_MACOS

QList<LocalPortEntry> queryMac(QString *error)
{
    QProcess process;
    process.start(QStringLiteral("lsof"), {QStringLiteral("-nP"), QStringLiteral("-iTCP"),
                                           QStringLiteral("-sTCP:LISTEN"), QStringLiteral("-iUDP"),
                                           QStringLiteral("-FpcnP")});
    if (!process.waitForFinished(5000)) {
        process.kill();
        if (error) *error = QStringLiteral("Не удалось выполнить lsof.");
        return {};
    }

    QList<LocalPortEntry> result;
    qint64 pid = -1;
    QString command;
    QString protocol;
    const QString output = QString::fromUtf8(process.readAllStandardOutput());
    for (const QString &line : output.split(QLatin1Char('\n'), Qt::SkipEmptyParts)) {
        const QChar type = line[0];
        const QString value = line.mid(1);
        if (type == QLatin1Char('p')) pid = value.toLongLong();
        else if (type == QLatin1Char('c')) command = value;
        else if (type == QLatin1Char('P')) protocol = value;
        else if (type == QLatin1Char('n')) {
            QString endpoint = value.section(QStringLiteral("->"), 0, 0);
            const qsizetype colon = endpoint.lastIndexOf(QLatin1Char(':'));
            bool ok = false;
            const uint port = endpoint.mid(colon + 1).toUInt(&ok);
            if (colon > 0 && ok && port <= 65535)
                result.append({protocol, endpoint.left(colon), static_cast<quint16>(port), pid, command});
        }
    }
    return result;
}

#endif

} // namespace

QList<LocalPortEntry> LocalPortsProvider::query(QString *error)
{
    QList<LocalPortEntry> result;

#ifdef Q_OS_LINUX
    const auto owners = linuxSocketOwners();
    readLinuxTable(QStringLiteral("/proc/net/tcp"), QStringLiteral("TCP"), false, owners, result);
    readLinuxTable(QStringLiteral("/proc/net/tcp6"), QStringLiteral("TCP6"), true, owners, result);
    readLinuxTable(QStringLiteral("/proc/net/udp"), QStringLiteral("UDP"), false, owners, result);
    readLinuxTable(QStringLiteral("/proc/net/udp6"), QStringLiteral("UDP6"), true, owners, result);
#elif defined(Q_OS_WIN)
    readWindowsTcp4(result);
    readWindowsUdp4(result);
#elif defined(Q_OS_MACOS)
    result = queryMac(error);
#else
    if (error) *error = QStringLiteral("Эта операционная система пока не поддерживается.");
#endif

    sortEntries(result);
    return result;
}

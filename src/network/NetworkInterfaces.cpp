#include "NetworkInterfaces.h"

#include <QAbstractSocket>
#include <QHostAddress>
#include <QNetworkAddressEntry>
#include <QNetworkInterface>
#include <QSet>

QList<LocalSubnet> NetworkInterfaces::ipv4Subnets()
{
    QList<LocalSubnet> result;
    QSet<QString> seen;

    for (const QNetworkInterface &interface : QNetworkInterface::allInterfaces()) {
        const auto flags = interface.flags();
        if (!flags.testFlag(QNetworkInterface::IsUp)
            || flags.testFlag(QNetworkInterface::IsLoopBack)) {
            continue;
        }

        for (const QNetworkAddressEntry &entry : interface.addressEntries()) {
            if (entry.ip().protocol() != QAbstractSocket::IPv4Protocol)
                continue;
            const int prefix = entry.prefixLength();
            if (prefix < 0 || prefix > 32)
                continue;

            const quint32 ip = entry.ip().toIPv4Address();
            const quint32 mask = prefix == 0 ? 0U : 0xffffffffU << (32 - prefix);
            const QString cidr = QHostAddress(ip & mask).toString()
                               + QLatin1Char('/') + QString::number(prefix);
            if (seen.contains(cidr))
                continue;
            seen.insert(cidr);
            result.append({interface.humanReadableName(), entry.ip().toString(), cidr});
        }
    }
    return result;
}

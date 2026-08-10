#pragma once

#include <QList>
#include <QString>

struct LocalSubnet
{
    QString interfaceName;
    QString address;
    QString cidr;
};

class NetworkInterfaces
{
public:
    static QList<LocalSubnet> ipv4Subnets();
};

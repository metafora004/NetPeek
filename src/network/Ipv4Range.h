#pragma once

#include <QHostAddress>
#include <QString>
#include <QVector>

class Ipv4Range
{
public:
    static QVector<QHostAddress> parse(const QString &text, QString *error,
                                       qsizetype maximumAddresses = 4096);

private:
    static bool toIpv4(const QString &text, quint32 *value);
};


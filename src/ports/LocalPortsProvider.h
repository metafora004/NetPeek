#pragma once

#include <QList>
#include <QString>

struct LocalPortEntry
{
    QString protocol;
    QString localAddress;
    quint16 port = 0;
    qint64 pid = -1;
    QString processName;
};

class LocalPortsProvider
{
public:
    static QList<LocalPortEntry> query(QString *error = nullptr);
};


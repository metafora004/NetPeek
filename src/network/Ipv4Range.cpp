#include "Ipv4Range.h"

#include <QStringList>
#include <limits>

bool Ipv4Range::toIpv4(const QString &text, quint32 *value)
{
    QHostAddress address;
    if (!address.setAddress(text.trimmed()) || address.protocol() != QAbstractSocket::IPv4Protocol)
        return false;
    *value = address.toIPv4Address();
    return true;
}

QVector<QHostAddress> Ipv4Range::parse(const QString &input, QString *error,
                                       const qsizetype maximumAddresses)
{
    const QString text = input.trimmed();
    quint32 first = 0;
    quint32 last = 0;

    if (text.contains(QLatin1Char('/'))) {
        const QStringList parts = text.split(QLatin1Char('/'));
        bool prefixOk = false;
        const int prefix = parts.value(1).toInt(&prefixOk);
        quint32 address = 0;
        if (parts.size() != 2 || !toIpv4(parts[0], &address) || !prefixOk || prefix < 0 || prefix > 32) {
            if (error) *error = QStringLiteral("Некорректная IPv4 CIDR-сеть.");
            return {};
        }

        const quint32 mask = prefix == 0 ? 0U : std::numeric_limits<quint32>::max() << (32 - prefix);
        first = address & mask;
        last = first | ~mask;
        if (prefix <= 30) {
            ++first;
            --last;
        }
    } else if (text.contains(QLatin1Char('-'))) {
        const qsizetype separator = text.indexOf(QLatin1Char('-'));
        const QString left = text.left(separator).trimmed();
        const QString right = text.mid(separator + 1).trimmed();
        if (!toIpv4(left, &first)) {
            if (error) *error = QStringLiteral("Некорректный начальный IPv4-адрес.");
            return {};
        }

        if (!toIpv4(right, &last)) {
            bool octetOk = false;
            const uint octet = right.toUInt(&octetOk);
            if (!octetOk || octet > 255) {
                if (error) *error = QStringLiteral("Некорректный конечный IPv4-адрес.");
                return {};
            }
            last = (first & 0xffffff00U) | octet;
        }

        if (last < first) {
            if (error) *error = QStringLiteral("Конец диапазона меньше его начала.");
            return {};
        }
    } else {
        if (!toIpv4(text, &first)) {
            if (error) *error = QStringLiteral("Введите IPv4-адрес, диапазон или CIDR-сеть.");
            return {};
        }
        last = first;
    }

    const quint64 count = static_cast<quint64>(last) - first + 1;
    if (count > static_cast<quint64>(maximumAddresses)) {
        if (error) *error = QStringLiteral("Диапазон содержит %1 адресов; максимум — %2.")
                                .arg(count).arg(maximumAddresses);
        return {};
    }

    QVector<QHostAddress> result;
    result.reserve(static_cast<qsizetype>(count));
    for (quint64 value = first; value <= last; ++value)
        result.emplaceBack(static_cast<quint32>(value));
    return result;
}

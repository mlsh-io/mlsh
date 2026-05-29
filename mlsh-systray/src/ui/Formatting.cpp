#include "ui/Formatting.h"

QString formatBytes(quint64 bytes)
{
    constexpr double gb = 1024.0 * 1024.0 * 1024.0;
    constexpr double mb = 1024.0 * 1024.0;
    constexpr double kb = 1024.0;
    const double b = static_cast<double>(bytes);

    if (b >= gb)
        return QStringLiteral("%1 GB").arg(b / gb, 0, 'f', 1);
    if (b >= mb)
        return QStringLiteral("%1 MB").arg(b / mb, 0, 'f', 1);
    if (b >= kb)
        return QStringLiteral("%1 KB").arg(b / kb, 0, 'f', 1);
    return QStringLiteral("%1 B").arg(bytes);
}

QString formatUptime(quint64 seconds)
{
    if (seconds < 60)
        return QStringLiteral("%1s").arg(seconds);
    if (seconds < 3600)
        return QStringLiteral("%1m %2s").arg(seconds / 60).arg(seconds % 60);
    const quint64 hours = seconds / 3600;
    const quint64 mins = (seconds % 3600) / 60;
    return QStringLiteral("%1h %2m").arg(hours).arg(mins);
}

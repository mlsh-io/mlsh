#include "ui/IconFactory.h"

#include "ui/Theme.h"

#include <QPainter>
#include <QPainterPath>

namespace IconFactory {

namespace {

QColor colorFor(AppState::OverallState state)
{
    switch (state) {
    case AppState::OverallState::Connected:
        return Theme::Colors::connected();
    case AppState::OverallState::Partial:
        return Theme::Colors::partial();
    case AppState::OverallState::Disconnected:
        return Theme::Colors::disconnected();
    case AppState::OverallState::DaemonDown:
        return Theme::Colors::daemonDown();
    }
    return Theme::Colors::disconnected();
}

// Draw the MLSH hexagon (SVG viewBox 0..256) into a `size`×`size` pixmap.
QPixmap drawLogo(int size, const QColor &color, bool filled)
{
    QPixmap pm(size, size);
    pm.fill(Qt::transparent);

    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing, true);

    // Map the 256-unit design space into the pixmap with a small padding.
    const qreal pad = size * 0.06;
    const qreal scale = (size - 2 * pad) / 256.0;
    p.translate(pad, pad);
    p.scale(scale, scale);

    auto poly = [](std::initializer_list<QPointF> pts) {
        QPolygonF poly;
        for (const QPointF &pt : pts)
            poly << pt;
        return poly;
    };

    if (filled) {
        // Three cube faces, descending opacity for a 3D look.
        QColor face = color;
        face.setAlphaF(0.9);
        p.setPen(Qt::NoPen);
        p.setBrush(face);
        p.drawPolygon(poly({{128, 39}, {52, 83}, {128, 127}, {204, 83}})); // top

        face.setAlphaF(0.6);
        p.setBrush(face);
        p.drawPolygon(poly({{52, 83}, {52, 171}, {128, 215}, {128, 127}})); // left

        face.setAlphaF(0.35);
        p.setBrush(face);
        p.drawPolygon(poly({{204, 83}, {128, 127}, {128, 215}, {204, 171}})); // right
    }

    QPen pen(color);
    pen.setCapStyle(Qt::RoundCap);
    pen.setJoinStyle(Qt::RoundJoin);
    p.setBrush(Qt::NoBrush);

    // Outer hexagon.
    pen.setWidthF(filled ? 12 : 16);
    p.setPen(pen);
    p.drawPolygon(poly({{128, 7}, {24, 67}, {24, 187}, {128, 247}, {232, 187}, {232, 67}}));

    // Inner cube edges.
    pen.setWidthF(filled ? 8 : 12);
    p.setPen(pen);
    p.drawPolygon(poly({{128, 39}, {52, 83}, {128, 127}, {204, 83}})); // top diamond
    p.drawLine(QPointF(128, 127), QPointF(128, 215));                  // vertical center
    p.drawLine(QPointF(52, 83), QPointF(52, 171));                     // left vertical
    p.drawLine(QPointF(204, 83), QPointF(204, 171));                   // right vertical

    p.end();
    return pm;
}

} // namespace

QIcon trayIcon(AppState::OverallState state)
{
    const QColor color = colorFor(state);
    const bool filled = state == AppState::OverallState::Connected
        || state == AppState::OverallState::Partial;

    QIcon icon;
    for (int s : {16, 24, 32, 48, 64})
        icon.addPixmap(drawLogo(s, color, filled));
    return icon;
}

QIcon appIcon()
{
    QIcon icon;
    for (int s : {16, 32, 48, 64, 128, 256})
        icon.addPixmap(drawLogo(s, QColor(0x1d, 0x1d, 0x1f), true));
    return icon;
}

QPixmap statusDot(const QColor &color, int size)
{
    QPixmap pm(size, size);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setPen(Qt::NoPen);
    p.setBrush(color);
    p.drawEllipse(0, 0, size, size);
    p.end();
    return pm;
}

QIcon dotIcon(const QColor &color, int size)
{
    return QIcon(statusDot(color, size));
}

QIcon plusIcon(const QColor &color)
{
    const int s = 32;
    QPixmap pm(s, s);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing, true);
    QPen pen(color);
    pen.setWidthF(s * 0.14);
    pen.setCapStyle(Qt::RoundCap);
    p.setPen(pen);
    const qreal m = s * 0.24;
    p.drawLine(QPointF(s / 2.0, m), QPointF(s / 2.0, s - m));
    p.drawLine(QPointF(m, s / 2.0), QPointF(s - m, s / 2.0));
    p.end();
    return QIcon(pm);
}

} // namespace IconFactory

import SwiftUI
import AppKit

/// Menu bar icon using the MLSH hexagonal logo.
/// Outline when disconnected, solid filled cube when connected.
struct MenuBarIcon: View {
    let state: OverallState

    var body: some View {
        Image(nsImage: icon)
            .renderingMode(.template)
    }

    private var icon: NSImage {
        switch state {
        case .connected, .partial:
            return Self.filledIcon
        case .disconnected, .daemonDown:
            return Self.outlineIcon
        }
    }

    // MARK: - Cached icons

    /// Solid filled cube — connection active.
    private static let filledIcon: NSImage = drawIcon(filled: true)

    /// Outline only — disconnected / daemon down.
    private static let outlineIcon: NSImage = drawIcon(filled: false)

    /// Draw the MLSH hexagonal cube logo.
    /// When `filled`, the three cube faces are filled in with varying opacity
    /// to give a 3D solid look. When outline, just strokes.
    private static func drawIcon(filled: Bool) -> NSImage {
        let size = NSSize(width: 22, height: 22)
        let image = NSImage(size: size, flipped: true) { _ in
            guard let ctx = NSGraphicsContext.current?.cgContext else { return false }

            // SVG viewBox 0..256 → 18x18 with 1px padding
            let scale: CGFloat = 20.0 / 256.0
            let offset: CGFloat = 1.0

            ctx.translateBy(x: offset, y: offset)
            ctx.scaleBy(x: scale, y: scale)

            let color = NSColor.black

            if filled {
                // Top face (brightest)
                ctx.setFillColor(color.withAlphaComponent(0.9).cgColor)
                ctx.move(to: CGPoint(x: 128, y: 39))
                ctx.addLine(to: CGPoint(x: 52, y: 83))
                ctx.addLine(to: CGPoint(x: 128, y: 127))
                ctx.addLine(to: CGPoint(x: 204, y: 83))
                ctx.closePath()
                ctx.fillPath()

                // Left face (medium)
                ctx.setFillColor(color.withAlphaComponent(0.6).cgColor)
                ctx.move(to: CGPoint(x: 52, y: 83))
                ctx.addLine(to: CGPoint(x: 52, y: 171))
                ctx.addLine(to: CGPoint(x: 128, y: 215))
                ctx.addLine(to: CGPoint(x: 128, y: 127))
                ctx.closePath()
                ctx.fillPath()

                // Right face (darkest)
                ctx.setFillColor(color.withAlphaComponent(0.35).cgColor)
                ctx.move(to: CGPoint(x: 204, y: 83))
                ctx.addLine(to: CGPoint(x: 128, y: 127))
                ctx.addLine(to: CGPoint(x: 128, y: 215))
                ctx.addLine(to: CGPoint(x: 204, y: 171))
                ctx.closePath()
                ctx.fillPath()
            }

            // Outer hexagon stroke
            ctx.setStrokeColor(color.cgColor)
            ctx.setLineWidth(filled ? 12 : 16)
            ctx.setLineCap(.round)
            ctx.setLineJoin(.round)

            ctx.move(to: CGPoint(x: 128, y: 7))
            ctx.addLine(to: CGPoint(x: 24, y: 67))
            ctx.addLine(to: CGPoint(x: 24, y: 187))
            ctx.addLine(to: CGPoint(x: 128, y: 247))
            ctx.addLine(to: CGPoint(x: 232, y: 187))
            ctx.addLine(to: CGPoint(x: 232, y: 67))
            ctx.closePath()
            ctx.strokePath()

            // Inner cube edges
            ctx.setLineWidth(filled ? 8 : 12)

            // Top diamond
            ctx.move(to: CGPoint(x: 128, y: 39))
            ctx.addLine(to: CGPoint(x: 52, y: 83))
            ctx.addLine(to: CGPoint(x: 128, y: 127))
            ctx.addLine(to: CGPoint(x: 204, y: 83))
            ctx.closePath()
            ctx.strokePath()

            // Vertical center
            ctx.move(to: CGPoint(x: 128, y: 127))
            ctx.addLine(to: CGPoint(x: 128, y: 215))
            ctx.strokePath()

            // Left vertical
            ctx.move(to: CGPoint(x: 52, y: 83))
            ctx.addLine(to: CGPoint(x: 52, y: 171))
            ctx.strokePath()

            // Right vertical
            ctx.move(to: CGPoint(x: 204, y: 83))
            ctx.addLine(to: CGPoint(x: 204, y: 171))
            ctx.strokePath()

            return true
        }
        image.isTemplate = true
        return image
    }
}

import SwiftUI

/// Centralized design tokens for the MLSH menu bar app.
enum Theme {

    // MARK: - Spacing (8pt grid)

    enum Spacing {
        static let xxs: CGFloat = 2
        static let xs: CGFloat = 4
        static let sm: CGFloat = 8
        static let md: CGFloat = 12
        static let lg: CGFloat = 16
        static let xl: CGFloat = 20
    }

    // MARK: - Dimensions

    enum Dimensions {
        static let popoverWidth: CGFloat = 340
        static let maxContentHeight: CGFloat = 360
        static let statusDotSize: CGFloat = 8
        static let headerDotSize: CGFloat = 10
        static let iconButtonSize: CGFloat = 24
        static let hoverCornerRadius: CGFloat = 6
    }

    // MARK: - Colors

    enum Colors {
        static let connected: Color = .green
        static let partial: Color = .orange
        static let disconnected: Color = .secondary
        static let daemonDown: Color = .red
        static let hoverBackground: Color = Color.primary.opacity(0.06)
        static let transportBadge: Color = Color.secondary.opacity(0.12)
    }

    // MARK: - Animation

    enum Anim {
        static let stateChange: Animation = .easeInOut(duration: 0.2)
        static let pulse: Animation = .easeOut(duration: 1.2).repeatForever(autoreverses: false)
    }
}

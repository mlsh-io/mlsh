import SwiftUI

/// ViewModifier that adds a hover highlight to a row, matching native macOS menu behavior.
struct HoverableRow: ViewModifier {
    @State private var isHovered = false

    func body(content: Content) -> some View {
        content
            .background(
                RoundedRectangle(cornerRadius: Theme.Dimensions.hoverCornerRadius)
                    .fill(isHovered ? Theme.Colors.hoverBackground : Color.clear)
            )
            .onHover { hovering in
                isHovered = hovering
            }
    }
}

extension View {
    func hoverableRow() -> some View {
        modifier(HoverableRow())
    }
}

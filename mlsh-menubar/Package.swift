// swift-tools-version: 5.9
// SPDX-License-Identifier: MIT

import PackageDescription

let package = Package(
    name: "MLSHMenuBar",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "MLSHMenuBar",
            path: "Sources/MLSHMenuBar",
            resources: [.copy("Resources")]
        ),
    ]
)

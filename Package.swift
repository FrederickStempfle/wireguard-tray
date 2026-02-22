// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "WireGuardTray",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "WireGuardTray", targets: ["WireGuardTray"])
    ],
    targets: [
        .executableTarget(
            name: "WireGuardTray"
        )
    ]
)

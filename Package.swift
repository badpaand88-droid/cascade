// swift-tools-version: 6.0
import PackageDescription
let package = Package(name: "Cascade", platforms: [.macOS(.v14)], products: [
    .executable(name: "Cascade", targets: ["CascadeMac"]),
    .executable(name: "CascadeTemplateExporter", targets: ["CascadeTemplateExporter"]),
    .library(name: "CascadeCore", targets: ["CascadeCore"])
], targets: [
    .systemLibrary(name: "CZlib"),
    .target(name: "CascadeCore", dependencies: ["CZlib"]),
    .executableTarget(name: "CascadeMac", dependencies: ["CascadeCore"], resources: [.copy("Resources/askpass.sh")]),
    .executableTarget(name: "CascadeTemplateExporter", dependencies: ["CascadeCore"], path: "script/template-export"),
    .testTarget(name: "CascadeCoreTests", dependencies: ["CascadeCore"]),
    .testTarget(name: "CascadeMacTests", dependencies: ["CascadeMac"])
])

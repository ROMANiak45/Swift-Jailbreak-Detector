// swift-tools-version: 6.0
//
//  Package.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

import PackageDescription

let package = Package(
    name: "JailbreakDetector",
    platforms: [.iOS(.v15)],
    products: [
        .library(name: "JailbreakDetector", targets: ["JailbreakDetector"]),
    ],
    targets: [
        .target(
            name: "JailbreakDetector",
            resources: [.process("Resources/PrivacyInfo.xcprivacy")]
        ),
        .testTarget(
            name: "JailbreakDetectorTests",
            dependencies: ["JailbreakDetector"]
        ),
    ],
    swiftLanguageModes: [.v6]
)

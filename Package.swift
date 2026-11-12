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
        .library(name: "JailbreakDetectorHardening", targets: ["JailbreakDetectorHardening"]),
    ],
    targets: [
        .target(
            name: "JailbreakDetector",
            resources: [.process("Resources/PrivacyInfo.xcprivacy")]
        ),
        .target(name: "CJailbreakProbes"),
        .target(
            name: "JailbreakDetectorHardening",
            dependencies: ["JailbreakDetector", "CJailbreakProbes"]
        ),
        .testTarget(
            name: "JailbreakDetectorTests",
            dependencies: ["JailbreakDetector"]
        ),
        .testTarget(
            name: "JailbreakDetectorHardeningTests",
            dependencies: ["JailbreakDetector", "JailbreakDetectorHardening", "CJailbreakProbes"]
        ),
    ],
    swiftLanguageModes: [.v6]
)

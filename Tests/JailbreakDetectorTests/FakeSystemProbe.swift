//
//  FakeSystemProbe.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

import Foundation
@testable import JailbreakDetector

/// A scripted system. The default value describes a stock device running a development-free App Store build.
struct FakeSystemProbe: SystemProbe {
    static let bundlePath =
        "/private/var/containers/Bundle/Application/5B1F0C9E-2A53-4C0B-9E55-3F0B0A6C1D77/Bank.app"

    static let stockImages = [
        "\(bundlePath)/Bank",
        "\(bundlePath)/Frameworks/Analytics.framework/Analytics",
        "/usr/lib/libobjc.A.dylib",
        "/usr/lib/system/libsystem_kernel.dylib",
        "/System/Library/Frameworks/Foundation.framework/Foundation",
        "/System/Library/PrivateFrameworks/UIKitCore.framework/UIKitCore",
    ]

    static let stockOrigins = [
        FunctionOrigin(name: "access", imagePath: "/usr/lib/system/libsystem_kernel.dylib"),
        FunctionOrigin(name: "getenv", imagePath: "/usr/lib/system/libsystem_c.dylib"),
        FunctionOrigin(
            name: "-[NSFileManager fileExistsAtPath:]",
            imagePath: "/System/Library/Frameworks/Foundation.framework/Foundation"
        ),
    ]

    var mainBundlePath = FakeSystemProbe.bundlePath
    var existingPaths: Set<String> = []
    var symbolicLinks: [String: String] = [:]
    var directories: [String: [String]] = [:]
    var writableDirectories: Set<String> = []
    var loadedImages = FakeSystemProbe.stockImages
    var environment: [String: String] = [:]
    var origins = FakeSystemProbe.stockOrigins

    func fileExists(atPath path: String) -> Bool {
        existingPaths.contains(path)
    }

    func symbolicLinkDestination(atPath path: String) -> String? {
        symbolicLinks[path]
    }

    func directoryEntries(atPath path: String) -> [String]? {
        directories[path]
    }

    func canCreateFile(atPath path: String) -> Bool {
        guard let separator = path.lastIndex(of: "/") else { return false }
        return writableDirectories.contains(String(path[...separator]))
    }

    func loadedImagePaths() -> [String] {
        loadedImages
    }

    func environmentValue(named name: String) -> String? {
        environment[name]
    }

    func functionOrigins() -> [FunctionOrigin] {
        origins
    }
}

extension FakeSystemProbe {
    static let clean = FakeSystemProbe()

    /// A classic jailbreak that writes to the root file system and injects Substrate.
    static var rootful: FakeSystemProbe {
        var probe = FakeSystemProbe()
        probe.existingPaths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/private/etc/apt",
            "/usr/sbin/sshd",
            "/bin/bash",
        ]
        probe.writableDirectories = ["/private/"]
        probe.loadedImages += ["/Library/MobileSubstrate/MobileSubstrate.dylib"]
        probe.environment = ["DYLD_INSERT_LIBRARIES": "/Library/MobileSubstrate/MobileSubstrate.dylib"]
        return probe
    }

    /// A rootless jailbreak such as Dopamine, which lives under `/var/jb` and injects ElleKit.
    static var rootless: FakeSystemProbe {
        var probe = FakeSystemProbe()
        probe.existingPaths = [
            "/var/jb",
            "/var/jb/usr/lib/libellekit.dylib",
            "/var/jb/Applications/Sileo.app",
        ]
        probe.symbolicLinks = ["/var/jb": "/private/preboot/3A9F/jb-x1Y2z3/procursus"]
        probe.loadedImages += [
            "/usr/lib/systemhook.dylib",
            "/var/jb/usr/lib/libellekit.dylib",
            "/var/jb/usr/lib/TweakInject/SomeTweak.dylib",
        ]
        probe.environment = [
            "JB_ROOT_PATH": "/var/jb",
            "DYLD_INSERT_LIBRARIES": "/usr/lib/systemhook.dylib",
        ]
        return probe
    }

    /// A roothide jailbreak, which keeps its root in a randomly named directory next to the app containers.
    static var roothide: FakeSystemProbe {
        let root = "/private/var/containers/Bundle/Application/.jbroot-A1B2C3D4E5F60718"
        var probe = FakeSystemProbe()
        probe.directories = [
            "/private/var/containers/Bundle/Application": [
                "5B1F0C9E-2A53-4C0B-9E55-3F0B0A6C1D77",
                ".jbroot-A1B2C3D4E5F60718",
            ],
        ]
        probe.loadedImages += ["\(root)/usr/lib/roothideinit.dylib"]
        probe.environment = ["JBROOT": root, "JBRAND": "A1B2C3D4E5F60718"]
        return probe
    }

    /// A jailbroken device where a bypass tweak hides every file, image and variable by hooking the lookups.
    static var hooked: FakeSystemProbe {
        var probe = FakeSystemProbe()
        probe.origins = [
            FunctionOrigin(name: "access", imagePath: "/var/jb/usr/lib/TweakInject/Shadow.dylib"),
            FunctionOrigin(name: "getenv", imagePath: "/usr/lib/system/libsystem_c.dylib"),
            FunctionOrigin(
                name: "-[NSFileManager fileExistsAtPath:]",
                imagePath: "/var/jb/usr/lib/TweakInject/Shadow.dylib"
            ),
        ]
        return probe
    }
}

/// A scripted set of installed apps and declared query schemes.
struct FakeURLSchemeProbe: URLSchemeProbe {
    var declaredSchemes: [String] = []
    var installedSchemes: Set<String> = []

    func declaredQuerySchemes() -> [String] {
        declaredSchemes
    }

    @MainActor func canOpen(_ url: URL) -> Bool {
        url.scheme.map(installedSchemes.contains) ?? false
    }
}

extension SystemCheck {
    /// Runs the check with the built-in indicators.
    func findings(using probe: any SystemProbe) -> [JailbreakReport.Finding] {
        findings(using: probe, indicators: .builtIn)
    }
}

extension URLSchemeCheck {
    /// Runs the check with the built-in indicators.
    @MainActor func findings(using probe: any URLSchemeProbe) -> [JailbreakReport.Finding] {
        findings(using: probe, indicators: .builtIn)
    }
}

extension [JailbreakReport.Finding] {
    /// The details of the findings with the given confidence.
    func details(_ confidence: JailbreakReport.Confidence) -> [String] {
        filter { $0.confidence == confidence }.map(\.detail)
    }
}

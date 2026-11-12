//
//  ImageTrust.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

/// Decides whether an image path is one a stock device would load into the app.
///
/// Trusted images are the operating system's, Xcode's developer tools, and anything inside the app's own
/// bundle. Everything else was injected from outside.
struct ImageTrust: Sendable {
    private static let systemPrefixes = [
        "/usr/lib/",
        "/System/",
        "/Developer/",
        "/preboot/Cryptexes/",
    ]
    private static let bundleRelativePrefixes = ["@executable_path/", "@loader_path/", "@rpath/"]

    private let applicationRoot: String

    init(mainBundlePath: String) {
        applicationRoot = Self.normalized(Self.applicationRoot(forBundlePath: mainBundlePath))
    }

    func isTrusted(_ imagePath: String) -> Bool {
        if Self.bundleRelativePrefixes.contains(where: { imagePath.hasPrefix($0) }) { return true }
        let path = Self.normalized(imagePath)
        if Self.systemPrefixes.contains(where: { path.hasPrefix($0) }) { return true }
        return path.hasPrefix(applicationRoot + "/")
    }

    /// The enclosing `.app` directory, so that an extension also trusts frameworks embedded in its host app.
    static func applicationRoot(forBundlePath path: String) -> String {
        var components: [Substring] = []
        for component in path.split(separator: "/") {
            components.append(component)
            if component.hasSuffix(".app") { break }
        }
        return "/" + components.joined(separator: "/")
    }

    /// Drops the `/private` prefix, because the same location is reported both with and without it.
    private static func normalized(_ path: String) -> String {
        path.hasPrefix("/private/") ? String(path.dropFirst("/private".count)) : path
    }
}

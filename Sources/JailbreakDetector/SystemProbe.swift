//
//  SystemProbe.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

import Foundation

/// The view of the system that the checks read. Tests substitute a fake.
protocol SystemProbe: Sendable {
    /// The path of the main bundle, used to tell the app's own code from injected code.
    var mainBundlePath: String { get }

    /// Whether anything exists at the path, following symbolic links.
    func fileExists(atPath path: String) -> Bool
    /// The destination of the symbolic link at the path, or `nil` if it is not a readable symbolic link.
    func symbolicLinkDestination(atPath path: String) -> String?
    /// The names of the entries in the directory, or `nil` if it cannot be listed.
    func directoryEntries(atPath path: String) -> [String]?
    /// Whether a file can be created at the path. The file is removed again.
    func canCreateFile(atPath path: String) -> Bool
    /// The paths of every image loaded into the process.
    func loadedImagePaths() -> [String]
    /// The value of an environment variable, or `nil` if it is not set.
    func environmentValue(named name: String) -> String?
    /// The images that implement the system functions the checks rely on.
    func functionOrigins() -> [FunctionOrigin]
}

/// The image that implements a system function, as resolved at run time.
struct FunctionOrigin: Sendable, Hashable {
    /// The function or Objective-C method, such as `access` or `-[NSFileManager fileExistsAtPath:]`.
    let name: String
    /// The path of the image containing the implementation, or `nil` if it is outside every loaded image.
    let imagePath: String?
}

/// The view of installed URL schemes that the URL scheme check reads.
protocol URLSchemeProbe: Sendable {
    /// The schemes the host app declares under `LSApplicationQueriesSchemes`.
    func declaredQuerySchemes() -> [String]
    /// Whether an installed app can open the URL.
    @MainActor func canOpen(_ url: URL) -> Bool
}

/// A built-in check that reads the system through a probe.
protocol SystemCheck: Sendable {
    var id: JailbreakCheckID { get }
    func findings(using probe: any SystemProbe, indicators: IndicatorSet) -> [JailbreakReport.Finding]
}

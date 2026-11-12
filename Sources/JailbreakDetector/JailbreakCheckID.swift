//
//  JailbreakCheckID.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

/// Identifies the check that produced a finding.
public struct JailbreakCheckID: RawRepresentable, Hashable, Sendable, Codable, CustomStringConvertible {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public var description: String { rawValue }
}

extension JailbreakCheckID {
    /// Files and directories installed by jailbreaks and their package managers.
    public static let fileArtifacts = JailbreakCheckID(rawValue: "file-artifacts")
    /// Paths that are symbolic links only on jailbroken systems.
    public static let symbolicLinks = JailbreakCheckID(rawValue: "symbolic-links")
    /// Creating a file outside the app's sandbox.
    public static let sandboxEscape = JailbreakCheckID(rawValue: "sandbox-escape")
    /// Listing directories the sandbox normally denies.
    public static let restrictedDirectories = JailbreakCheckID(rawValue: "restricted-directories")
    /// Hooking frameworks, instrumentation tools and bypass tweaks loaded into the process.
    public static let loadedImages = JailbreakCheckID(rawValue: "loaded-images")
    /// Environment variables set by jailbreaks and library injection.
    public static let environmentVariables = JailbreakCheckID(rawValue: "environment-variables")
    /// System functions the other checks rely on being redirected to foreign code.
    public static let hookIntegrity = JailbreakCheckID(rawValue: "hook-integrity")
    /// URL schemes registered by jailbreak apps. Runs only in the asynchronous evaluation.
    public static let urlSchemes = JailbreakCheckID(rawValue: "url-schemes")
    /// Reported when the configuration asks for the Simulator to be treated as jailbroken.
    public static let simulator = JailbreakCheckID(rawValue: "simulator")

    /// Every check that ships in the core library.
    public static let builtIn: Set<JailbreakCheckID> = [
        .fileArtifacts,
        .symbolicLinks,
        .sandboxEscape,
        .restrictedDirectories,
        .loadedImages,
        .environmentVariables,
        .hookIntegrity,
        .urlSchemes,
    ]
}

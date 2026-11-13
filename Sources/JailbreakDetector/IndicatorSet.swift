//
//  IndicatorSet.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 13.11.2026.
//

/// The paths, names and schemes the checks look for.
///
/// The built-in set is public, so a bypass tweak can be written against it. An app can add indicators of
/// its own with ``merging(_:)``, or replace the set entirely, for example with a list delivered by its
/// server and checked with ``verified(payload:signature:publicKey:minimumVersion:)``.
///
/// When decoded from JSON, missing keys become empty lists and a missing `version` becomes `0`.
public struct IndicatorSet: Sendable, Hashable, Codable {
    /// A path and how strongly its presence indicates a jailbreak.
    public struct PathIndicator: Sendable, Hashable, Codable {
        public var path: String
        public var confidence: JailbreakReport.Confidence

        public init(path: String, confidence: JailbreakReport.Confidence) {
            self.path = path
            self.confidence = confidence
        }
    }

    /// Identifies the list, so that a server can tell which indicators a report was produced with.
    /// The built-in set is version `0`.
    public var version: Int
    /// Files and directories that exist only on jailbroken systems.
    public var files: [PathIndicator]
    /// Paths that are real directories or absent on a stock system and symbolic links on a jailbroken one.
    public var symbolicLinks: [PathIndicator]
    /// Environment variables that only jailbreaks set.
    public var environmentVariables: [String]
    /// Fragments that identify the path of a hooking framework, instrumentation tool or tweak.
    /// Matched case-insensitively anywhere in an image path.
    public var imageFragments: [String]
    /// File names of jailbreak support libraries and detection bypass tweaks. Matched case-insensitively.
    public var imageNames: [String]
    /// URL schemes registered by jailbreak apps.
    public var urlSchemes: [String]
    /// Directories the sandbox normally refuses to list.
    public var restrictedDirectories: [String]

    public init(
        version: Int = 0,
        files: [PathIndicator] = [],
        symbolicLinks: [PathIndicator] = [],
        environmentVariables: [String] = [],
        imageFragments: [String] = [],
        imageNames: [String] = [],
        urlSchemes: [String] = [],
        restrictedDirectories: [String] = []
    ) {
        self.version = version
        self.files = files
        self.symbolicLinks = symbolicLinks
        self.environmentVariables = environmentVariables
        self.imageFragments = imageFragments
        self.imageNames = imageNames
        self.urlSchemes = urlSchemes
        self.restrictedDirectories = restrictedDirectories
    }

    /// Returns a set containing every indicator from both sets.
    ///
    /// Merging only ever adds: a path in both sets keeps the stronger confidence, and the result has the
    /// higher of the two versions. To remove an indicator, assign a complete set instead.
    public func merging(_ other: IndicatorSet) -> IndicatorSet {
        IndicatorSet(
            version: max(version, other.version),
            files: Self.union(files, other.files),
            symbolicLinks: Self.union(symbolicLinks, other.symbolicLinks),
            environmentVariables: Self.union(environmentVariables, other.environmentVariables),
            imageFragments: Self.union(imageFragments, other.imageFragments),
            imageNames: Self.union(imageNames, other.imageNames),
            urlSchemes: Self.union(urlSchemes, other.urlSchemes),
            restrictedDirectories: Self.union(restrictedDirectories, other.restrictedDirectories)
        )
    }

    /// Whether the image path belongs to a known hooking framework, instrumentation tool or bypass tweak.
    public func isInjectedImage(_ path: String) -> Bool {
        ImageMatcher(self).matches(path)
    }

    private static func union(_ first: [String], _ second: [String]) -> [String] {
        var seen = Set(first)
        return first + second.filter { seen.insert($0).inserted }
    }

    private static func union(_ first: [PathIndicator], _ second: [PathIndicator]) -> [PathIndicator] {
        var result = first
        for indicator in second {
            if let index = result.firstIndex(where: { $0.path == indicator.path }) {
                if indicator.confidence == .definitive {
                    result[index].confidence = .definitive
                }
            } else {
                result.append(indicator)
            }
        }
        return result
    }
}

extension IndicatorSet {
    private enum CodingKeys: String, CodingKey {
        case version
        case files
        case symbolicLinks
        case environmentVariables
        case imageFragments
        case imageNames
        case urlSchemes
        case restrictedDirectories
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try container.decodeIfPresent(Int.self, forKey: .version) ?? 0,
            files: try container.decodeIfPresent([PathIndicator].self, forKey: .files) ?? [],
            symbolicLinks: try container.decodeIfPresent([PathIndicator].self, forKey: .symbolicLinks) ?? [],
            environmentVariables: try container.decodeIfPresent([String].self, forKey: .environmentVariables) ?? [],
            imageFragments: try container.decodeIfPresent([String].self, forKey: .imageFragments) ?? [],
            imageNames: try container.decodeIfPresent([String].self, forKey: .imageNames) ?? [],
            urlSchemes: try container.decodeIfPresent([String].self, forKey: .urlSchemes) ?? [],
            restrictedDirectories: try container.decodeIfPresent([String].self, forKey: .restrictedDirectories) ?? []
        )
    }
}

/// Matches image paths against a set's fragments and names, lowercased once up front.
struct ImageMatcher: Sendable {
    private let fragments: [String]
    private let names: Set<String>

    init(_ indicators: IndicatorSet) {
        fragments = indicators.imageFragments.map { $0.lowercased() }.filter { !$0.isEmpty }
        names = Set(indicators.imageNames.map { $0.lowercased() })
    }

    func matches(_ path: String) -> Bool {
        let path = path.lowercased()
        if fragments.contains(where: { path.contains($0) }) { return true }
        guard let name = path.split(separator: "/").last else { return false }
        return names.contains(String(name))
    }
}

extension IndicatorSet {
    /// The indicators that ship with the package.
    public static let builtIn = IndicatorSet(
        version: 0,
        files: definitive([
            // Package managers and jailbreak apps, rootful.
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/Applications/Zebra.app",
            "/Applications/Installer.app",
            "/Applications/Filza.app",
            "/Applications/NewTerm.app",
            // Hooking frameworks, rootful.
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/Library/MobileSubstrate/DynamicLibraries",
            "/Library/Frameworks/CydiaSubstrate.framework",
            "/usr/lib/substrate",
            "/usr/lib/TweakInject",
            "/usr/lib/libsubstrate.dylib",
            "/usr/lib/libsubstitute.dylib",
            "/usr/lib/libhooker.dylib",
            "/usr/lib/libellekit.dylib",
            "/usr/lib/libjailbreak.dylib",
            "/usr/lib/systemhook.dylib",
            "/usr/lib/libcycript.dylib",
            "/usr/bin/cycript",
            "/usr/sbin/frida-server",
            // APT and dpkg.
            "/private/etc/apt",
            "/private/var/lib/apt",
            "/private/var/lib/cydia",
            "/private/var/lib/dpkg",
            "/private/var/cache/apt",
            "/private/var/stash",
            "/usr/bin/apt",
            "/usr/bin/dpkg",
            "/usr/libexec/cydia",
            // Markers left by specific jailbreaks.
            "/.installed_unc0ver",
            "/.installed_odyssey",
            "/.installed_taurine",
            "/.bootstrapped_electra",
            "/.cydia_no_stash",
            "/.procursus_strapped",
            "/.mount_rw",
            "/jb",
            "/binpack",
            "/cores/binpack",
            "/var/binpack",
            "/var/checkra1n.dmg",
            // Rootless jailbreaks.
            "/var/jb",
            "/private/var/jb",
            "/var/jb/.procursus_strapped",
            "/var/jb/.installed_dopamine",
            "/var/jb/.palecursus_strapped",
            "/var/jb/basebin",
            "/var/jb/usr/bin/apt",
            "/var/jb/usr/lib/libellekit.dylib",
            "/var/jb/usr/lib/TweakInject",
            "/var/jb/Library/MobileSubstrate/DynamicLibraries",
            "/var/jb/Applications/Sileo.app",
            "/var/jb/Applications/Zebra.app",
            "/var/Liy",
            "/var/LIB",
            "/var/ulb",
            // Package manager data in the user's library.
            "/private/var/mobile/Library/Cydia",
            "/private/var/mobile/Library/Sileo",
            "/private/var/mobile/Library/Preferences/com.saurik.Cydia.plist",
        ]) + suspicious([
            // Generic Unix tools that stock iOS does not ship.
            "/bin/bash",
            "/bin/zsh",
            "/usr/bin/ssh",
            "/usr/bin/sudo",
            "/usr/sbin/sshd",
            "/usr/libexec/sftp-server",
            "/usr/libexec/ssh-keysign",
            "/private/etc/ssh/sshd_config",
        ]),
        symbolicLinks: definitive([
            "/var/jb",
            "/private/var/jb",
        ]) + suspicious([
            "/Applications",
            "/Library/Ringtones",
            "/Library/Wallpaper",
        ]),
        environmentVariables: [
            "_MSSafeMode",
            "_SafeMode",
            "JB_ROOT_PATH",
            "JB_SANDBOX_EXTENSIONS",
            "JBROOT",
            "JBRAND",
        ],
        imageFragments: [
            "/var/jb/",
            "/.jbroot-",
            "/library/mobilesubstrate/",
            "/tweakinject/",
            "mobilesubstrate",
            "cydiasubstrate",
            "libsubstrate",
            "substrateloader",
            "substrateinserter",
            "substratebootstrap",
            "libsubstitute",
            "substitute-inserter",
            "substitute-loader",
            "libhooker",
            "libblackjack",
            "libellekit",
            "ellekit.framework",
            "pspawn_payload",
            "fridagadget",
            "frida-gadget",
            "frida-agent",
            "libfrida",
            "libcycript",
            "cynject",
            "sslkillswitch",
        ],
        imageNames: [
            "systemhook.dylib",
            "roothideinit.dylib",
            "roothidepatch.dylib",
            "libjailbreak.dylib",
            "shadow.dylib",
            "0shadow.dylib",
            "liberty.dylib",
            "libertylite.dylib",
            "abypass.dylib",
            "abdyld.dylib",
            "absubloader.dylib",
            "flyjb.dylib",
            "flyjbx.dylib",
            "kernbypass.dylib",
            "vnodebypass.dylib",
            "hidejb.dylib",
            "hestia.dylib",
            "choicy.dylib",
            "xcon.dylib",
            "tsprotector.dylib",
        ],
        urlSchemes: ["cydia", "sileo", "zbra", "filza"],
        restrictedDirectories: [
            "/private/var/containers/Bundle/Application",
            "/private/var/mobile/Containers/Data/Application",
            "/private/var/mobile/Library/Preferences",
            "/private/var/root",
            "/private/var/mobile",
            "/private/var/mobile/Library",
            "/private/var/db",
            "/private/var/log",
        ]
    )

    private static func definitive(_ paths: [String]) -> [PathIndicator] {
        paths.map { PathIndicator(path: $0, confidence: .definitive) }
    }

    private static func suspicious(_ paths: [String]) -> [PathIndicator] {
        paths.map { PathIndicator(path: $0, confidence: .suspicious) }
    }
}

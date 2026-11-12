//
//  JailbreakIndicators.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

/// The indicator lists shared by the core checks and the hardening checks.
package enum JailbreakIndicators {
    /// A path and how strongly its presence indicates a jailbreak.
    package struct Path: Sendable, Hashable {
        package let path: String
        package let confidence: JailbreakReport.Confidence
    }

    /// Files and directories that exist only on jailbroken systems.
    package static let files: [Path] = definitive([
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
    ])

    /// Paths that are real directories or absent on a stock system and symbolic links on a jailbroken one.
    package static let symbolicLinks: [Path] = definitive([
        "/var/jb",
        "/private/var/jb",
    ]) + suspicious([
        "/Applications",
        "/Library/Ringtones",
        "/Library/Wallpaper",
    ])

    /// Directories outside the sandbox in which the sandbox escape check tries to create a file.
    package static let sandboxEscapeDirectories = [
        "/",
        "/private/",
        "/private/var/mobile/",
    ]

    /// Directories the sandbox normally refuses to list.
    package static let restrictedDirectories = [
        "/private/var/containers/Bundle/Application",
        "/private/var/mobile/Containers/Data/Application",
        "/private/var/mobile/Library/Preferences",
    ]

    /// The prefix of the directory in which roothide jailbreaks keep their root file system.
    package static let roothideDirectoryPrefix = ".jbroot-"

    /// Environment variables that only jailbreaks set.
    package static let environmentVariables = [
        "_MSSafeMode",
        "_SafeMode",
        "JB_ROOT_PATH",
        "JB_SANDBOX_EXTENSIONS",
        "JBROOT",
        "JBRAND",
    ]

    /// The environment variable through which libraries are injected at launch.
    package static let insertedLibrariesVariable = "DYLD_INSERT_LIBRARIES"

    /// URL schemes registered by jailbreak apps.
    package static let urlSchemes = ["cydia", "sileo", "zbra", "filza"]

    /// Lowercased fragments that identify the path of a hooking framework, instrumentation tool or tweak.
    private static let injectedImageFragments = [
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
    ]

    /// Lowercased file names of jailbreak support libraries and detection bypass tweaks.
    private static let injectedImageNames: Set<String> = [
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
    ]

    /// Whether the image path belongs to a known hooking framework, instrumentation tool or bypass tweak.
    package static func isInjectedImage(_ path: String) -> Bool {
        let path = path.lowercased()
        if injectedImageFragments.contains(where: { path.contains($0) }) { return true }
        guard let name = path.split(separator: "/").last else { return false }
        return injectedImageNames.contains(String(name))
    }

    private static func definitive(_ paths: [String]) -> [Path] {
        paths.map { Path(path: $0, confidence: .definitive) }
    }

    private static func suspicious(_ paths: [String]) -> [Path] {
        paths.map { Path(path: $0, confidence: .suspicious) }
    }
}

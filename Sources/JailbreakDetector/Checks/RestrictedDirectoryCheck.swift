//
//  RestrictedDirectoryCheck.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

/// Tries to list directories the sandbox normally denies, and looks for a roothide jailbreak root in them.
///
/// A successful listing is only suspicious, because which system directories a stock app may read varies
/// between iOS versions.
struct RestrictedDirectoryCheck: SystemCheck {
    /// The prefix of the directory in which roothide jailbreaks keep their root file system.
    static let roothideDirectoryPrefix = ".jbroot-"

    let id = JailbreakCheckID.restrictedDirectories

    func findings(using probe: any SystemProbe, indicators: IndicatorSet) -> [JailbreakReport.Finding] {
        indicators.restrictedDirectories.flatMap { directory -> [JailbreakReport.Finding] in
            guard let entries = probe.directoryEntries(atPath: directory) else { return [] }
            let listed = JailbreakReport.Finding(check: id, confidence: .suspicious, detail: directory)
            let roothideRoots = entries
                .filter { $0.hasPrefix(Self.roothideDirectoryPrefix) }
                .map { JailbreakReport.Finding(check: id, confidence: .definitive, detail: "\(directory)/\($0)") }
            return [listed] + roothideRoots
        }
    }
}

//
//  RestrictedDirectoryCheck.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

/// Tries to list directories the sandbox normally denies, and looks for a roothide jailbreak root in them.
struct RestrictedDirectoryCheck: SystemCheck {
    let id = JailbreakCheckID.restrictedDirectories

    func findings(using probe: any SystemProbe) -> [JailbreakReport.Finding] {
        JailbreakIndicators.restrictedDirectories.flatMap { directory -> [JailbreakReport.Finding] in
            guard let entries = probe.directoryEntries(atPath: directory) else { return [] }
            let listed = JailbreakReport.Finding(check: id, confidence: .suspicious, detail: directory)
            let roothideRoots = entries
                .filter { $0.hasPrefix(JailbreakIndicators.roothideDirectoryPrefix) }
                .map { JailbreakReport.Finding(check: id, confidence: .definitive, detail: "\(directory)/\($0)") }
            return [listed] + roothideRoots
        }
    }
}

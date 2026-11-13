//
//  SandboxEscapeCheck.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

import Foundation

/// Tries to create a file outside the app's container, which the sandbox denies on a stock system.
struct SandboxEscapeCheck: SystemCheck {
    /// Directories outside the sandbox in which the check tries to create a file.
    static let directories = [
        "/",
        "/private/",
        "/private/var/",
        "/private/var/mobile/",
        "/private/var/root/",
        "/Applications/",
        "/Library/",
        "/usr/",
        "/bin/",
    ]

    let id = JailbreakCheckID.sandboxEscape

    func findings(using probe: any SystemProbe, indicators: IndicatorSet) -> [JailbreakReport.Finding] {
        let fileName = ".jailbreak-detector-\(UUID().uuidString)"
        return Self.directories
            .filter { probe.canCreateFile(atPath: $0 + fileName) }
            .map { JailbreakReport.Finding(check: id, confidence: .definitive, detail: $0) }
    }
}

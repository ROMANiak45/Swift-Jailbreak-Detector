//
//  FileArtifactCheck.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

/// Looks for files and directories that jailbreaks and their package managers install.
struct FileArtifactCheck: SystemCheck {
    let id = JailbreakCheckID.fileArtifacts

    func findings(using probe: any SystemProbe) -> [JailbreakReport.Finding] {
        JailbreakIndicators.files
            .filter { probe.fileExists(atPath: $0.path) }
            .map { JailbreakReport.Finding(check: id, confidence: $0.confidence, detail: $0.path) }
    }
}

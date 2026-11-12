//
//  EnvironmentVariableCheck.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

/// Looks for environment variables that jailbreaks set and for libraries injected at launch.
struct EnvironmentVariableCheck: SystemCheck {
    let id = JailbreakCheckID.environmentVariables

    func findings(using probe: any SystemProbe) -> [JailbreakReport.Finding] {
        let jailbreakVariables = JailbreakIndicators.environmentVariables
            .filter { probe.environmentValue(named: $0) != nil }
            .map { JailbreakReport.Finding(check: id, confidence: .definitive, detail: $0) }
        return jailbreakVariables + insertedLibraryFindings(using: probe)
    }

    /// Xcode injects its own debugging libraries on development builds, so only foreign entries are reported.
    private func insertedLibraryFindings(using probe: any SystemProbe) -> [JailbreakReport.Finding] {
        let variable = JailbreakIndicators.insertedLibrariesVariable
        guard let value = probe.environmentValue(named: variable) else { return [] }
        let trust = ImageTrust(mainBundlePath: probe.mainBundlePath)
        return value.split(separator: ":").map(String.init).compactMap { library in
            if JailbreakIndicators.isInjectedImage(library) {
                return JailbreakReport.Finding(check: id, confidence: .definitive, detail: "\(variable)=\(library)")
            }
            if !trust.isTrusted(library) {
                return JailbreakReport.Finding(check: id, confidence: .suspicious, detail: "\(variable)=\(library)")
            }
            return nil
        }
    }
}

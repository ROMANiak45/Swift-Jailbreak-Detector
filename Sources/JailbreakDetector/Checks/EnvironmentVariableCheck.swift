//
//  EnvironmentVariableCheck.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

/// Looks for environment variables that jailbreaks set and for libraries injected at launch.
struct EnvironmentVariableCheck: SystemCheck {
    /// The environment variable through which libraries are injected at launch.
    static let insertedLibrariesVariable = "DYLD_INSERT_LIBRARIES"

    let id = JailbreakCheckID.environmentVariables

    func findings(using probe: any SystemProbe, indicators: IndicatorSet) -> [JailbreakReport.Finding] {
        let jailbreakVariables = indicators.environmentVariables
            .filter { probe.environmentValue(named: $0) != nil }
            .map { JailbreakReport.Finding(check: id, confidence: .definitive, detail: $0) }
        return jailbreakVariables + insertedLibraryFindings(using: probe, indicators: indicators)
    }

    /// Xcode injects its own debugging libraries on development builds, so only foreign entries are reported.
    private func insertedLibraryFindings(
        using probe: any SystemProbe,
        indicators: IndicatorSet
    ) -> [JailbreakReport.Finding] {
        let variable = Self.insertedLibrariesVariable
        guard let value = probe.environmentValue(named: variable) else { return [] }
        let trust = ImageTrust(mainBundlePath: probe.mainBundlePath)
        let matcher = ImageMatcher(indicators)
        return value.split(separator: ":").map(String.init).compactMap { library in
            if matcher.matches(library) {
                return JailbreakReport.Finding(check: id, confidence: .definitive, detail: "\(variable)=\(library)")
            }
            if !trust.isTrusted(library) {
                return JailbreakReport.Finding(check: id, confidence: .suspicious, detail: "\(variable)=\(library)")
            }
            return nil
        }
    }
}

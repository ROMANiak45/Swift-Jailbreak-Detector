//
//  Engine.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

import Foundation

/// Runs the checks that apply to the current environment and assembles the report.
struct Engine: Sendable {
    let probe: any SystemProbe
    let environment: JailbreakReport.Environment

    static let live = Engine(probe: DarwinSystemProbe(), environment: .current)

    private static let systemChecks: [any SystemCheck] = [
        FileArtifactCheck(),
        SymbolicLinkCheck(),
        SandboxEscapeCheck(),
        RestrictedDirectoryCheck(),
        LoadedImageCheck(),
        EnvironmentVariableCheck(),
        HookIntegrityCheck(),
    ]

    func evaluate(_ configuration: JailbreakDetector.Configuration) -> JailbreakReport {
        report(systemFindings(configuration) + additionalFindings(configuration), configuration)
    }

    func evaluate(
        _ configuration: JailbreakDetector.Configuration,
        urlSchemeProbe: any URLSchemeProbe
    ) async -> JailbreakReport {
        var findings = systemFindings(configuration)
        let urlSchemeCheck = URLSchemeCheck()
        if environment == .device, configuration.checks.contains(urlSchemeCheck.id) {
            findings += await urlSchemeCheck.findings(using: urlSchemeProbe)
        }
        return report(findings + additionalFindings(configuration), configuration)
    }

    private func systemFindings(_ configuration: JailbreakDetector.Configuration) -> [JailbreakReport.Finding] {
        guard environment == .device else { return [] }
        return Self.systemChecks
            .filter { configuration.checks.contains($0.id) }
            .flatMap { $0.findings(using: probe) }
    }

    private func additionalFindings(_ configuration: JailbreakDetector.Configuration) -> [JailbreakReport.Finding] {
        guard environment == .device else { return [] }
        return configuration.additionalChecks.flatMap { $0.run() }
    }

    private func report(
        _ findings: [JailbreakReport.Finding],
        _ configuration: JailbreakDetector.Configuration
    ) -> JailbreakReport {
        var findings = findings
        if environment == .simulator, configuration.simulatorPolicy == .reportJailbroken {
            findings.append(JailbreakReport.Finding(
                check: .simulator,
                confidence: .definitive,
                detail: "Simulator reported as jailbroken by configuration"
            ))
        }
        return JailbreakReport(environment: environment, findings: findings)
    }
}

extension JailbreakReport.Environment {
    /// The environment this process is running in.
    static var current: JailbreakReport.Environment {
        #if targetEnvironment(simulator)
        return .simulator
        #else
        let process = ProcessInfo.processInfo
        return process.isMacCatalystApp || process.isiOSAppOnMac ? .mac : .device
        #endif
    }
}

//
//  EngineTests.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

import Foundation
import Testing
@testable import JailbreakDetector

@Suite struct JailbreakReportTests {
    private let suspicious = JailbreakReport.Finding(check: .fileArtifacts, confidence: .suspicious, detail: "/bin/bash")
    private let definitive = JailbreakReport.Finding(check: .fileArtifacts, confidence: .definitive, detail: "/var/jb")

    @Test func noFindingsIsClean() {
        #expect(JailbreakReport(environment: .device, findings: []).verdict == .clean)
    }

    @Test func onlySuspiciousFindingsIsSuspicious() {
        #expect(JailbreakReport(environment: .device, findings: [suspicious, suspicious]).verdict == .suspicious)
    }

    @Test func anyDefinitiveFindingIsJailbroken() {
        #expect(JailbreakReport(environment: .device, findings: [suspicious, definitive]).verdict == .jailbroken)
    }

    @Test func survivesAnEncodingRoundTrip() throws {
        let report = JailbreakReport(environment: .device, findings: [suspicious, definitive])
        let decoded = try JSONDecoder().decode(JailbreakReport.self, from: JSONEncoder().encode(report))
        #expect(decoded == report)
    }
}

@Suite struct EngineTests {
    private struct StubCheck: JailbreakCheck {
        let id = JailbreakCheckID(rawValue: "stub")

        func run() -> [JailbreakReport.Finding] {
            [JailbreakReport.Finding(check: id, confidence: .definitive, detail: "stub")]
        }
    }

    private func device(_ probe: FakeSystemProbe) -> Engine {
        Engine(probe: probe, environment: .device)
    }

    @Test func stockDeviceIsClean() {
        let report = device(.clean).evaluate(.default)
        #expect(report.verdict == .clean)
        #expect(report.environment == .device)
        #expect(report.findings.isEmpty)
    }

    @Test(arguments: [FakeSystemProbe.rootful, .rootless, .roothide, .hooked])
    func jailbrokenDeviceIsJailbroken(probe: FakeSystemProbe) {
        #expect(device(probe).evaluate(.default).verdict == .jailbroken)
    }

    @Test func bypassTweakThatHidesEverythingElseIsCaughtByHookIntegrity() {
        let report = device(.hooked).evaluate(.default)
        #expect(Set(report.findings.map(\.check)) == [.hookIntegrity])
    }

    @Test func onlySuspiciousFindingsGiveASuspiciousVerdict() {
        var probe = FakeSystemProbe()
        probe.existingPaths = ["/bin/bash"]
        #expect(device(probe).evaluate(.default).verdict == .suspicious)
    }

    @Test func findingsFollowTheOrderOfTheChecks() {
        let checks = device(.rootful).evaluate(.default).findings.map(\.check)
        #expect(checks.uniqued() == [.fileArtifacts, .sandboxEscape, .loadedImages, .environmentVariables])
    }

    @Test(arguments: [JailbreakReport.Environment.simulator, .mac])
    func checksDoNotRunOffDevice(environment: JailbreakReport.Environment) {
        let configuration = JailbreakDetector.Configuration(additionalChecks: [StubCheck()])
        let report = Engine(probe: FakeSystemProbe.rootful, environment: environment).evaluate(configuration)
        #expect(report.verdict == .clean)
        #expect(report.environment == environment)
        #expect(report.findings.isEmpty)
    }

    @Test func simulatorCanBeReportedAsJailbroken() {
        let configuration = JailbreakDetector.Configuration(simulatorPolicy: .reportJailbroken)
        let report = Engine(probe: FakeSystemProbe.clean, environment: .simulator).evaluate(configuration)
        #expect(report.verdict == .jailbroken)
        #expect(report.findings.map(\.check) == [.simulator])
    }

    @Test func simulatorPolicyDoesNotAffectADevice() {
        let configuration = JailbreakDetector.Configuration(simulatorPolicy: .reportJailbroken)
        #expect(device(.clean).evaluate(configuration).verdict == .clean)
    }

    @Test func onlySelectedChecksRun() {
        let configuration = JailbreakDetector.Configuration(checks: [.sandboxEscape])
        let report = device(.rootful).evaluate(configuration)
        #expect(Set(report.findings.map(\.check)) == [.sandboxEscape])
    }

    @Test func additionalChecksRunAfterTheBuiltInOnes() {
        let configuration = JailbreakDetector.Configuration(additionalChecks: [StubCheck()])
        let clean = device(.clean).evaluate(configuration)
        #expect(clean.verdict == .jailbroken)
        #expect(clean.findings.map(\.detail) == ["stub"])
        #expect(device(.rootful).evaluate(configuration).findings.last?.detail == "stub")
    }

    @Test func asynchronousEvaluationAddsURLSchemeFindings() async {
        let urlSchemes = FakeURLSchemeProbe(declaredSchemes: ["sileo"], installedSchemes: ["sileo"])
        let report = await device(.clean).evaluate(.default, urlSchemeProbe: urlSchemes)
        #expect(report.verdict == .suspicious)
        #expect(report.findings == [
            JailbreakReport.Finding(check: .urlSchemes, confidence: .suspicious, detail: "sileo://"),
        ])
    }

    @Test func asynchronousEvaluationKeepsTheSynchronousFindings() async {
        let urlSchemes = FakeURLSchemeProbe(declaredSchemes: ["sileo"], installedSchemes: ["sileo"])
        let report = await device(.rootless).evaluate(.default, urlSchemeProbe: urlSchemes)
        let synchronous = device(.rootless).evaluate(.default)
        #expect(report.verdict == .jailbroken)
        #expect(report.findings.filter { $0.check != .urlSchemes } == synchronous.findings)
    }

    @Test func urlSchemeCheckCanBeDisabled() async {
        let urlSchemes = FakeURLSchemeProbe(declaredSchemes: ["sileo"], installedSchemes: ["sileo"])
        let configuration = JailbreakDetector.Configuration(checks: JailbreakCheckID.builtIn.subtracting([.urlSchemes]))
        let report = await device(.clean).evaluate(configuration, urlSchemeProbe: urlSchemes)
        #expect(report.findings.isEmpty)
    }

    @Test func urlSchemeCheckDoesNotRunOffDevice() async {
        let urlSchemes = FakeURLSchemeProbe(declaredSchemes: ["sileo"], installedSchemes: ["sileo"])
        let engine = Engine(probe: FakeSystemProbe.clean, environment: .simulator)
        let report = await engine.evaluate(.default, urlSchemeProbe: urlSchemes)
        #expect(report.findings.isEmpty)
    }
}

extension Array where Element: Hashable {
    /// The elements in their original order with repeats removed.
    fileprivate func uniqued() -> [Element] {
        var seen: Set<Element> = []
        return filter { seen.insert($0).inserted }
    }
}

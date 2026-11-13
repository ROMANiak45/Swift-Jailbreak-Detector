//
//  HardeningCheckTests.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

import JailbreakDetector
import Testing
@testable import JailbreakDetectorHardening

/// A scripted low-level view of the system. The default value describes a stock device.
struct FakeLowLevelProbe: LowLevelProbe {
    var supportsDirectSyscalls = true
    var kernelPaths: Set<String> = []
    var libcPaths: Set<String> = []
    var kernelLinks: [String: String] = [:]
    var libcLinks: [String: String] = [:]
    var trampolines: Set<String> = []
    var canFork = false
    var openPorts: Set<UInt16> = []

    func directFileExists(atPath path: String) -> Bool { kernelPaths.contains(path) }
    func libcFileExists(atPath path: String) -> Bool { libcPaths.contains(path) }
    func directSymbolicLinkDestination(atPath path: String) -> String? { kernelLinks[path] }
    func libcSymbolicLinkDestination(atPath path: String) -> String? { libcLinks[path] }
    func functionStartsWithTrampoline(_ symbol: String) -> Bool { trampolines.contains(symbol) }
    func forkSucceeds() -> Bool { canFork }
    func isLoopbackPortOpen(_ port: UInt16) -> Bool { openPorts.contains(port) }
}

extension JailbreakCheck {
    /// Runs the check with the built-in indicators.
    func run() -> [JailbreakReport.Finding] {
        run(JailbreakCheckContext(indicators: .builtIn))
    }
}

@Suite struct DirectSyscallCheckTests {
    private func findings(_ probe: FakeLowLevelProbe) -> [JailbreakReport.Finding] {
        DirectSyscallCheck(probe: probe).run()
    }

    @Test func stockDeviceHasNoFindings() {
        #expect(findings(FakeLowLevelProbe()).isEmpty)
    }

    @Test func fileVisibleToLibcKeepsItsIndicatorConfidence() {
        let paths: Set = ["/var/jb", "/bin/bash"]
        let result = findings(FakeLowLevelProbe(kernelPaths: paths, libcPaths: paths))
        #expect(Set(result) == [
            JailbreakReport.Finding(check: .directSyscalls, confidence: .definitive, detail: "/var/jb"),
            JailbreakReport.Finding(check: .directSyscalls, confidence: .suspicious, detail: "/bin/bash"),
        ])
    }

    @Test func fileHiddenFromLibcIsDefinitive() {
        let result = findings(FakeLowLevelProbe(kernelPaths: ["/bin/bash"]))
        #expect(result == [
            JailbreakReport.Finding(
                check: .directSyscalls,
                confidence: .definitive,
                detail: "/bin/bash (hidden from libc)"
            ),
        ])
    }

    @Test func symbolicLinkVisibleToLibcKeepsItsIndicatorConfidence() {
        let links = ["/Applications": "/var/stash/Applications.x1Y2z3"]
        let result = findings(FakeLowLevelProbe(kernelLinks: links, libcLinks: links))
        #expect(result == [
            JailbreakReport.Finding(
                check: .directSyscalls,
                confidence: .suspicious,
                detail: "/Applications -> /var/stash/Applications.x1Y2z3"
            ),
        ])
    }

    @Test func symbolicLinkHiddenFromLibcIsDefinitive() {
        let result = findings(FakeLowLevelProbe(kernelLinks: ["/var/jb": "/private/preboot/3A9F/jb-x1Y2z3/procursus"]))
        #expect(result == [
            JailbreakReport.Finding(
                check: .directSyscalls,
                confidence: .definitive,
                detail: "/var/jb -> /private/preboot/3A9F/jb-x1Y2z3/procursus (hidden from libc)"
            ),
        ])
    }

    @Test func nothingIsReportedWhenDirectSyscallsAreUnsupported() {
        var probe = FakeLowLevelProbe(kernelPaths: ["/var/jb"], kernelLinks: ["/var/jb": "/elsewhere"])
        probe.supportsDirectSyscalls = false
        #expect(findings(probe).isEmpty)
    }
}

@Suite struct FunctionPrologueCheckTests {
    @Test func intactFunctionsHaveNoFindings() {
        #expect(FunctionPrologueCheck(probe: FakeLowLevelProbe()).run().isEmpty)
    }

    @Test func functionStartingWithATrampolineIsSuspicious() {
        let probe = FakeLowLevelProbe(trampolines: ["access", "getenv"])
        #expect(FunctionPrologueCheck(probe: probe).run() == [
            JailbreakReport.Finding(check: .functionPrologues, confidence: .suspicious, detail: "access"),
            JailbreakReport.Finding(check: .functionPrologues, confidence: .suspicious, detail: "getenv"),
        ])
    }

    @Test func functionsOutsideTheWatchListAreIgnored() {
        let probe = FakeLowLevelProbe(trampolines: ["printf"])
        #expect(FunctionPrologueCheck(probe: probe).run().isEmpty)
    }
}

@Suite struct ForkCheckTests {
    @Test func deniedForkHasNoFindings() {
        #expect(ForkCheck(probe: FakeLowLevelProbe()).run().isEmpty)
    }

    @Test func successfulForkIsDefinitive() {
        let probe = FakeLowLevelProbe(canFork: true)
        #expect(ForkCheck(probe: probe).run() == [
            JailbreakReport.Finding(check: .fork, confidence: .definitive, detail: "fork() succeeded"),
        ])
    }
}

@Suite struct LoopbackPortCheckTests {
    @Test func closedPortsHaveNoFindings() {
        #expect(LoopbackPortCheck(probe: FakeLowLevelProbe()).run().isEmpty)
    }

    @Test func openJailbreakPortsAreSuspicious() {
        let probe = FakeLowLevelProbe(openPorts: [22, 27042, 8080])
        #expect(LoopbackPortCheck(probe: probe).run() == [
            JailbreakReport.Finding(check: .loopbackPorts, confidence: .suspicious, detail: "127.0.0.1:22"),
            JailbreakReport.Finding(check: .loopbackPorts, confidence: .suspicious, detail: "127.0.0.1:27042"),
        ])
    }
}

@Suite struct HardenedConfigurationTests {
    @Test func addsEveryHardeningCheckToTheBuiltInOnes() {
        let configuration = JailbreakDetector.Configuration.hardened
        #expect(configuration.checks == JailbreakCheckID.builtIn)
        #expect(configuration.additionalChecks.map(\.id) == [
            .directSyscalls,
            .functionPrologues,
            .fork,
            .loopbackPorts,
        ])
    }

    @Test func hardeningChecksDoNotRunInTheSimulator() {
        let report = JailbreakDetector.evaluate(.hardened)
        #expect(report.environment == .simulator)
        #expect(report.verdict == .clean)
        #expect(report.findings.isEmpty)
    }
}

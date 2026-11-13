//
//  FileSystemCheckTests.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

import Testing
@testable import JailbreakDetector

@Suite struct FileArtifactCheckTests {
    let check = FileArtifactCheck()

    @Test func stockDeviceHasNoFindings() {
        #expect(check.findings(using: FakeSystemProbe.clean).isEmpty)
    }

    @Test func rootfulArtifactsAreDefinitive() {
        let findings = check.findings(using: FakeSystemProbe.rootful)
        #expect(findings.details(.definitive) == [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/private/etc/apt",
        ])
        #expect(findings.allSatisfy { $0.check == .fileArtifacts })
    }

    @Test func rootlessArtifactsAreDefinitive() {
        let findings = check.findings(using: FakeSystemProbe.rootless)
        #expect(Set(findings.details(.definitive)) == [
            "/var/jb",
            "/var/jb/usr/lib/libellekit.dylib",
            "/var/jb/Applications/Sileo.app",
        ])
    }

    @Test func genericUnixToolsAreOnlySuspicious() {
        let findings = check.findings(using: FakeSystemProbe.rootful)
        #expect(Set(findings.details(.suspicious)) == ["/bin/bash", "/usr/sbin/sshd"])
    }
}

@Suite struct SymbolicLinkCheckTests {
    let check = SymbolicLinkCheck()

    @Test func stockDeviceHasNoFindings() {
        #expect(check.findings(using: FakeSystemProbe.clean).isEmpty)
    }

    @Test func rootlessLinkIsDefinitiveAndReportsItsDestination() {
        let findings = check.findings(using: FakeSystemProbe.rootless)
        #expect(findings == [
            JailbreakReport.Finding(
                check: .symbolicLinks,
                confidence: .definitive,
                detail: "/var/jb -> /private/preboot/3A9F/jb-x1Y2z3/procursus"
            ),
        ])
    }

    @Test func stashedSystemDirectoryIsSuspicious() {
        var probe = FakeSystemProbe()
        probe.symbolicLinks = ["/Applications": "/var/stash/Applications.x1Y2z3"]
        let findings = check.findings(using: probe)
        #expect(findings.details(.suspicious) == ["/Applications -> /var/stash/Applications.x1Y2z3"])
        #expect(findings.details(.definitive).isEmpty)
    }
}

@Suite struct SandboxEscapeCheckTests {
    let check = SandboxEscapeCheck()

    @Test func stockDeviceHasNoFindings() {
        #expect(check.findings(using: FakeSystemProbe.clean).isEmpty)
    }

    @Test(arguments: [
        "/", "/private/", "/private/var/", "/private/var/mobile/", "/private/var/root/",
        "/Applications/", "/Library/", "/usr/", "/bin/",
    ])
    func everyWriteTargetIsProbedAndDefinitive(directory: String) {
        var probe = FakeSystemProbe()
        probe.writableDirectories = [directory]
        #expect(check.findings(using: probe) == [
            JailbreakReport.Finding(check: .sandboxEscape, confidence: .definitive, detail: directory),
        ])
    }

    @Test func probeFileNamesAreUniqueAndHidden() {
        final class Recorder: @unchecked Sendable {
            var paths: [String] = []
        }
        struct RecordingProbe: SystemProbe {
            let recorder: Recorder
            var mainBundlePath: String { FakeSystemProbe.bundlePath }
            func fileExists(atPath path: String) -> Bool { false }
            func symbolicLinkDestination(atPath path: String) -> String? { nil }
            func directoryEntries(atPath path: String) -> [String]? { nil }
            func canCreateFile(atPath path: String) -> Bool {
                recorder.paths.append(path)
                return false
            }
            func loadedImagePaths() -> [String] { [] }
            func environmentValue(named name: String) -> String? { nil }
            func functionOrigins() -> [FunctionOrigin] { [] }
        }

        let recorder = Recorder()
        _ = check.findings(using: RecordingProbe(recorder: recorder))
        _ = check.findings(using: RecordingProbe(recorder: recorder))
        let names = recorder.paths.compactMap { $0.split(separator: "/").last.map(String.init) }
        #expect(names.allSatisfy { $0.hasPrefix(".jailbreak-detector-") })
        #expect(Set(names).count == 2)
    }

    @Test func writableDirectoryOutsideTheContainerIsDefinitive() {
        let findings = check.findings(using: FakeSystemProbe.rootful)
        #expect(findings == [
            JailbreakReport.Finding(check: .sandboxEscape, confidence: .definitive, detail: "/private/"),
        ])
    }
}

@Suite struct RestrictedDirectoryCheckTests {
    let check = RestrictedDirectoryCheck()

    @Test func stockDeviceHasNoFindings() {
        #expect(check.findings(using: FakeSystemProbe.clean).isEmpty)
    }

    @Test func listingARestrictedDirectoryIsSuspicious() {
        var probe = FakeSystemProbe()
        probe.directories = ["/private/var/mobile/Library/Preferences": []]
        #expect(check.findings(using: probe) == [
            JailbreakReport.Finding(
                check: .restrictedDirectories,
                confidence: .suspicious,
                detail: "/private/var/mobile/Library/Preferences"
            ),
        ])
    }

    @Test(arguments: IndicatorSet.builtIn.restrictedDirectories)
    func everyBuiltInRestrictedDirectoryIsOnlySuspicious(directory: String) {
        var probe = FakeSystemProbe()
        probe.directories = [directory: ["entry"]]
        #expect(check.findings(using: probe) == [
            JailbreakReport.Finding(check: .restrictedDirectories, confidence: .suspicious, detail: directory),
        ])
    }

    @Test func builtInRestrictedDirectoriesIncludeTheSystemFolders() {
        #expect(Set(IndicatorSet.builtIn.restrictedDirectories).isSuperset(of: [
            "/private/var/root",
            "/private/var/mobile",
            "/private/var/mobile/Library",
            "/private/var/db",
            "/private/var/log",
        ]))
        #expect(!IndicatorSet.builtIn.restrictedDirectories.contains("/"))
    }

    @Test func customRestrictedDirectoriesReplaceTheBuiltInOnes() {
        var probe = FakeSystemProbe()
        probe.directories = ["/private/var/root": [], "/private/var/custom": []]
        let findings = check.findings(using: probe, indicators: IndicatorSet(restrictedDirectories: ["/private/var/custom"]))
        #expect(findings.map(\.detail) == ["/private/var/custom"])
    }

    @Test func roothideRootIsDefinitive() {
        let findings = check.findings(using: FakeSystemProbe.roothide)
        #expect(findings.details(.definitive) == [
            "/private/var/containers/Bundle/Application/.jbroot-A1B2C3D4E5F60718",
        ])
        #expect(findings.details(.suspicious) == ["/private/var/containers/Bundle/Application"])
    }
}

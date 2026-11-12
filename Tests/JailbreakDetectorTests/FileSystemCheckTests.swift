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

    @Test func roothideRootIsDefinitive() {
        let findings = check.findings(using: FakeSystemProbe.roothide)
        #expect(findings.details(.definitive) == [
            "/private/var/containers/Bundle/Application/.jbroot-A1B2C3D4E5F60718",
        ])
        #expect(findings.details(.suspicious) == ["/private/var/containers/Bundle/Application"])
    }
}

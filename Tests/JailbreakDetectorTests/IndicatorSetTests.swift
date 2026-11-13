//
//  IndicatorSetTests.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 13.11.2026.
//

import Foundation
import Testing
@testable import JailbreakDetector

@Suite struct IndicatorSetTests {
    private typealias PathIndicator = IndicatorSet.PathIndicator

    @Test func builtInSetIsVersionZeroAndCoversEveryCategory() {
        let builtIn = IndicatorSet.builtIn
        #expect(builtIn.version == 0)
        #expect(!builtIn.files.isEmpty)
        #expect(!builtIn.symbolicLinks.isEmpty)
        #expect(!builtIn.environmentVariables.isEmpty)
        #expect(!builtIn.imageFragments.isEmpty)
        #expect(!builtIn.imageNames.isEmpty)
        #expect(builtIn.urlSchemes == ["cydia", "sileo", "zbra", "filza"])
        #expect(builtIn.restrictedDirectories.count == 8)
        #expect(Set(builtIn.files.map(\.path)).count == builtIn.files.count)
    }

    @Test func mergingAddsNewIndicatorsAfterExistingOnes() {
        let first = IndicatorSet(
            version: 1,
            files: [PathIndicator(path: "/a", confidence: .definitive)],
            urlSchemes: ["one"]
        )
        let second = IndicatorSet(
            version: 4,
            files: [PathIndicator(path: "/b", confidence: .suspicious)],
            urlSchemes: ["one", "two"]
        )
        let merged = first.merging(second)
        #expect(merged.version == 4)
        #expect(merged.files.map(\.path) == ["/a", "/b"])
        #expect(merged.urlSchemes == ["one", "two"])
    }

    @Test func mergingNeverWeakensAPath() {
        let definitive = IndicatorSet(files: [PathIndicator(path: "/a", confidence: .definitive)])
        let suspicious = IndicatorSet(files: [PathIndicator(path: "/a", confidence: .suspicious)])
        #expect(definitive.merging(suspicious).files == definitive.files)
        #expect(suspicious.merging(definitive).files == definitive.files)
    }

    @Test func mergingKeepsTheHigherVersion() {
        #expect(IndicatorSet(version: 9).merging(IndicatorSet(version: 2)).version == 9)
    }

    @Test func survivesAnEncodingRoundTrip() throws {
        let decoded = try JSONDecoder().decode(IndicatorSet.self, from: JSONEncoder().encode(IndicatorSet.builtIn))
        #expect(decoded == .builtIn)
    }

    @Test func decodingTreatsMissingKeysAsEmpty() throws {
        let decoded = try JSONDecoder().decode(IndicatorSet.self, from: Data(#"{"urlSchemes":["x"]}"#.utf8))
        #expect(decoded == IndicatorSet(urlSchemes: ["x"]))
    }

    @Test func decodingRejectsAnUnknownConfidence() {
        let json = Data(#"{"files":[{"path":"/a","confidence":"maybe"}]}"#.utf8)
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(IndicatorSet.self, from: json)
        }
    }

    @Test func injectedImageMatchingIgnoresCase() {
        let indicators = IndicatorSet(imageFragments: ["MyHook"], imageNames: ["Bypass.dylib"])
        #expect(indicators.isInjectedImage("/usr/lib/libmyhook.dylib"))
        #expect(indicators.isInjectedImage("/var/tmp/BYPASS.DYLIB"))
        #expect(!indicators.isInjectedImage("/var/tmp/NotBypass.dylib"))
        #expect(!IndicatorSet(imageFragments: [""]).isInjectedImage("/usr/lib/libobjc.A.dylib"))
    }
}

@Suite struct CustomIndicatorTests {
    private let privateSet = IndicatorSet(
        version: 2,
        files: [IndicatorSet.PathIndicator(path: "/var/private-marker", confidence: .definitive)],
        symbolicLinks: [IndicatorSet.PathIndicator(path: "/private/var/private-link", confidence: .suspicious)],
        environmentVariables: ["PRIVATE_JB"],
        imageFragments: ["privatehook"],
        imageNames: ["privatebypass.dylib"],
        urlSchemes: ["privatejb"],
        restrictedDirectories: ["/private/var/private-directory"]
    )

    private var probe: FakeSystemProbe {
        var probe = FakeSystemProbe()
        probe.existingPaths = ["/var/private-marker", "/Applications/Cydia.app"]
        probe.symbolicLinks = ["/private/var/private-link": "/elsewhere"]
        probe.environment = ["PRIVATE_JB": "1"]
        probe.loadedImages += ["/usr/lib/libPrivateHook.dylib", "/usr/lib/PrivateBypass.dylib"]
        probe.directories = ["/private/var/private-directory": []]
        return probe
    }

    @Test func eachCheckReadsTheConfiguredIndicators() {
        let findings = Engine(probe: probe, environment: .device)
            .evaluate(JailbreakDetector.Configuration(indicators: privateSet))
            .findings
        #expect(findings.map(\.detail) == [
            "/var/private-marker",
            "/private/var/private-link -> /elsewhere",
            "/private/var/private-directory",
            "/usr/lib/libPrivateHook.dylib",
            "/usr/lib/PrivateBypass.dylib",
            "PRIVATE_JB",
        ])
    }

    @Test func replacingTheSetDropsTheBuiltInIndicators() {
        let report = Engine(probe: probe, environment: .device)
            .evaluate(JailbreakDetector.Configuration(indicators: privateSet))
        #expect(!report.findings.contains { $0.detail == "/Applications/Cydia.app" })
    }

    @Test func mergingWithTheBuiltInSetFindsBoth() {
        let configuration = JailbreakDetector.Configuration(indicators: IndicatorSet.builtIn.merging(privateSet))
        let details = Engine(probe: probe, environment: .device).evaluate(configuration).findings.map(\.detail)
        #expect(details.contains("/Applications/Cydia.app"))
        #expect(details.contains("/var/private-marker"))
    }

    @Test @MainActor func urlSchemeCheckReadsTheConfiguredSchemes() {
        let urlSchemes = FakeURLSchemeProbe(declaredSchemes: ["privatejb", "cydia"], installedSchemes: ["privatejb", "cydia"])
        let findings = URLSchemeCheck().findings(using: urlSchemes, indicators: privateSet)
        #expect(findings.map(\.detail) == ["privatejb://"])
    }

    @Test func additionalChecksReceiveTheConfiguredIndicators() {
        struct RecordingCheck: JailbreakCheck {
            let id = JailbreakCheckID(rawValue: "recording")

            func run(_ context: JailbreakCheckContext) -> [JailbreakReport.Finding] {
                context.indicators.urlSchemes.map {
                    JailbreakReport.Finding(check: id, confidence: .suspicious, detail: $0)
                }
            }
        }

        let configuration = JailbreakDetector.Configuration(
            checks: [],
            additionalChecks: [RecordingCheck()],
            indicators: privateSet
        )
        let report = Engine(probe: FakeSystemProbe.clean, environment: .device).evaluate(configuration)
        #expect(report.findings.map(\.detail) == ["privatejb"])
    }
}

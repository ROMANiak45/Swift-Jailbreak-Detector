//
//  LiveSystemTests.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

import Foundation
import Testing
@testable import JailbreakDetector

/// Exercises the real probe against the Simulator's file system and process.
@Suite struct DarwinSystemProbeTests {
    let probe = DarwinSystemProbe()

    private func temporaryPath() -> String {
        NSTemporaryDirectory() + "jailbreak-detector-tests-\(UUID().uuidString)"
    }

    @Test func findsExistingFilesAndDirectories() throws {
        let path = temporaryPath()
        try Data().write(to: URL(fileURLWithPath: path))
        defer { try? FileManager.default.removeItem(atPath: path) }

        #expect(probe.fileExists(atPath: path))
        #expect(probe.fileExists(atPath: NSTemporaryDirectory()))
    }

    @Test func doesNotFindMissingFiles() {
        #expect(!probe.fileExists(atPath: temporaryPath()))
    }

    @Test func readsSymbolicLinkDestinations() throws {
        let path = temporaryPath()
        try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: "/destination/that/is/missing")
        defer { try? FileManager.default.removeItem(atPath: path) }

        #expect(probe.symbolicLinkDestination(atPath: path) == "/destination/that/is/missing")
    }

    @Test func reportsNoDestinationForPathsThatAreNotSymbolicLinks() {
        #expect(probe.symbolicLinkDestination(atPath: NSTemporaryDirectory()) == nil)
        #expect(probe.symbolicLinkDestination(atPath: temporaryPath()) == nil)
    }

    @Test func listsDirectories() throws {
        let directory = temporaryPath()
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(atPath: directory) }
        try Data().write(to: URL(fileURLWithPath: directory + "/entry"))

        #expect(probe.directoryEntries(atPath: directory) == ["entry"])
        #expect(probe.directoryEntries(atPath: temporaryPath()) == nil)
    }

    @Test func createsAndRemovesTheProbeFile() {
        let path = temporaryPath()
        #expect(probe.canCreateFile(atPath: path))
        #expect(!FileManager.default.fileExists(atPath: path))
    }

    @Test func cannotCreateAFileInAMissingDirectory() {
        #expect(!probe.canCreateFile(atPath: temporaryPath() + "/file"))
    }

    @Test func listsTheImagesLoadedIntoTheProcess() {
        let images = probe.loadedImagePaths()
        #expect(images.contains { $0.hasSuffix("/libobjc.A.dylib") })
        #expect(images.contains { $0.hasSuffix("/Foundation.framework/Foundation") })
    }

    @Test func readsEnvironmentVariables() {
        let name = "JAILBREAK_DETECTOR_TESTS_\(UUID().uuidString.prefix(8))"
        #expect(probe.environmentValue(named: name) == nil)
        setenv(name, "value", 1)
        defer { unsetenv(name) }
        #expect(probe.environmentValue(named: name) == "value")
    }

    @Test func resolvesEveryWatchedFunctionToALoadedImage() {
        let origins = probe.functionOrigins()
        #expect(origins.map(\.name) == [
            "access",
            "fopen",
            "creat",
            "readlink",
            "getenv",
            "dladdr",
            "_dyld_image_count",
            "_dyld_get_image_name",
            "-[NSFileManager fileExistsAtPath:]",
            "-[NSFileManager contentsOfDirectoryAtPath:error:]",
            "-[UIApplication canOpenURL:]",
        ])
        #expect(origins.allSatisfy { $0.imagePath != nil })

        let loaded = Set(probe.loadedImagePaths())
        #expect(origins.allSatisfy { origin in origin.imagePath.map(loaded.contains) ?? false })
    }
}

/// Runs the public API end to end in the Simulator.
@Suite struct PublicAPITests {
    @Test func simulatorIsReportedAsCleanWithoutRunningChecks() {
        let report = JailbreakDetector.evaluate()
        #expect(report.environment == .simulator)
        #expect(report.verdict == .clean)
        #expect(report.findings.isEmpty)
        #expect(!JailbreakDetector.isJailbroken())
    }

    @Test func asynchronousEvaluationMatchesInTheSimulator() async {
        let report = await JailbreakDetector.evaluate()
        #expect(report.environment == .simulator)
        #expect(report.verdict == .clean)
    }

    @Test func simulatorPolicyIsHonoured() {
        let report = JailbreakDetector.evaluate(.init(simulatorPolicy: .reportJailbroken))
        #expect(report.verdict == .jailbroken)
    }
}

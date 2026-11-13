//
//  LiveProbeTests.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

import CJailbreakProbes
import Foundation
import Testing
@testable import JailbreakDetectorHardening

/// Encodings of the arm64 instructions used below.
private enum Instruction {
    static let movX16Access: UInt32 = 0xD280_0430 // mov x16, #33
    static let svc: UInt32 = 0xD400_1001 // svc #0x80
    static let branchIfCarryClear: UInt32 = 0x5400_0083 // b.lo
    static let ret: UInt32 = 0xD65F_03C0
    static let pacibsp: UInt32 = 0xD503_237F
    static let branch: UInt32 = 0x1400_0400 // b +0x1000
    static let branchWithLink: UInt32 = 0x9400_0400 // bl +0x1000
    static let loadX16Literal: UInt32 = 0x5800_0050 // ldr x16, #8
    static let branchX16: UInt32 = 0xD61F_0200 // br x16
    static let pageX17: UInt32 = 0xB000_0011 // adrp x17, <page>
    static let addX17: UInt32 = 0x9100_4231 // add x17, x17, #0x10
    static let branchX17: UInt32 = 0xD61F_0220 // br x17
    static let branchX8: UInt32 = 0xD61F_0100 // br x8
}

@Suite struct TrampolineDetectionTests {
    @Test(arguments: [
        [Instruction.branch, Instruction.ret, Instruction.ret, Instruction.ret],
        [Instruction.loadX16Literal, Instruction.branchX16, 0, 0],
        [Instruction.pageX17, Instruction.addX17, Instruction.branchX17, Instruction.ret],
        [Instruction.branchX16],
    ])
    func hookedPrologueIsATrampoline(instructions: [UInt32]) {
        #expect(jbp_instructions_are_trampoline(instructions, instructions.count))
    }

    @Test(arguments: [
        [Instruction.movX16Access, Instruction.svc, Instruction.branchIfCarryClear, Instruction.ret],
        [Instruction.pacibsp, Instruction.branchWithLink, Instruction.ret, Instruction.ret],
        [Instruction.pacibsp, Instruction.branch, Instruction.ret, Instruction.ret],
        [Instruction.pacibsp, Instruction.branchX8, Instruction.ret, Instruction.ret],
        [Instruction.ret, Instruction.ret, Instruction.ret, Instruction.ret, Instruction.branchX16],
        [],
    ])
    func stockPrologueIsNotATrampoline(instructions: [UInt32]) {
        #expect(!jbp_instructions_are_trampoline(instructions, instructions.count))
    }

    @Test func missingInstructionsAreNotATrampoline() {
        #expect(!jbp_instructions_are_trampoline(nil, 4))
    }
}

/// Exercises the real probes against the Simulator's file system and process.
@Suite struct DarwinLowLevelProbeTests {
    let probe = DarwinLowLevelProbe()

    private func temporaryPath() -> String {
        NSTemporaryDirectory() + "jailbreak-detector-tests-\(UUID().uuidString)"
    }

    @Test func libcFindsExistingFilesOnly() throws {
        let path = temporaryPath()
        #expect(!probe.libcFileExists(atPath: path))
        try Data().write(to: URL(fileURLWithPath: path))
        defer { try? FileManager.default.removeItem(atPath: path) }
        #expect(probe.libcFileExists(atPath: path))
    }

    @Test func libcReadsSymbolicLinkDestinations() throws {
        let path = temporaryPath()
        try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: "/destination/that/is/missing")
        defer { try? FileManager.default.removeItem(atPath: path) }
        #expect(probe.libcSymbolicLinkDestination(atPath: path) == "/destination/that/is/missing")
        #expect(probe.libcSymbolicLinkDestination(atPath: NSTemporaryDirectory()) == nil)
    }

    @Test func foundationListsExistingDirectoriesOnly() {
        #expect(probe.foundationCanListDirectory(atPath: NSTemporaryDirectory()))
        #expect(!probe.foundationCanListDirectory(atPath: temporaryPath()))
    }

    #if arch(arm64)
    @Test func directSyscallsOpenExistingDirectoriesOnly() {
        #expect(probe.directCanOpenDirectory(atPath: NSTemporaryDirectory()))
        #expect(!probe.directCanOpenDirectory(atPath: temporaryPath()))
    }

    @Test func directSyscallsAreSupported() {
        #expect(probe.supportsDirectSyscalls)
    }

    @Test func directSyscallsFindExistingFilesAndDirectoriesOnly() throws {
        let path = temporaryPath()
        #expect(!probe.directFileExists(atPath: path))
        #expect(jbp_direct_access(path) == 0)
        #expect(jbp_direct_open(path) == 0)

        try Data().write(to: URL(fileURLWithPath: path))
        defer { try? FileManager.default.removeItem(atPath: path) }
        #expect(probe.directFileExists(atPath: path))
        #expect(jbp_direct_access(path) == 1)
        #expect(jbp_direct_open(path) == 1)
        #expect(jbp_direct_access(NSTemporaryDirectory()) == 1)
    }

    @Test func directOpenDoesNotLeakFileDescriptors() throws {
        let path = temporaryPath()
        try Data().write(to: URL(fileURLWithPath: path))
        defer { try? FileManager.default.removeItem(atPath: path) }

        // More attempts than the process may hold open descriptors, so a leak makes a later attempt fail.
        var limit = rlimit()
        getrlimit(RLIMIT_NOFILE, &limit)
        let attempts = Int(min(limit.rlim_cur, 65536)) + 16
        let failures = (0..<attempts).filter { _ in jbp_direct_open(path) != 1 }
        #expect(failures.isEmpty)
    }

    @Test func directSyscallsReadSymbolicLinkDestinations() throws {
        let path = temporaryPath()
        try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: "/destination/that/is/missing")
        defer { try? FileManager.default.removeItem(atPath: path) }

        #expect(probe.directSymbolicLinkDestination(atPath: path) == "/destination/that/is/missing")
        #expect(probe.directSymbolicLinkDestination(atPath: NSTemporaryDirectory()) == nil)
        #expect(probe.directSymbolicLinkDestination(atPath: temporaryPath()) == nil)
    }

    @Test(arguments: FunctionPrologueCheck.watchedFunctions)
    func watchedSystemFunctionIsIntact(symbol: String) {
        #expect(jbp_function_is_trampoline(symbol) == 0)
        #expect(!probe.functionStartsWithTrampoline(symbol))
    }
    #else
    @Test func directSyscallsAreUnsupported() {
        #expect(!probe.supportsDirectSyscalls)
        #expect(jbp_direct_access("/") == -1)
        #expect(jbp_direct_open("/") == -1)
        #expect(jbp_function_is_trampoline("access") == -1)
    }
    #endif

    @Test func unknownFunctionIsNotReportedAsATrampoline() {
        #expect(jbp_function_is_trampoline("jbp_function_that_does_not_exist") == -1)
        #expect(!probe.functionStartsWithTrampoline("jbp_function_that_does_not_exist"))
    }

    @Test func forkIsAllowedInTheSimulator() {
        #expect(probe.forkSucceeds())
    }

    @Test func detectsAListeningLoopbackPort() throws {
        let listener = try LoopbackListener()
        #expect(probe.isLoopbackPortOpen(listener.port))
        listener.close()
        #expect(!probe.isLoopbackPortOpen(listener.port))
    }
}

/// A TCP socket listening on a port the system picked on the loopback interface.
private struct LoopbackListener {
    struct SocketError: Error {}

    let descriptor: Int32
    let port: UInt16

    init() throws {
        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw SocketError() }
        self.descriptor = descriptor

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = INADDR_LOOPBACK.bigEndian
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)

        let bound = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { generic in
                bind(descriptor, generic, length) == 0
                    && listen(descriptor, 1) == 0
                    && getsockname(descriptor, generic, &length) == 0
            }
        }
        guard bound else {
            Darwin.close(descriptor)
            throw SocketError()
        }
        port = UInt16(bigEndian: address.sin_port)
    }

    func close() {
        Darwin.close(descriptor)
    }
}

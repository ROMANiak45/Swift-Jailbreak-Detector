//
//  LowLevelProbe.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

import CJailbreakProbes
import Darwin
import Foundation

/// The low-level view of the system that the hardening checks read. Tests substitute a fake.
protocol LowLevelProbe: Sendable {
    /// Whether this build can issue system calls directly.
    var supportsDirectSyscalls: Bool { get }

    /// Whether the kernel, asked directly, says something exists at the path.
    func directFileExists(atPath path: String) -> Bool
    /// Whether libc says something exists at the path.
    func libcFileExists(atPath path: String) -> Bool
    /// The destination of the symbolic link at the path, read from the kernel directly.
    func directSymbolicLinkDestination(atPath path: String) -> String?
    /// The destination of the symbolic link at the path, read through libc.
    func libcSymbolicLinkDestination(atPath path: String) -> String?
    /// Whether the kernel, asked directly, lets the process open the directory for reading.
    func directCanOpenDirectory(atPath path: String) -> Bool
    /// Whether Foundation can list the directory.
    func foundationCanListDirectory(atPath path: String) -> Bool
    /// Whether the named function starts with a jump to somewhere else.
    func functionStartsWithTrampoline(_ symbol: String) -> Bool
    /// Whether the process is allowed to fork.
    func forkSucceeds() -> Bool
    /// Whether something accepts connections on the loopback interface at the port.
    func isLoopbackPortOpen(_ port: UInt16) -> Bool
}

/// Reads the real system through the C probes.
struct DarwinLowLevelProbe: LowLevelProbe {
    private static let connectionTimeoutMilliseconds: Int32 = 150

    var supportsDirectSyscalls: Bool { jbp_direct_syscalls_supported() }

    func directFileExists(atPath path: String) -> Bool {
        jbp_direct_access(path) == 1 || jbp_direct_open(path) == 1
    }

    /// Uses the same two calls as the direct version, so that a disagreement can only come from a hook.
    func libcFileExists(atPath path: String) -> Bool {
        if access(path, F_OK) == 0 { return true }
        let descriptor = open(path, O_RDONLY | O_CLOEXEC)
        guard descriptor >= 0 else { return false }
        close(descriptor)
        return true
    }

    func directSymbolicLinkDestination(atPath path: String) -> String? {
        Self.string { buffer, size in jbp_direct_readlink(path, buffer, size) }
    }

    func libcSymbolicLinkDestination(atPath path: String) -> String? {
        Self.string { buffer, size in readlink(path, buffer, size) }
    }

    func directCanOpenDirectory(atPath path: String) -> Bool {
        jbp_direct_open(path) == 1
    }

    func foundationCanListDirectory(atPath path: String) -> Bool {
        (try? FileManager.default.contentsOfDirectory(atPath: path)) != nil
    }

    func functionStartsWithTrampoline(_ symbol: String) -> Bool {
        jbp_function_is_trampoline(symbol) == 1
    }

    func forkSucceeds() -> Bool {
        jbp_fork_succeeds() == 1
    }

    func isLoopbackPortOpen(_ port: UInt16) -> Bool {
        jbp_loopback_port_is_open(port, Self.connectionTimeoutMilliseconds) == 1
    }

    /// Builds a string from a call that fills a buffer and returns the byte count, or a negative value.
    private static func string(filledBy fill: (UnsafeMutablePointer<CChar>?, Int) -> Int) -> String? {
        var buffer = [UInt8](repeating: 0, count: Int(PATH_MAX))
        let length = buffer.withUnsafeMutableBytes { bytes in
            fill(bytes.baseAddress?.assumingMemoryBound(to: CChar.self), bytes.count)
        }
        guard length >= 0 else { return nil }
        return String(decoding: buffer[..<length], as: UTF8.self)
    }
}

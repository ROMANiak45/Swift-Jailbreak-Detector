//
//  HardeningChecks.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

import JailbreakDetector

/// Extra checks that are harder to bypass than the core ones.
///
/// They issue system calls directly, read the machine code of system functions, call `fork` and connect to
/// local ports. None of this uses private API, but it is the kind of behaviour App Review may question, so
/// it ships in this separate product and stays out of the binary unless the app links it.
public enum HardeningChecks {
    /// Repeats the file and symbolic link lookups with system calls issued directly to the kernel.
    public static let directSyscalls: any JailbreakCheck = DirectSyscallCheck()
    /// Looks for inline hooks at the start of the libc functions the checks rely on.
    public static let functionPrologues: any JailbreakCheck = FunctionPrologueCheck()
    /// Tries to fork the process.
    public static let fork: any JailbreakCheck = ForkCheck()
    /// Looks for SSH and Frida servers listening on the device.
    ///
    /// This check connects to three local ports and can block the calling thread for up to half a second.
    public static let loopbackPorts: any JailbreakCheck = LoopbackPortCheck()

    /// Every hardening check.
    public static let all: [any JailbreakCheck] = [directSyscalls, functionPrologues, fork, loopbackPorts]
}

extension JailbreakCheckID {
    /// Jailbreak files and symbolic links found with system calls issued directly to the kernel.
    public static let directSyscalls = JailbreakCheckID(rawValue: "direct-syscalls")
    /// Inline hooks at the start of libc functions.
    public static let functionPrologues = JailbreakCheckID(rawValue: "function-prologues")
    /// The process being allowed to fork.
    public static let fork = JailbreakCheckID(rawValue: "fork")
    /// SSH and Frida servers listening on the device.
    public static let loopbackPorts = JailbreakCheckID(rawValue: "loopback-ports")
}

extension JailbreakDetector.Configuration {
    /// Every built-in check followed by every hardening check.
    public static let hardened = JailbreakDetector.Configuration(additionalChecks: HardeningChecks.all)
}

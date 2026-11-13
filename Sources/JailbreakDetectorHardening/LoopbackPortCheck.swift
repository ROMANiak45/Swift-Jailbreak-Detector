//
//  LoopbackPortCheck.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

import JailbreakDetector

/// Looks for services that jailbreaks and instrumentation tools run on the device itself.
///
/// Another app could listen on the same port, so an open port is only suspicious.
struct LoopbackPortCheck: JailbreakCheck {
    /// SSH, the SSH server bundled with checkra1n and palera1n, and the Frida server.
    static let watchedPorts: [UInt16] = [22, 44, 27042]

    let id = JailbreakCheckID.loopbackPorts
    var probe: any LowLevelProbe = DarwinLowLevelProbe()

    func run(_ context: JailbreakCheckContext) -> [JailbreakReport.Finding] {
        Self.watchedPorts
            .filter { probe.isLoopbackPortOpen($0) }
            .map { JailbreakReport.Finding(check: id, confidence: .suspicious, detail: "127.0.0.1:\($0)") }
    }
}

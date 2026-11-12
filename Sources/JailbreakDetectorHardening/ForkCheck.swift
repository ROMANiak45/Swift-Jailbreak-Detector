//
//  ForkCheck.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

import JailbreakDetector

/// Tries to fork the process, which the sandbox denies on a stock system.
struct ForkCheck: JailbreakCheck {
    let id = JailbreakCheckID.fork
    var probe: any LowLevelProbe = DarwinLowLevelProbe()

    func run() -> [JailbreakReport.Finding] {
        guard probe.forkSucceeds() else { return [] }
        return [JailbreakReport.Finding(check: id, confidence: .definitive, detail: "fork() succeeded")]
    }
}

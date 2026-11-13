//
//  FunctionPrologueCheck.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

import JailbreakDetector

/// Reads the first instructions of the libc functions the checks rely on, looking for an inline hook.
///
/// An inline hook overwrites the start of a function with a jump to the hook, which leaves the function's
/// address unchanged and so escapes the core hook integrity check.
struct FunctionPrologueCheck: JailbreakCheck {
    static let watchedFunctions = ["access", "open", "readlink", "fopen", "creat", "getenv"]

    let id = JailbreakCheckID.functionPrologues
    var probe: any LowLevelProbe = DarwinLowLevelProbe()

    func run(_ context: JailbreakCheckContext) -> [JailbreakReport.Finding] {
        Self.watchedFunctions
            .filter { probe.functionStartsWithTrampoline($0) }
            .map { JailbreakReport.Finding(check: id, confidence: .suspicious, detail: $0) }
    }
}

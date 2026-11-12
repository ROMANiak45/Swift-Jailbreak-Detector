//
//  JailbreakCheck.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

/// A check that runs alongside the built-in ones.
///
/// Add conforming values to ``JailbreakDetector/Configuration/additionalChecks``. They run only on a physical
/// device, after the built-in checks, on the thread that called the evaluation.
public protocol JailbreakCheck: Sendable {
    /// The identifier attached to this check's findings.
    var id: JailbreakCheckID { get }

    /// Inspects the system and returns one finding per indicator observed, or an empty array.
    func run() -> [JailbreakReport.Finding]
}

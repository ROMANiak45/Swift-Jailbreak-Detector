//
//  JailbreakReport.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

/// The outcome of a jailbreak evaluation.
///
/// The report keeps every individual finding so that a backend can score risk itself instead of relying on
/// a single boolean.
public struct JailbreakReport: Sendable, Hashable, Codable {
    /// The overall conclusion drawn from the findings.
    public enum Verdict: String, Sendable, Hashable, Codable {
        /// No check produced a finding.
        case clean
        /// At least one check produced a finding, but none of them is conclusive on its own.
        case suspicious
        /// At least one check produced a conclusive finding.
        case jailbroken
    }

    /// Where the evaluation ran.
    public enum Environment: String, Sendable, Hashable, Codable {
        /// A physical iOS or iPadOS device.
        case device
        /// The iOS Simulator. No checks run here because the host Mac's file system looks like a jailbreak.
        case simulator
        /// A Mac running the app through Mac Catalyst or as an iOS app on Apple silicon. No checks run here.
        case mac
    }

    /// How strongly a finding indicates a jailbreak.
    public enum Confidence: String, Sendable, Hashable, Codable {
        /// Unusual for a stock device, but with possible innocent explanations.
        case suspicious
        /// Not expected on a stock device under any normal circumstances.
        case definitive
    }

    /// A single indicator reported by a check.
    public struct Finding: Sendable, Hashable, Codable {
        /// The check that produced the finding.
        public let check: JailbreakCheckID
        /// How strongly the finding indicates a jailbreak.
        public let confidence: Confidence
        /// The indicator that was observed, such as a file path or an image name.
        public let detail: String

        public init(check: JailbreakCheckID, confidence: Confidence, detail: String) {
            self.check = check
            self.confidence = confidence
            self.detail = detail
        }
    }

    /// The overall conclusion: `jailbroken` if any finding is definitive, `suspicious` if there are only
    /// suspicious findings, and `clean` if there are none.
    public let verdict: Verdict
    /// Where the evaluation ran.
    public let environment: Environment
    /// Every indicator that was observed, in the order the checks ran.
    public let findings: [Finding]

    /// Creates a report and derives its verdict from the findings.
    public init(environment: Environment, findings: [Finding]) {
        self.environment = environment
        self.findings = findings
        if findings.contains(where: { $0.confidence == .definitive }) {
            verdict = .jailbroken
        } else if findings.isEmpty {
            verdict = .clean
        } else {
            verdict = .suspicious
        }
    }
}

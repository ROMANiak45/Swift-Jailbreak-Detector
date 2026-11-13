//
//  Configuration.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

extension JailbreakDetector {
    /// Selects which checks run, what they look for, and how the Simulator is reported.
    public struct Configuration: Sendable {
        /// How an evaluation in the iOS Simulator is reported.
        public enum SimulatorPolicy: Sendable, Hashable {
            /// Report a clean verdict with no findings.
            case reportClean
            /// Report a jailbroken verdict, to exercise the app's blocked-device flow during development.
            case reportJailbroken
        }

        /// The built-in checks to run. Defaults to all of them.
        public var checks: Set<JailbreakCheckID>
        /// Extra checks to run after the built-in ones, such as those in `JailbreakDetectorHardening`.
        public var additionalChecks: [any JailbreakCheck]
        /// The indicators the checks look for. Defaults to the built-in set.
        public var indicators: IndicatorSet
        /// How an evaluation in the iOS Simulator is reported. Defaults to a clean verdict.
        public var simulatorPolicy: SimulatorPolicy

        public init(
            checks: Set<JailbreakCheckID> = JailbreakCheckID.builtIn,
            additionalChecks: [any JailbreakCheck] = [],
            indicators: IndicatorSet = .builtIn,
            simulatorPolicy: SimulatorPolicy = .reportClean
        ) {
            self.checks = checks
            self.additionalChecks = additionalChecks
            self.indicators = indicators
            self.simulatorPolicy = simulatorPolicy
        }

        /// Every built-in check with the built-in indicators, no additional checks, and a clean verdict in
        /// the Simulator.
        public static let `default` = Configuration()
    }
}

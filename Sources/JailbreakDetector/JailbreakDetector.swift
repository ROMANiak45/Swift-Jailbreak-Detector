//
//  JailbreakDetector.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

/// Detects whether the current device is jailbroken.
///
/// Detection that runs on the device can be bypassed by whoever controls the device. Treat the report as one
/// risk signal and pair it with server-side attestation.
public enum JailbreakDetector {
    /// Returns `true` when the default evaluation concludes that the device is jailbroken.
    ///
    /// A suspicious verdict returns `false`. Call `evaluate(_:)` to act on suspicious findings.
    public static func isJailbroken() -> Bool {
        evaluate().verdict == .jailbroken
    }

    /// Runs the configured checks and reports what they found.
    ///
    /// This overload is synchronous, safe to call from any thread, and does not touch UIKit. It skips the
    /// URL scheme check, which needs the main actor.
    public static func evaluate(_ configuration: Configuration = .default) -> JailbreakReport {
        Engine.live.evaluate(configuration)
    }

    /// Runs the configured checks, including the URL scheme check, and reports what they found.
    ///
    /// The URL scheme check only queries schemes that the host app lists under `LSApplicationQueriesSchemes`
    /// in its `Info.plist`.
    @available(iOSApplicationExtension, unavailable)
    public static func evaluate(_ configuration: Configuration = .default) async -> JailbreakReport {
        await Engine.live.evaluate(configuration, urlSchemeProbe: ApplicationURLSchemeProbe())
    }
}

//
//  JailbreakDetector.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

import Foundation

/// Detects whether the current device is jailbroken.
///
/// Detection that runs on the device can be bypassed by whoever controls the device. Treat the report as one
/// risk signal and pair it with server-side attestation.
public enum JailbreakDetector {
    /// Returns `true` when the default evaluation concludes that the device is jailbroken.
    ///
    /// A suspicious verdict returns `false`. Call `evaluate(_:nonce:)` to act on suspicious findings.
    public static func isJailbroken() -> Bool {
        evaluate().verdict == .jailbroken
    }

    /// Runs the configured checks and reports what they found.
    ///
    /// This overload is synchronous, safe to call from any thread, and does not touch UIKit. It skips the
    /// URL scheme check, which needs the main actor. Inside an `async` function Swift picks the asynchronous
    /// overload instead.
    ///
    /// - Parameter nonce: A value issued by your server for this evaluation, carried into the report so the
    ///   server can reject a replayed report. Required by ``JailbreakReport/attestationPayload()``.
    public static func evaluate(_ configuration: Configuration = .default, nonce: Data? = nil) -> JailbreakReport {
        Engine.live.evaluate(configuration, nonce: nonce)
    }

    /// Runs the configured checks, including the URL scheme check, and reports what they found.
    ///
    /// The URL scheme check only queries schemes that the host app lists under `LSApplicationQueriesSchemes`
    /// in its `Info.plist`.
    ///
    /// - Parameter nonce: A value issued by your server for this evaluation, carried into the report so the
    ///   server can reject a replayed report. Required by ``JailbreakReport/attestationPayload()``.
    @available(iOSApplicationExtension, unavailable)
    public static func evaluate(
        _ configuration: Configuration = .default,
        nonce: Data? = nil
    ) async -> JailbreakReport {
        await Engine.live.evaluate(configuration, nonce: nonce, urlSchemeProbe: ApplicationURLSchemeProbe())
    }
}

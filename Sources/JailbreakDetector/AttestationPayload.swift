//
//  AttestationPayload.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 13.11.2026.
//

import CryptoKit
import Foundation

/// A report encoded for the server, with the digest to have App Attest sign.
///
/// Send ``data`` to the server unchanged. Pass ``digest`` as the `clientDataHash` of
/// `DCAppAttestService.generateAssertion(_:clientDataHash:)`; the server recomputes the SHA-256 of the
/// bytes it received, so no canonical encoding is needed.
public struct AttestationPayload: Sendable, Hashable {
    /// The JSON-encoded report.
    public let data: Data
    /// The SHA-256 digest of ``data``.
    public let digest: Data
}

extension JailbreakReport {
    /// Why a report could not be encoded for attestation.
    public enum AttestationError: Error, Hashable, Sendable {
        /// The report was evaluated without a nonce, so the server could not tell it from a replay.
        case missingNonce
    }

    /// Encodes the report for the server and computes the digest to have App Attest sign.
    ///
    /// Throws ``AttestationError/missingNonce`` if the evaluation was not given a nonce.
    public func attestationPayload() throws -> AttestationPayload {
        guard nonce != nil else { throw AttestationError.missingNonce }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(self)
        return AttestationPayload(data: data, digest: Data(SHA256.hash(data: data)))
    }
}

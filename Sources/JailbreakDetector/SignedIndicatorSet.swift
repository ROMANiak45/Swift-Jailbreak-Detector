//
//  SignedIndicatorSet.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 13.11.2026.
//

import CryptoKit
import Foundation

extension IndicatorSet {
    /// Why a delivered indicator set was rejected.
    public enum VerificationError: Error, Hashable, Sendable {
        /// The signature is not a DER-encoded P-256 ECDSA signature.
        case malformedSignature
        /// The signature does not match the payload and public key.
        case invalidSignature
        /// The payload is signed correctly but is not an indicator set.
        case undecodablePayload
        /// The set is older than the newest one the app has already accepted.
        case versionTooOld(version: Int, minimumVersion: Int)
    }

    /// Decodes an indicator set delivered by a server, after checking that it was signed with the
    /// matching private key.
    ///
    /// - Parameters:
    ///   - payload: The JSON bytes exactly as received.
    ///   - signature: A DER-encoded ECDSA signature over the SHA-256 digest of `payload`, as produced by
    ///     `openssl dgst -sha256 -sign key.pem payload.json`.
    ///   - publicKey: The public key the app ships with.
    ///   - minimumVersion: The version of the newest set the app has accepted before. A lower version is
    ///     rejected, so that an attacker cannot replay an older, signed list that lacks newer indicators.
    public static func verified(
        payload: Data,
        signature: Data,
        publicKey: P256.Signing.PublicKey,
        minimumVersion: Int = 0
    ) throws -> IndicatorSet {
        let ecdsaSignature: P256.Signing.ECDSASignature
        do {
            ecdsaSignature = try P256.Signing.ECDSASignature(derRepresentation: signature)
        } catch {
            throw VerificationError.malformedSignature
        }
        guard publicKey.isValidSignature(ecdsaSignature, for: payload) else {
            throw VerificationError.invalidSignature
        }
        let indicators: IndicatorSet
        do {
            indicators = try JSONDecoder().decode(IndicatorSet.self, from: payload)
        } catch {
            throw VerificationError.undecodablePayload
        }
        guard indicators.version >= minimumVersion else {
            throw VerificationError.versionTooOld(version: indicators.version, minimumVersion: minimumVersion)
        }
        return indicators
    }
}

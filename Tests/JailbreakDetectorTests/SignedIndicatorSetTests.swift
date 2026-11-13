//
//  SignedIndicatorSetTests.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 13.11.2026.
//

import CryptoKit
import Foundation
import Testing
import JailbreakDetector

@Suite struct SignedIndicatorSetTests {
    /// A list signed outside Swift with `openssl dgst -sha256 -sign`, to prove the formats interoperate.
    /// Only the public key is kept; the private key was discarded after signing.
    private enum OpenSSLFixture {
        static let publicKey = """
            -----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFpOyrCFgZUAqRSY5KHPyeFSOKJaA
            +zS0SLtHM4Xd8RA5fV+aVwR6911JhnCeGnlqBBe0jeKgSlW6tzgkxSl9cA==
            -----END PUBLIC KEY-----
            """
        static let payload = Data(
            #"{"version":3,"files":[{"path":"/var/private-marker","confidence":"definitive"}],"imageNames":["privatebypass.dylib"]}"#
                .utf8
        )
        static let signature = Data(
            base64Encoded: "MEQCIHcu2g8yNpxhFSWVRIuwHk+JmZ0865SsYnTpIggjVbRDAiBo73m4JoePzjXPWaFpXuR4PdUKEJIBqeSRMps1u09LsA=="
        )!
    }

    private let key = P256.Signing.PrivateKey()
    private let indicators = IndicatorSet(
        version: 5,
        files: [IndicatorSet.PathIndicator(path: "/var/private-marker", confidence: .definitive)],
        restrictedDirectories: ["/private/var/private-directory"]
    )

    private func signed(_ payload: Data, with key: P256.Signing.PrivateKey) throws -> Data {
        try key.signature(for: payload).derRepresentation
    }

    private func verify(
        _ payload: Data,
        signature: Data,
        minimumVersion: Int = 0
    ) throws -> IndicatorSet {
        try IndicatorSet.verified(
            payload: payload,
            signature: signature,
            publicKey: key.publicKey,
            minimumVersion: minimumVersion
        )
    }

    @Test func acceptsAValidSignature() throws {
        let payload = try JSONEncoder().encode(indicators)
        #expect(try verify(payload, signature: signed(payload, with: key)) == indicators)
    }

    @Test func acceptsAListSignedWithOpenSSL() throws {
        let publicKey = try P256.Signing.PublicKey(pemRepresentation: OpenSSLFixture.publicKey)
        let verified = try IndicatorSet.verified(
            payload: OpenSSLFixture.payload,
            signature: OpenSSLFixture.signature,
            publicKey: publicKey
        )
        #expect(verified.version == 3)
        #expect(verified.files == [IndicatorSet.PathIndicator(path: "/var/private-marker", confidence: .definitive)])
        #expect(verified.imageNames == ["privatebypass.dylib"])
        #expect(verified.isInjectedImage("/usr/lib/PrivateBypass.dylib"))
        #expect(verified.symbolicLinks.isEmpty)
    }

    @Test func rejectsATamperedPayload() throws {
        let payload = try JSONEncoder().encode(indicators)
        let signature = try signed(payload, with: key)
        var emptied = indicators
        emptied.files = []
        let tampered = try JSONEncoder().encode(emptied)
        #expect(throws: IndicatorSet.VerificationError.invalidSignature) {
            try verify(tampered, signature: signature)
        }
    }

    @Test func rejectsASignatureFromAnotherKey() throws {
        let payload = try JSONEncoder().encode(indicators)
        #expect(throws: IndicatorSet.VerificationError.invalidSignature) {
            try verify(payload, signature: signed(payload, with: P256.Signing.PrivateKey()))
        }
    }

    @Test(arguments: [Data(), Data("not a signature".utf8), Data(repeating: 0, count: 64)])
    func rejectsAMalformedSignature(signature: Data) throws {
        let payload = try JSONEncoder().encode(indicators)
        #expect(throws: IndicatorSet.VerificationError.malformedSignature) {
            try verify(payload, signature: signature)
        }
    }

    @Test func rejectsASignedPayloadThatIsNotAnIndicatorSet() throws {
        let payload = Data(#"{"files":"not a list"}"#.utf8)
        #expect(throws: IndicatorSet.VerificationError.undecodablePayload) {
            try verify(payload, signature: signed(payload, with: key))
        }
    }

    @Test func rejectsAVersionBelowTheMinimum() throws {
        let payload = try JSONEncoder().encode(indicators)
        let signature = try signed(payload, with: key)
        #expect(throws: IndicatorSet.VerificationError.versionTooOld(version: 5, minimumVersion: 6)) {
            try verify(payload, signature: signature, minimumVersion: 6)
        }
        #expect(try verify(payload, signature: signature, minimumVersion: 5).version == 5)
    }
}

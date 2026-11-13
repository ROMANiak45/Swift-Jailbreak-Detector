//
//  AttestationPayloadTests.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 13.11.2026.
//

import CryptoKit
import Foundation
import Testing
@testable import JailbreakDetector

@Suite struct NonceTests {
    private let nonce = Data("server-issued-nonce".utf8)

    @Test(arguments: [JailbreakReport.Environment.device, .simulator, .mac])
    func nonceIsCarriedIntoTheReport(environment: JailbreakReport.Environment) {
        let report = Engine(probe: FakeSystemProbe.rootful, environment: environment).evaluate(.default, nonce: nonce)
        #expect(report.nonce == nonce)
    }

    @Test func asynchronousEvaluationCarriesTheNonce() async {
        let report = await Engine(probe: FakeSystemProbe.clean, environment: .device)
            .evaluate(.default, nonce: nonce, urlSchemeProbe: FakeURLSchemeProbe())
        #expect(report.nonce == nonce)
    }

    @Test func reportHasNoNonceByDefault() {
        #expect(Engine(probe: FakeSystemProbe.clean, environment: .device).evaluate(.default).nonce == nil)
    }

    @Test func reportRecordsTheIndicatorVersion() {
        let engine = Engine(probe: FakeSystemProbe.clean, environment: .device)
        #expect(engine.evaluate(.default).indicatorVersion == 0)
        let configuration = JailbreakDetector.Configuration(indicators: IndicatorSet.builtIn.merging(IndicatorSet(version: 7)))
        #expect(engine.evaluate(configuration).indicatorVersion == 7)
    }

    @Test func synchronousPublicAPICarriesTheNonce() {
        #expect(JailbreakDetector.evaluate(nonce: nonce).nonce == nonce)
    }

    @Test func asynchronousPublicAPICarriesTheNonce() async {
        #expect(await JailbreakDetector.evaluate(nonce: nonce).nonce == nonce)
    }
}

@Suite struct AttestationPayloadTests {
    private func report(nonce: Data?) -> JailbreakReport {
        Engine(probe: FakeSystemProbe.rootless, environment: .device).evaluate(.default, nonce: nonce)
    }

    @Test func digestIsTheSHA256OfThePayloadBytes() throws {
        let payload = try report(nonce: Data("a".utf8)).attestationPayload()
        #expect(payload.digest == Data(SHA256.hash(data: payload.data)))
        #expect(payload.digest.count == 32)
    }

    @Test func payloadDecodesBackToTheReport() throws {
        let original = report(nonce: Data("a".utf8))
        let decoded = try JSONDecoder().decode(JailbreakReport.self, from: original.attestationPayload().data)
        #expect(decoded == original)
    }

    @Test func differentNoncesGiveDifferentDigests() throws {
        let first = try report(nonce: Data("a".utf8)).attestationPayload()
        let second = try report(nonce: Data("b".utf8)).attestationPayload()
        #expect(first.digest != second.digest)
    }

    @Test func sameReportGivesTheSameBytes() throws {
        let report = report(nonce: Data("a".utf8))
        #expect(try report.attestationPayload() == report.attestationPayload())
    }

    @Test func reportWithoutANonceIsRejected() {
        #expect(throws: JailbreakReport.AttestationError.missingNonce) {
            try report(nonce: nil).attestationPayload()
        }
    }
}

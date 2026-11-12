//
//  HookIntegrityCheck.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

/// Verifies that the system functions the other checks rely on are still implemented by the system.
///
/// A bypass tweak hides a jailbreak by redirecting these functions to its own code. A function that resolves
/// to a known hooking library is definitive; one that resolves anywhere else outside the system and the app
/// bundle is suspicious.
struct HookIntegrityCheck: SystemCheck {
    let id = JailbreakCheckID.hookIntegrity

    func findings(using probe: any SystemProbe) -> [JailbreakReport.Finding] {
        let trust = ImageTrust(mainBundlePath: probe.mainBundlePath)
        return probe.functionOrigins().compactMap { origin in
            guard let image = origin.imagePath else {
                return JailbreakReport.Finding(
                    check: id,
                    confidence: .suspicious,
                    detail: "\(origin.name) -> outside any loaded image"
                )
            }
            if JailbreakIndicators.isInjectedImage(image) {
                return JailbreakReport.Finding(check: id, confidence: .definitive, detail: "\(origin.name) -> \(image)")
            }
            if !trust.isTrusted(image) {
                return JailbreakReport.Finding(check: id, confidence: .suspicious, detail: "\(origin.name) -> \(image)")
            }
            return nil
        }
    }
}

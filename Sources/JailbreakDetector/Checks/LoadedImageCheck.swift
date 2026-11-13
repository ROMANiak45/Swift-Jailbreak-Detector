//
//  LoadedImageCheck.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

/// Scans the images loaded into the process for hooking frameworks, instrumentation tools and bypass tweaks.
///
/// A known name is definitive. Any other image loaded from outside the system and the app bundle is
/// suspicious, which catches tweaks this library has never heard of.
struct LoadedImageCheck: SystemCheck {
    let id = JailbreakCheckID.loadedImages

    func findings(using probe: any SystemProbe, indicators: IndicatorSet) -> [JailbreakReport.Finding] {
        let trust = ImageTrust(mainBundlePath: probe.mainBundlePath)
        let matcher = ImageMatcher(indicators)
        return probe.loadedImagePaths().compactMap { image in
            if matcher.matches(image) {
                return JailbreakReport.Finding(check: id, confidence: .definitive, detail: image)
            }
            if !image.isEmpty, !trust.isTrusted(image) {
                return JailbreakReport.Finding(check: id, confidence: .suspicious, detail: image)
            }
            return nil
        }
    }
}

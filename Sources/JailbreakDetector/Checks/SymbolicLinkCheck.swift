//
//  SymbolicLinkCheck.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

/// Looks for symbolic links at paths that are real directories or absent on a stock system.
///
/// This also finds links whose destination the sandbox hides, which an existence check would miss.
struct SymbolicLinkCheck: SystemCheck {
    let id = JailbreakCheckID.symbolicLinks

    func findings(using probe: any SystemProbe, indicators: IndicatorSet) -> [JailbreakReport.Finding] {
        indicators.symbolicLinks.compactMap { indicator in
            guard let destination = probe.symbolicLinkDestination(atPath: indicator.path) else { return nil }
            return JailbreakReport.Finding(
                check: id,
                confidence: indicator.confidence,
                detail: "\(indicator.path) -> \(destination)"
            )
        }
    }
}

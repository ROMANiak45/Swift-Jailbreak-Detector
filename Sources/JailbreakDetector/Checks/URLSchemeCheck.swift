//
//  URLSchemeCheck.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

import Foundation

/// Asks the system whether an installed app handles a URL scheme registered by jailbreak apps.
///
/// Any app can register these schemes, so a match is only suspicious. Schemes the host app has not declared
/// under `LSApplicationQueriesSchemes` are skipped, because the system refuses to answer for them.
struct URLSchemeCheck: Sendable {
    let id = JailbreakCheckID.urlSchemes

    @MainActor
    func findings(using probe: any URLSchemeProbe, indicators: IndicatorSet) -> [JailbreakReport.Finding] {
        let declared = Set(probe.declaredQuerySchemes().map { $0.lowercased() })
        return indicators.urlSchemes
            .map { $0.lowercased() }
            .filter { declared.contains($0) }
            .compactMap { scheme in
                guard let url = URL(string: "\(scheme)://"), probe.canOpen(url) else { return nil }
                return JailbreakReport.Finding(check: id, confidence: .suspicious, detail: "\(scheme)://")
            }
    }
}

//
//  DirectSyscallCheck.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

import JailbreakDetector

/// Repeats the file, symbolic link and restricted directory lookups with system calls issued directly to
/// the kernel.
///
/// A bypass tweak hides jailbreak files by hooking the libc wrappers. Going around libc finds the files
/// anyway, and a path the kernel reports but libc or Foundation denies proves that they are being falsified.
struct DirectSyscallCheck: JailbreakCheck {
    let id = JailbreakCheckID.directSyscalls
    var probe: any LowLevelProbe = DarwinLowLevelProbe()

    func run(_ context: JailbreakCheckContext) -> [JailbreakReport.Finding] {
        guard probe.supportsDirectSyscalls else { return [] }
        let indicators = context.indicators
        return fileFindings(indicators) + symbolicLinkFindings(indicators) + directoryFindings(indicators)
    }

    private func fileFindings(_ indicators: IndicatorSet) -> [JailbreakReport.Finding] {
        indicators.files.compactMap { indicator in
            guard probe.directFileExists(atPath: indicator.path) else { return nil }
            return finding(
                confidence: indicator.confidence,
                detail: indicator.path,
                hiddenFrom: probe.libcFileExists(atPath: indicator.path) ? nil : "libc"
            )
        }
    }

    private func symbolicLinkFindings(_ indicators: IndicatorSet) -> [JailbreakReport.Finding] {
        indicators.symbolicLinks.compactMap { indicator in
            guard let destination = probe.directSymbolicLinkDestination(atPath: indicator.path) else { return nil }
            return finding(
                confidence: indicator.confidence,
                detail: "\(indicator.path) -> \(destination)",
                hiddenFrom: probe.libcSymbolicLinkDestination(atPath: indicator.path) == nil ? "libc" : nil
            )
        }
    }

    /// Opening a restricted directory is suspicious, like listing it in the core check.
    private func directoryFindings(_ indicators: IndicatorSet) -> [JailbreakReport.Finding] {
        indicators.restrictedDirectories.compactMap { directory in
            guard probe.directCanOpenDirectory(atPath: directory) else { return nil }
            return finding(
                confidence: .suspicious,
                detail: directory,
                hiddenFrom: probe.foundationCanListDirectory(atPath: directory) ? nil : "Foundation"
            )
        }
    }

    /// A finding the kernel confirms but a higher layer denies is definitive whatever the indicator says.
    private func finding(
        confidence: JailbreakReport.Confidence,
        detail: String,
        hiddenFrom layer: String?
    ) -> JailbreakReport.Finding {
        guard let layer else {
            return JailbreakReport.Finding(check: id, confidence: confidence, detail: detail)
        }
        return JailbreakReport.Finding(check: id, confidence: .definitive, detail: "\(detail) (hidden from \(layer))")
    }
}

//
//  DirectSyscallCheck.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

import JailbreakDetector

/// Repeats the file and symbolic link lookups with system calls issued directly to the kernel.
///
/// A bypass tweak hides jailbreak files by hooking the libc wrappers. Going around libc finds the files
/// anyway, and a path the kernel reports but libc denies proves that libc is being falsified.
struct DirectSyscallCheck: JailbreakCheck {
    let id = JailbreakCheckID.directSyscalls
    var probe: any LowLevelProbe = DarwinLowLevelProbe()

    func run(_ context: JailbreakCheckContext) -> [JailbreakReport.Finding] {
        guard probe.supportsDirectSyscalls else { return [] }
        return fileFindings(context.indicators) + symbolicLinkFindings(context.indicators)
    }

    private func fileFindings(_ indicators: IndicatorSet) -> [JailbreakReport.Finding] {
        indicators.files.compactMap { indicator in
            guard probe.directFileExists(atPath: indicator.path) else { return nil }
            return finding(
                confidence: indicator.confidence,
                detail: indicator.path,
                hiddenFromLibc: !probe.libcFileExists(atPath: indicator.path)
            )
        }
    }

    private func symbolicLinkFindings(_ indicators: IndicatorSet) -> [JailbreakReport.Finding] {
        indicators.symbolicLinks.compactMap { indicator in
            guard let destination = probe.directSymbolicLinkDestination(atPath: indicator.path) else { return nil }
            return finding(
                confidence: indicator.confidence,
                detail: "\(indicator.path) -> \(destination)",
                hiddenFromLibc: probe.libcSymbolicLinkDestination(atPath: indicator.path) == nil
            )
        }
    }

    private func finding(
        confidence: JailbreakReport.Confidence,
        detail: String,
        hiddenFromLibc: Bool
    ) -> JailbreakReport.Finding {
        if hiddenFromLibc {
            return JailbreakReport.Finding(check: id, confidence: .definitive, detail: "\(detail) (hidden from libc)")
        }
        return JailbreakReport.Finding(check: id, confidence: confidence, detail: detail)
    }
}

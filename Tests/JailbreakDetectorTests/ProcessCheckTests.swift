//
//  ProcessCheckTests.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

import Testing
@testable import JailbreakDetector

@Suite struct LoadedImageCheckTests {
    let check = LoadedImageCheck()

    @Test func stockImagesHaveNoFindings() {
        #expect(check.findings(using: FakeSystemProbe.clean).isEmpty)
    }

    @Test(arguments: [
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/usr/lib/libsubstrate.dylib",
        "/usr/lib/libhooker.dylib",
        "/usr/lib/systemhook.dylib",
        "/var/jb/usr/lib/libellekit.dylib",
        "/var/jb/usr/lib/TweakInject/SomeTweak.dylib",
        "/usr/lib/TweakInject/Liberty.dylib",
        "/private/var/containers/Bundle/Application/.jbroot-A1B2C3D4E5F60718/usr/lib/roothideinit.dylib",
        "/usr/lib/frida/frida-agent.dylib",
        "\(FakeSystemProbe.bundlePath)/Frameworks/FridaGadget.dylib",
        "/USR/LIB/LIBSUBSTITUTE.DYLIB",
    ])
    func knownInjectedImageIsDefinitive(image: String) {
        var probe = FakeSystemProbe()
        probe.loadedImages += [image]
        #expect(check.findings(using: probe) == [
            JailbreakReport.Finding(check: .loadedImages, confidence: .definitive, detail: image),
        ])
    }

    @Test func unknownImageFromOutsideTheSystemAndTheBundleIsSuspicious() {
        var probe = FakeSystemProbe()
        probe.loadedImages += ["/private/var/tmp/Unknown.dylib"]
        #expect(check.findings(using: probe) == [
            JailbreakReport.Finding(
                check: .loadedImages,
                confidence: .suspicious,
                detail: "/private/var/tmp/Unknown.dylib"
            ),
        ])
    }

    @Test(arguments: [
        "\(FakeSystemProbe.bundlePath)/Frameworks/Friday.framework/Friday",
        "\(FakeSystemProbe.bundlePath)/Frameworks/ShadowKit.framework/ShadowKit",
        "/var/containers/Bundle/Application/5B1F0C9E-2A53-4C0B-9E55-3F0B0A6C1D77/Bank.app/Bank.debug.dylib",
        "/Developer/usr/lib/libMainThreadChecker.dylib",
        "/System/Developer/usr/lib/libBacktraceRecording.dylib",
        "/private/preboot/Cryptexes/OS/System/Library/Frameworks/WebKit.framework/WebKit",
        "",
    ])
    func legitimateImageHasNoFindings(image: String) {
        var probe = FakeSystemProbe()
        probe.loadedImages += [image]
        #expect(check.findings(using: probe).isEmpty)
    }
}

@Suite struct EnvironmentVariableCheckTests {
    let check = EnvironmentVariableCheck()

    @Test func stockEnvironmentHasNoFindings() {
        #expect(check.findings(using: FakeSystemProbe.clean).isEmpty)
    }

    @Test func jailbreakVariablesAreDefinitive() {
        let findings = check.findings(using: FakeSystemProbe.roothide)
        #expect(Set(findings.details(.definitive)) == ["JBROOT", "JBRAND"])
    }

    @Test func injectedHookingLibraryIsDefinitive() {
        let findings = check.findings(using: FakeSystemProbe.rootless)
        #expect(Set(findings.details(.definitive)) == [
            "JB_ROOT_PATH",
            "DYLD_INSERT_LIBRARIES=/usr/lib/systemhook.dylib",
        ])
    }

    @Test func unknownInjectedLibraryIsSuspicious() {
        var probe = FakeSystemProbe()
        probe.environment = ["DYLD_INSERT_LIBRARIES": "/private/var/tmp/Unknown.dylib"]
        #expect(check.findings(using: probe) == [
            JailbreakReport.Finding(
                check: .environmentVariables,
                confidence: .suspicious,
                detail: "DYLD_INSERT_LIBRARIES=/private/var/tmp/Unknown.dylib"
            ),
        ])
    }

    @Test func librariesInjectedByXcodeHaveNoFindings() {
        var probe = FakeSystemProbe()
        probe.environment = [
            "DYLD_INSERT_LIBRARIES": [
                "/Developer/usr/lib/libBacktraceRecording.dylib",
                "/Developer/usr/lib/libMainThreadChecker.dylib",
                "/System/Developer/Library/PrivateFrameworks/DTDDISupport.framework/libViewDebuggerSupport.dylib",
                "@executable_path/Bank.debug.dylib",
            ].joined(separator: ":"),
        ]
        #expect(check.findings(using: probe).isEmpty)
    }
}

@Suite struct HookIntegrityCheckTests {
    let check = HookIntegrityCheck()

    @Test func stockImplementationsHaveNoFindings() {
        #expect(check.findings(using: FakeSystemProbe.clean).isEmpty)
    }

    @Test func functionsRedirectedToABypassTweakAreDefinitive() {
        let findings = check.findings(using: FakeSystemProbe.hooked)
        #expect(findings.details(.definitive) == [
            "access -> /var/jb/usr/lib/TweakInject/Shadow.dylib",
            "-[NSFileManager fileExistsAtPath:] -> /var/jb/usr/lib/TweakInject/Shadow.dylib",
        ])
        #expect(findings.allSatisfy { $0.check == .hookIntegrity })
    }

    @Test func functionRedirectedToAnUnknownImageIsSuspicious() {
        var probe = FakeSystemProbe()
        probe.origins = [FunctionOrigin(name: "access", imagePath: "/private/var/tmp/Unknown.dylib")]
        #expect(check.findings(using: probe).details(.suspicious) == [
            "access -> /private/var/tmp/Unknown.dylib",
        ])
    }

    @Test func functionOutsideEveryImageIsSuspicious() {
        var probe = FakeSystemProbe()
        probe.origins = [FunctionOrigin(name: "access", imagePath: nil)]
        #expect(check.findings(using: probe).details(.suspicious) == ["access -> outside any loaded image"])
    }

    @Test func methodSwizzledByTheAppItselfHasNoFindings() {
        var probe = FakeSystemProbe()
        probe.origins = [
            FunctionOrigin(
                name: "-[UIApplication canOpenURL:]",
                imagePath: "\(FakeSystemProbe.bundlePath)/Frameworks/Analytics.framework/Analytics"
            ),
        ]
        #expect(check.findings(using: probe).isEmpty)
    }
}

@Suite struct URLSchemeCheckTests {
    let check = URLSchemeCheck()

    @Test @MainActor func installedJailbreakAppIsSuspicious() {
        let probe = FakeURLSchemeProbe(
            declaredSchemes: ["cydia", "sileo", "zbra", "filza"],
            installedSchemes: ["sileo", "filza"]
        )
        #expect(check.findings(using: probe) == [
            JailbreakReport.Finding(check: .urlSchemes, confidence: .suspicious, detail: "sileo://"),
            JailbreakReport.Finding(check: .urlSchemes, confidence: .suspicious, detail: "filza://"),
        ])
    }

    @Test @MainActor func undeclaredSchemesAreNotQueried() {
        let probe = FakeURLSchemeProbe(declaredSchemes: ["Cydia"], installedSchemes: ["cydia", "sileo"])
        #expect(check.findings(using: probe).map(\.detail) == ["cydia://"])
    }

    @Test @MainActor func nothingInstalledHasNoFindings() {
        let probe = FakeURLSchemeProbe(declaredSchemes: ["cydia", "sileo", "zbra", "filza"])
        #expect(check.findings(using: probe).isEmpty)
    }
}

@Suite struct ImageTrustTests {
    let trust = ImageTrust(mainBundlePath: FakeSystemProbe.bundlePath)

    @Test(arguments: [
        "/usr/lib/system/libsystem_kernel.dylib",
        "/System/Library/Frameworks/Foundation.framework/Foundation",
        "/Developer/usr/lib/libMainThreadChecker.dylib",
        "/private/preboot/Cryptexes/OS/System/Library/Frameworks/WebKit.framework/WebKit",
        "\(FakeSystemProbe.bundlePath)/Bank",
        "/var/containers/Bundle/Application/5B1F0C9E-2A53-4C0B-9E55-3F0B0A6C1D77/Bank.app/Frameworks/A.framework/A",
        "@rpath/A.framework/A",
    ])
    func trusted(image: String) {
        #expect(trust.isTrusted(image))
    }

    @Test(arguments: [
        "/var/jb/usr/lib/TweakInject/SomeTweak.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/SomeTweak.dylib",
        "/private/preboot/3A9F/jb-x1Y2z3/procursus/usr/lib/libellekit.dylib",
        "/private/var/containers/Bundle/Application/.jbroot-A1B2C3D4E5F60718/usr/lib/roothideinit.dylib",
        "/private/var/containers/Bundle/Application/5B1F0C9E-2A53-4C0B-9E55-3F0B0A6C1D77/Bank.app.evil/x.dylib",
        "/private/var/tmp/Unknown.dylib",
    ])
    func untrusted(image: String) {
        #expect(!trust.isTrusted(image))
    }

    @Test func extensionTrustsFrameworksEmbeddedInItsHostApp() {
        let trust = ImageTrust(mainBundlePath: "\(FakeSystemProbe.bundlePath)/PlugIns/Widget.appex")
        #expect(trust.isTrusted("\(FakeSystemProbe.bundlePath)/Frameworks/Analytics.framework/Analytics"))
    }
}

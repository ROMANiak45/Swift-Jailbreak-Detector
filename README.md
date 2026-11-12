# JailbreakDetector

[![CI](https://github.com/ROMANiak45/Swift-Jailbreak-Detector/actions/workflows/ci.yml/badge.svg)](https://github.com/ROMANiak45/Swift-Jailbreak-Detector/actions/workflows/ci.yml)

A Swift package that reports whether an iPhone or iPad is jailbroken. It runs several independent checks and returns every finding, so an app or its backend can decide how to respond instead of trusting a single boolean.

Jailbreaking is the iOS equivalent of rooting on Android. This package covers iOS and iPadOS only.

## Requirements

- iOS 15 or iPadOS 15 and later
- Swift 6 toolchain (Xcode 16 or later)
- No third-party dependencies

## Installation

Add the package in Xcode with **File > Add Package Dependencies** and this URL:

```
https://github.com/ROMANiak45/Swift-Jailbreak-Detector.git
```

Or add it to `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/ROMANiak45/Swift-Jailbreak-Detector.git", from: "0.1.0"),
],
targets: [
    .target(
        name: "MyApp",
        dependencies: [
            .product(name: "JailbreakDetector", package: "Swift-Jailbreak-Detector"),
        ]
    ),
]
```

## Usage

The quickest check returns a boolean:

```swift
import JailbreakDetector

if JailbreakDetector.isJailbroken() {
    // Block sensitive features.
}
```

For anything beyond a yes or no, evaluate and read the report:

```swift
let report = await JailbreakDetector.evaluate()

switch report.verdict {
case .clean:
    break
case .suspicious:
    // Unusual, but not conclusive. Send the report to your backend for risk scoring.
    break
case .jailbroken:
    // At least one conclusive finding.
    break
}

for finding in report.findings {
    print(finding.check, finding.confidence, finding.detail)
}
```

`evaluate` has two overloads:

- **Synchronous** runs on any thread and does not touch UIKit. It skips the URL scheme check.
- **Asynchronous** also runs the URL scheme check on the main actor. It is unavailable in app extensions.

`JailbreakReport` is `Codable`, so it can be sent to a backend as is:

```swift
let body = try JSONEncoder().encode(report)
```

### Verdicts

Each finding is either `definitive` or `suspicious`.

- `jailbroken` means at least one finding is definitive.
- `suspicious` means there are findings, but none is definitive.
- `clean` means there are no findings.

`isJailbroken()` returns `true` only for a `jailbroken` verdict.

### URL scheme check

The asynchronous evaluation asks the system whether a jailbreak app is installed. iOS only answers for schemes the host app declares, so add these to the app's `Info.plist`:

```xml
<key>LSApplicationQueriesSchemes</key>
<array>
    <string>cydia</string>
    <string>sileo</string>
    <string>zbra</string>
    <string>filza</string>
</array>
```

Schemes that are not declared are skipped. Nothing fails without them.

### Configuration

```swift
var configuration = JailbreakDetector.Configuration.default

// Run only some of the built-in checks.
configuration.checks = [.fileArtifacts, .loadedImages, .hookIntegrity]

// Report the Simulator as jailbroken to exercise the blocked-device flow during development.
configuration.simulatorPolicy = .reportJailbroken

let report = JailbreakDetector.evaluate(configuration)
```

To add a check of your own, conform a type to `JailbreakCheck` and append it to `configuration.additionalChecks`.

## Checks

The core product, `JailbreakDetector`, uses public API only.

| Check | What it looks for |
| --- | --- |
| `fileArtifacts` | Files installed by rootful and rootless jailbreaks, their package managers and hooking frameworks |
| `symbolicLinks` | Symbolic links at paths such as `/var/jb` that are absent or real directories on a stock system |
| `sandboxEscape` | Being able to create a file outside the app's container |
| `restrictedDirectories` | Being able to list directories the sandbox denies, and roothide's `.jbroot-*` directories |
| `loadedImages` | Substrate, Substitute, libhooker, ElleKit, Frida and known bypass tweaks loaded into the process, plus any library loaded from outside the system and the app bundle |
| `environmentVariables` | Variables set by jailbreaks, and foreign libraries in `DYLD_INSERT_LIBRARIES` |
| `hookIntegrity` | System functions and Objective-C methods the other checks use being redirected to foreign code |
| `urlSchemes` | Installed apps that handle `cydia://`, `sileo://`, `zbra://` or `filza://` |

## Hardening product

`JailbreakDetectorHardening` is a separate, opt-in product with checks that are harder to bypass.

| Check | What it does |
| --- | --- |
| `directSyscalls` | Repeats the file and symbolic link lookups with system calls issued straight to the kernel, and reports paths that libc hides |
| `functionPrologues` | Reads the first instructions of libc functions to find inline hooks |
| `fork` | Tries to fork the process, which the sandbox denies on a stock system |
| `loopbackPorts` | Connects to local ports 22, 44 and 27042, used by SSH servers and Frida |

None of these use private API, but they are the kind of behaviour App Review may question. That is why they live in a separate product: an app that does not link it does not ship the code. Decide with your own review history in mind.

```swift
.product(name: "JailbreakDetectorHardening", package: "Swift-Jailbreak-Detector"),
```

```swift
import JailbreakDetector
import JailbreakDetectorHardening

let report = JailbreakDetector.evaluate(.hardened)
```

The loopback port check can block the calling thread for up to half a second, so call it off the main thread.

## Simulator and Mac

No checks run in the Simulator, in Mac Catalyst, or when an iOS app runs on an Apple silicon Mac, because a Mac's file system looks like a jailbreak. The report says where it ran in `report.environment` and has a `clean` verdict. If your app should not run on a Mac at all, treat `.mac` accordingly.

## Privacy

The package collects no data and makes no network requests other than the local port connections in the hardening product. It ships a privacy manifest and uses no required-reason API.

## Limitations

- **Detection on the device can be bypassed.** Whoever controls a jailbroken device can hook or patch any check, and the indicator lists in this repository are public. Treat the report as one risk signal.
- **Pair it with server-side attestation.** For a banking app, use [App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity) so that your backend can verify the app and device independently of anything the app says about itself.
- **It detects jailbreaks, not every attack.** Debugger attachment, re-signed or modified builds and screen capture are out of scope.
- **Version 0.1.0 has not been run on real devices.** It is tested in the iOS Simulator and against scripted clean, rootful, rootless, roothide and hooked systems. Before relying on it in production, run it on a range of stock devices to confirm there are no false positives, and on a jailbroken device to confirm detection.

## License

MIT. See [LICENSE](LICENSE).

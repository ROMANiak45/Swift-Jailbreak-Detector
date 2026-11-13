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
    .package(url: "https://github.com/ROMANiak45/Swift-Jailbreak-Detector.git", from: "0.2.0"),
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

Inside an `async` function Swift always picks the asynchronous overload, so the call needs `await` there, even with a configuration such as `.hardened`.

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

To add a check of your own, conform a type to `JailbreakCheck` and append it to `configuration.additionalChecks`. Its `run(_:)` method receives a `JailbreakCheckContext` with the configured indicators.

## Private and remote indicators

The built-in paths, library names and schemes are public, so a bypass tweak can be written against them. `configuration.indicators` lets you change what the checks look for.

### Private indicators

Keep extra indicators in your own private repository and merge them with the built-in set. Merging only ever adds: a path in both sets keeps the stronger confidence.

```swift
let privateIndicators = IndicatorSet(
    files: [.init(path: "/var/some-new-jailbreak", confidence: .definitive)],
    imageNames: ["somebypass.dylib"]
)
configuration.indicators = IndicatorSet.builtIn.merging(privateIndicators)
```

Assigning a set without merging replaces the built-in one entirely, which is how you remove an indicator.

### Signed lists from your server

To cover a new jailbreak without an app release, deliver the indicators as JSON signed with a P-256 key. The app ships only the public key and rejects any list that is not signed with the matching private key, so whoever can tamper with the response still cannot empty the list.

The JSON has the same fields as `IndicatorSet`. Missing fields are empty, and `confidence` is `definitive` or `suspicious`:

```json
{
  "version": 12,
  "files": [{ "path": "/var/some-new-jailbreak", "confidence": "definitive" }],
  "symbolicLinks": [],
  "environmentVariables": ["SOME_NEW_JB"],
  "imageFragments": ["somehook"],
  "imageNames": ["somebypass.dylib"],
  "urlSchemes": [],
  "restrictedDirectories": []
}
```

Create the key pair once, keep `key.pem` on the server side, and sign each list:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl ec -in key.pem -pubout -out public.pem
openssl dgst -sha256 -sign key.pem -out indicators.sig indicators.json
```

In the app, fetch the JSON and the signature with your own URL session, then verify them. The package itself makes no network requests and stores nothing.

```swift
import CryptoKit

let publicKey = try P256.Signing.PublicKey(pemRepresentation: publicKeyPEM)
let delivered = try IndicatorSet.verified(
    payload: jsonData,
    signature: signatureData,
    publicKey: publicKey,
    minimumVersion: lastAcceptedVersion
)
lastAcceptedVersion = delivered.version
configuration.indicators = IndicatorSet.builtIn.merging(delivered)
```

`minimumVersion` rejects a list older than the newest one the app has accepted, so an attacker cannot replay an old, correctly signed list. Store `lastAcceptedVersion` wherever you keep similar app state. Verification throws `IndicatorSet.VerificationError` when the signature is malformed or wrong, the payload is not an indicator set, or the version is too old.

## Binding a report to your server

A report the app sends to your server could be one captured earlier on a clean device. To rule that out, have the server issue a single-use nonce, pass it to the evaluation, and sign the result with [App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity):

```swift
import DeviceCheck

let report = await JailbreakDetector.evaluate(configuration, nonce: serverNonce)
let payload = try report.attestationPayload()
let assertion = try await DCAppAttestService.shared.generateAssertion(keyID, clientDataHash: payload.digest)
// Send payload.data and assertion to the server.
```

`attestationPayload()` throws `JailbreakReport.AttestationError.missingNonce` if the evaluation had no nonce. The report also records `indicatorVersion`, the version of the set the checks used.

On the server:

1. Verify the assertion against the App Attest key registered for this device, using the SHA-256 of the `data` bytes exactly as received as the client data hash.
2. Decode the JSON and check that `nonce` is the one you issued for this session and has not been used before.
3. Check that `indicatorVersion` is the current version of your signed list.
4. Score `findings` on the server, rather than trusting the app's `verdict` alone.

App Attest proves the request came from your genuine app on genuine Apple hardware. It does not detect a jailbreak, and a tweak injected into your app can still alter the report before it is signed.

## Checks

The core product, `JailbreakDetector`, uses public API only.

| Check | What it looks for |
| --- | --- |
| `fileArtifacts` | Files installed by rootful and rootless jailbreaks, their package managers and hooking frameworks |
| `symbolicLinks` | Symbolic links at paths such as `/var/jb` that are absent or real directories on a stock system |
| `sandboxEscape` | Being able to create a file in `/`, `/private/`, `/private/var/`, `/private/var/mobile/`, `/private/var/root/`, `/Applications/`, `/Library/`, `/usr/` or `/bin/`. The probe file is empty, uniquely named and removed at once |
| `restrictedDirectories` | Being able to list system directories the sandbox denies, such as `/private/var/root`, `/private/var/mobile`, `/private/var/db` and `/private/var/log`, and roothide's `.jbroot-*` directories |
| `loadedImages` | Substrate, Substitute, libhooker, ElleKit, Frida and known bypass tweaks loaded into the process, plus any library loaded from outside the system and the app bundle |
| `environmentVariables` | Variables set by jailbreaks, and foreign libraries in `DYLD_INSERT_LIBRARIES` |
| `hookIntegrity` | System functions and Objective-C methods the other checks use being redirected to foreign code |
| `urlSchemes` | Installed apps that handle `cydia://`, `sileo://`, `zbra://` or `filza://` |

### System folder access

Writing outside the container is a definitive finding, because the sandbox denies it on every stock device. Listing a restricted directory is only suspicious: stock iOS lets apps read some system locations, and which ones varies between iOS versions. For the same reason the package does not try to list `/` itself, and it never probes folders holding personal data such as messages, contacts or photos.

The restricted directories are part of `IndicatorSet`, so a directory that turns out to be readable on a new iOS version can be removed through your signed list without an app release. The list has not yet been confirmed on physical stock devices across iOS 15 to 27; until it is, treat these findings as a risk signal rather than a reason to block.

## Hardening product

`JailbreakDetectorHardening` is a separate, opt-in product with checks that are harder to bypass.

| Check | What it does |
| --- | --- |
| `directSyscalls` | Repeats the file, symbolic link and restricted directory lookups with system calls issued straight to the kernel, and reports anything libc or Foundation hides as definitive |
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

The package collects no data, stores nothing, and makes no network requests other than the local port connections in the hardening product. Fetching a signed indicator list is up to the app. It ships a privacy manifest and uses no required-reason API.

## Limitations

- **Detection on the device can still be bypassed.** Private and signed indicator lists mean a generic bypass tweak built from this repository no longer knows everything the app looks for, and a nonce stops a captured report from being replayed. An attacker who instruments your running app can still log the paths it checks, and a hook inside the genuine app can forge a clean report with a fresh nonce before App Attest signs it. Treat the report as one risk signal.
- **Keep the decision on the server.** Score the findings there, and keep transaction limits, step-up authentication and fraud monitoring in place, since they still work when the app lies.
- **It detects jailbreaks, not every attack.** Debugger attachment, re-signed or modified builds and screen capture are out of scope.
- **It has not been run on real devices.** It is tested in the iOS Simulator and against scripted clean, rootful, rootless, roothide and hooked systems. Before relying on it in production, run it on a range of stock devices to confirm there are no false positives, and on a jailbroken device to confirm detection.

## Migrating from 0.1.0

- `JailbreakCheck.run()` is now `run(_ context: JailbreakCheckContext)`. Custom checks gain the parameter and can read `context.indicators`.
- `JailbreakReport` has two new fields, `indicatorVersion` and `nonce`. A server that decodes reports should accept them.
- The sandbox escape and restricted directory checks probe more locations, so a device may report findings it did not report before.

## License

MIT. See [LICENSE](LICENSE).

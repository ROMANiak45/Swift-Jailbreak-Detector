//
//  DarwinSystemProbe.swift
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

import Darwin
import Foundation
import MachO
import ObjectiveC
import UIKit

/// Reads the real system through libc, dyld, the Objective-C runtime and Foundation.
///
/// It deliberately avoids `stat`, `lstat` and `statfs`, which would require required-reason declarations in
/// the privacy manifest.
struct DarwinSystemProbe: SystemProbe {
    var mainBundlePath: String { Bundle.main.bundlePath }

    func fileExists(atPath path: String) -> Bool {
        // Three independent routes, so that hiding a path means hooking all of them.
        if access(path, F_OK) == 0 { return true }
        if let stream = fopen(path, "r") {
            fclose(stream)
            return true
        }
        return FileManager.default.fileExists(atPath: path)
    }

    func symbolicLinkDestination(atPath path: String) -> String? {
        var buffer = [UInt8](repeating: 0, count: Int(PATH_MAX))
        let length = buffer.withUnsafeMutableBytes { bytes in
            readlink(path, bytes.baseAddress?.assumingMemoryBound(to: CChar.self), bytes.count)
        }
        guard length >= 0 else { return nil }
        return String(decoding: buffer[..<length], as: UTF8.self)
    }

    func directoryEntries(atPath path: String) -> [String]? {
        try? FileManager.default.contentsOfDirectory(atPath: path)
    }

    func canCreateFile(atPath path: String) -> Bool {
        let descriptor = creat(path, 0o600)
        guard descriptor >= 0 else { return false }
        close(descriptor)
        unlink(path)
        return true
    }

    func loadedImagePaths() -> [String] {
        (0..<_dyld_image_count()).compactMap { index in
            _dyld_get_image_name(index).map { String(cString: $0) }
        }
    }

    func environmentValue(named name: String) -> String? {
        getenv(name).map { String(cString: $0) }
    }

    func functionOrigins() -> [FunctionOrigin] {
        cFunctionAddresses().map { name, address in
            FunctionOrigin(name: name, imagePath: Self.imagePath(containing: address))
        } + methodOrigins()
    }

    /// The addresses this image calls for each libc and dyld function the probe uses.
    ///
    /// Taking the address in Swift reads the same binding the calls above go through, so a rebinding hook
    /// shows up here as an address inside the hook's image.
    private func cFunctionAddresses() -> [(String, UnsafeRawPointer?)] {
        let accessFunction: @convention(c) (UnsafePointer<CChar>?, Int32) -> Int32 = access
        let fopenFunction: @convention(c) (UnsafePointer<CChar>?, UnsafePointer<CChar>?)
            -> UnsafeMutablePointer<FILE>? = fopen
        let creatFunction: @convention(c) (UnsafePointer<CChar>?, mode_t) -> Int32 = creat
        let readlinkFunction: @convention(c) (UnsafePointer<CChar>?, UnsafeMutablePointer<CChar>?, Int)
            -> Int = readlink
        let getenvFunction: @convention(c) (UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>? = getenv
        let dladdrFunction: @convention(c) (UnsafeRawPointer?, UnsafeMutablePointer<Dl_info>?) -> Int32 = dladdr
        let imageCountFunction: @convention(c) () -> UInt32 = _dyld_image_count
        let imageNameFunction: @convention(c) (UInt32) -> UnsafePointer<CChar>? = _dyld_get_image_name

        return [
            ("access", unsafeBitCast(accessFunction, to: UnsafeRawPointer?.self)),
            ("fopen", unsafeBitCast(fopenFunction, to: UnsafeRawPointer?.self)),
            ("creat", unsafeBitCast(creatFunction, to: UnsafeRawPointer?.self)),
            ("readlink", unsafeBitCast(readlinkFunction, to: UnsafeRawPointer?.self)),
            ("getenv", unsafeBitCast(getenvFunction, to: UnsafeRawPointer?.self)),
            ("dladdr", unsafeBitCast(dladdrFunction, to: UnsafeRawPointer?.self)),
            ("_dyld_image_count", unsafeBitCast(imageCountFunction, to: UnsafeRawPointer?.self)),
            ("_dyld_get_image_name", unsafeBitCast(imageNameFunction, to: UnsafeRawPointer?.self)),
        ]
    }

    /// The current implementations of the Objective-C methods the checks use, which a swizzling hook replaces.
    private func methodOrigins() -> [FunctionOrigin] {
        let methods: [(AnyClass, String)] = [
            (FileManager.self, "fileExistsAtPath:"),
            (FileManager.self, "contentsOfDirectoryAtPath:error:"),
            (UIApplication.self, "canOpenURL:"),
        ]
        return methods.map { type, selector in
            let implementation = class_getMethodImplementation(type, NSSelectorFromString(selector))
            return FunctionOrigin(
                name: "-[\(NSStringFromClass(type)) \(selector)]",
                imagePath: Self.imagePath(containing: implementation.map { UnsafeRawPointer($0) })
            )
        }
    }

    private static func imagePath(containing address: UnsafeRawPointer?) -> String? {
        guard let address else { return nil }
        var info = Dl_info()
        guard dladdr(address, &info) != 0, let name = info.dli_fname else { return nil }
        return String(cString: name)
    }
}

/// Queries installed URL schemes through `UIApplication`.
@available(iOSApplicationExtension, unavailable)
struct ApplicationURLSchemeProbe: URLSchemeProbe {
    func declaredQuerySchemes() -> [String] {
        Bundle.main.object(forInfoDictionaryKey: "LSApplicationQueriesSchemes") as? [String] ?? []
    }

    @MainActor func canOpen(_ url: URL) -> Bool {
        UIApplication.shared.canOpenURL(url)
    }
}

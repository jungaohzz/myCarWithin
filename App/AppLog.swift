import Darwin
import Foundation
import UIKit

/// Crash evidence: the raw descriptor of the current log file, kept in sync by AppLog.open().
/// Signal handlers may only use async-signal-safe calls, so the messages are pre-encoded
/// with strdup before any handler can fire and written with write(2).
private var appLogCrashFD: Int32 = -1
private var appLogAbortPointer: UnsafeMutablePointer<CChar>?
private var appLogAbortLength = 0
private var appLogSegvPointer: UnsafeMutablePointer<CChar>?
private var appLogSegvLength = 0
private var appLogBusPointer: UnsafeMutablePointer<CChar>?
private var appLogBusLength = 0
private var appLogIllPointer: UnsafeMutablePointer<CChar>?
private var appLogIllLength = 0
private var appLogFpePointer: UnsafeMutablePointer<CChar>?
private var appLogFpeLength = 0
private var appLogTrapPointer: UnsafeMutablePointer<CChar>?
private var appLogTrapLength = 0

private func appLogStash(_ text: String) -> (UnsafeMutablePointer<CChar>?, Int) {
    guard let pointer = strdup(text) else { return (nil, 0) }
    return (pointer, strlen(pointer))
}

private func appLogSignalDispatcher(_ signalNumber: Int32) {
    var pointer: UnsafeMutablePointer<CChar>?
    var length = 0
    switch signalNumber {
    case SIGABRT: pointer = appLogAbortPointer; length = appLogAbortLength
    case SIGSEGV: pointer = appLogSegvPointer; length = appLogSegvLength
    case SIGBUS: pointer = appLogBusPointer; length = appLogBusLength
    case SIGILL: pointer = appLogIllPointer; length = appLogIllLength
    case SIGFPE: pointer = appLogFpePointer; length = appLogFpeLength
    case SIGTRAP: pointer = appLogTrapPointer; length = appLogTrapLength
    default: break
    }
    if let pointer, length > 0, appLogCrashFD >= 0 {
        _ = Darwin.write(appLogCrashFD, UnsafeRawPointer(pointer), length)
    }
    signal(signalNumber, SIG_DFL)
    raise(signalNumber)
}

private func appLogUncaughtExceptionHandler(_ exception: NSException) {
    AppLog.recordCrash("[崩溃] 未捕获异常 \(exception.name.rawValue)：\(exception.reason ?? "无原因")")
    AppLog.recordCrash("[崩溃] 调用栈：\n" + exception.callStackSymbols.joined(separator: "\n"))
}

/// One plain-text log file per launch under Documents/Logs. Every line is timestamped and
/// written immediately so a crash or a force-quit keeps the evidence. The files are listed,
/// deleted and shared from the 日志 settings page.
final class AppLog: @unchecked Sendable {
    static let shared = AppLog()

    /// Called from any thread; the line is appended in arrival order.
    static func record(_ message: String) {
        shared.write(message)
    }

    /// Crash path: the uncaught handler runs right before the process dies, so the line must
    /// reach the fd synchronously instead of riding the logging queue.
    static func recordCrash(_ message: String) {
        let stamp = shared.formatter.string(from: Date())
        guard appLogCrashFD >= 0, let data = "\(stamp)  \(message)\n".data(using: .utf8) else { return }
        data.withUnsafeBytes { _ = Darwin.write(appLogCrashFD, $0.baseAddress, $0.count) }
    }

    let directory: URL
    private let queue = DispatchQueue(label: "CarWithin.applog", qos: .utility)
    private let formatter: DateFormatter
    private let stampFormatter: DateFormatter
    private var handle: FileHandle?
    private var currentURL: URL
    private let maximumFiles = 30

    private init() {
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        directory = documents.appendingPathComponent("Logs", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let stamp = DateFormatter()
        stamp.dateFormat = "yyyyMMdd-HHmmss"
        stamp.locale = Locale(identifier: "en_US_POSIX")
        stampFormatter = stamp
        let line = DateFormatter()
        line.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS Z"
        line.locale = Locale(identifier: "en_US_POSIX")
        formatter = line
        currentURL = directory.appendingPathComponent("CarWithin-\(stamp.string(from: Date())).txt")
        prune()
        open()
        installCrashHandlers()
        write("App 启动 · \(AppLog.environmentSummary())")
        write("网络接口 · \(AppLog.interfaceSummary())")
        write("本机 CarPlay · \(AppLog.localCarPlaySupport.summary)")
        write("磁盘 · \(AppLog.storageSummary())")
    }

    /// 未捕获异常和致命信号（SIGABRT/SIGSEGV/SIGBUS/SIGILL/SIGFPE/SIGTRAP）也写进日志，
    /// 私有接口导致的崩溃因此有据可查，不需要再猜是哪一步掉的。
    private func installCrashHandlers() {
        (appLogAbortPointer, appLogAbortLength) = appLogStash("\n!!! 进程收到 SIGABRT（异常中止）!!!\n")
        (appLogSegvPointer, appLogSegvLength) = appLogStash("\n!!! 进程收到 SIGSEGV（访问非法内存）!!!\n")
        (appLogBusPointer, appLogBusLength) = appLogStash("\n!!! 进程收到 SIGBUS（总线错误）!!!\n")
        (appLogIllPointer, appLogIllLength) = appLogStash("\n!!! 进程收到 SIGILL（非法指令）!!!\n")
        (appLogFpePointer, appLogFpeLength) = appLogStash("\n!!! 进程收到 SIGFPE（算术异常）!!!\n")
        (appLogTrapPointer, appLogTrapLength) = appLogStash("\n!!! 进程收到 SIGTRAP（Swift 运行时陷阱）!!!\n")
        for number in [SIGABRT, SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP] {
            signal(number, appLogSignalDispatcher)
        }
        NSSetUncaughtExceptionHandler(appLogUncaughtExceptionHandler)
    }

    /// 本机 CarPlay（自建 iAP2 配件端点）从 iOS 16 起可用；参考项目 CarWithin 明确要求
    /// iOS/iPadOS 16.0+，且其发布包最低 iOS 16.4。iOS 15 能完成 iAP2 握手，但 CarPlay
    /// 守护进程不会回连，因此这里把系统版本写进日志和超时提示。
    static var localCarPlaySupport: (supported: Bool, summary: String) {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        let text = "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
        if version.majorVersion >= 16 {
            return (true, "iOS \(text) 满足 iOS 16.0+ 要求")
        }
        return (false, "警告：当前 iOS \(text)，本机 CarPlay 需要 iOS 16.0+（参考项目明确不支持 iOS 15），CarPlay 会话不会启动")
    }

    static func storageSummary() -> String {
        let values = try? FileManager.default.attributesOfFileSystem(forPath: NSHomeDirectory())
        let free = (values?[.systemFreeSize] as? NSNumber)?.int64Value ?? 0
        let total = (values?[.systemSize] as? NSNumber)?.int64Value ?? 0
        let process = ProcessInfo.processInfo
        return "磁盘可用 \(free / 1_048_576) MiB / 共 \(total / 1_048_576) MiB，设备内存 \(process.physicalMemory / 1_048_576) MiB，低电量模式 \(process.isLowPowerModeEnabled ? 1 : 0)，热状态 \(process.thermalState.rawValue)"
    }

    var currentFile: URL { queue.sync { currentURL } }

    /// Newest first.
    func files() -> [URL] {
        queue.sync {
            ((try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil))
                ?? [])
                .filter { $0.pathExtension == "txt" }
                .sorted { $0.lastPathComponent > $1.lastPathComponent }
        }
    }

    /// Deletes every file and starts a fresh one so sharing keeps working afterwards.
    func deleteAll() {
        queue.sync {
            try? handle?.close(); handle = nil; appLogCrashFD = -1
            let names = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
            names.forEach { try? FileManager.default.removeItem(at: $0) }
            currentURL = directory.appendingPathComponent("CarWithin-\(stampFormatter.string(from: Date())).txt")
            open()
            write("已清空此前的日志")
        }
    }

    func delete(_ url: URL) {
        queue.sync {
            if url == currentURL {
                try? handle?.close(); handle = nil; appLogCrashFD = -1
                try? FileManager.default.removeItem(at: url)
                open()
                return
            }
            try? FileManager.default.removeItem(at: url)
        }
    }

    private func open() {
        _ = FileManager.default.createFile(atPath: currentURL.path, contents: nil)
        handle = try? FileHandle(forWritingTo: currentURL)
        appLogCrashFD = handle?.fileDescriptor ?? -1
    }

    private func prune() {
        let existing = ((try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? [])
            .filter { $0.pathExtension == "txt" }
            .sorted { $0.lastPathComponent > $1.lastPathComponent }
        for url in existing.dropFirst(maximumFiles - 1) { try? FileManager.default.removeItem(at: url) }
    }

    private func write(_ message: String) {
        let text = message.trimmingCharacters(in: .newlines)
        guard !text.isEmpty else { return }
        queue.async { [self] in
            guard let handle else { return }
            let stamp = formatter.string(from: Date())
            var entry = "\(stamp)  \(text)\n"
            for part in text.split(separator: "\n").dropFirst() { entry += "\(stamp)  \(part)\n" }
            if let data = entry.data(using: .utf8) { try? handle.write(contentsOf: data) }
        }
        NSLog("[CarWithin] %@", text)
    }

    static func environmentSummary() -> String {
        let info = Bundle.main.infoDictionary ?? [:]
        let version = info["CFBundleShortVersionString"] as? String ?? "?"
        let build = info["CFBundleVersion"] as? String ?? "?"
        var system = utsname(); uname(&system)
        let model = withUnsafeBytes(of: &system.machine) {
            String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self)
        }
        return "CarWithin \(version) (\(build)) · \(model) · iOS \(UIDevice.current.systemVersion) · \(TimeZone.current.identifier)"
    }

    /// Wi-Fi and cellular addresses with masks, so a wrong interface is visible in the log.
    static func interfaceSummary() -> String {
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0 else { return "无法读取网络接口" }
        defer { freeifaddrs(first) }
        var entries: [String] = []
        var current = first
        while let entry = current {
            defer { current = entry.pointee.ifa_next }
            guard let address = entry.pointee.ifa_addr, address.pointee.sa_family == UInt8(AF_INET),
                  entry.pointee.ifa_flags & UInt32(IFF_UP) != 0,
                  entry.pointee.ifa_flags & UInt32(IFF_LOOPBACK) == 0 else { continue }
            let name = String(cString: entry.pointee.ifa_name)
            let ip = text(address)
            let mask = entry.pointee.ifa_netmask.map { text($0) } ?? "?"
            entries.append("\(name) \(ip)/\(mask)")
        }
        return entries.isEmpty ? "没有 IPv4 网络接口" : entries.joined(separator: "，")
    }

    private static func text(_ address: UnsafePointer<sockaddr>) -> String {
        address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
            let raw = UInt32(bigEndian: $0.pointee.sin_addr.s_addr)
            return "\(raw >> 24).\((raw >> 16) & 255).\((raw >> 8) & 255).\(raw & 255)"
        }
    }
}

/// 按键日志：独立于文本日志的文件，只收 HID/按键证据。来源有两个：系统统一日志里与
/// HID、键盘、旋钮、方向盘等相关的行（车机按键会经过 carplayd/BackBoard），以及 App
/// 自己发出的 HID 报告（作为格式参照）。每次收集换一个新文件，便于单独导出分析。
final class ButtonLog: @unchecked Sendable {
    static let shared = ButtonLog()

    let directory: URL
    private let queue = DispatchQueue(label: "CarWithin.buttonlog", qos: .utility)
    private let formatter: DateFormatter
    private let stampFormatter: DateFormatter
    private var handle: FileHandle?
    private var currentURL: URL
    private let maximumFiles = 20

    private init() {
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        directory = documents.appendingPathComponent("Logs/ButtonLogs", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let stamp = DateFormatter()
        stamp.dateFormat = "yyyyMMdd-HHmmss"
        stamp.locale = Locale(identifier: "en_US_POSIX")
        stampFormatter = stamp
        let line = DateFormatter()
        line.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS Z"
        line.locale = Locale(identifier: "en_US_POSIX")
        formatter = line
        currentURL = directory.appendingPathComponent("Keys-\(stamp.string(from: Date())).txt")
        prune()
        open()
    }

    static func record(_ message: String) { shared.write(message) }

    var currentFile: URL { queue.sync { currentURL } }

    /// 每次收集换一个新文件，导出的就是这一次按键测试的内容。
    func startSession() {
        queue.sync {
            try? handle?.close(); handle = nil
            currentURL = directory.appendingPathComponent("Keys-\(stampFormatter.string(from: Date())).txt")
            open()
            prune()
        }
    }

    /// Newest first.
    func files() -> [URL] {
        queue.sync {
            ((try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? [])
                .filter { $0.pathExtension == "txt" }
                .sorted { $0.lastPathComponent > $1.lastPathComponent }
        }
    }

    func deleteAll() {
        queue.sync {
            try? handle?.close(); handle = nil
            let names = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
            names.forEach { try? FileManager.default.removeItem(at: $0) }
            currentURL = directory.appendingPathComponent("Keys-\(stampFormatter.string(from: Date())).txt")
            open()
        }
    }

    func delete(_ url: URL) {
        queue.sync {
            if url == currentURL {
                try? handle?.close(); handle = nil
                try? FileManager.default.removeItem(at: url)
                open()
                return
            }
            try? FileManager.default.removeItem(at: url)
        }
    }

    private func open() {
        _ = FileManager.default.createFile(atPath: currentURL.path, contents: nil)
        handle = try? FileHandle(forWritingTo: currentURL)
    }

    private func prune() {
        let existing = ((try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? [])
            .filter { $0.pathExtension == "txt" }
            .sorted { $0.lastPathComponent > $1.lastPathComponent }
        for url in existing.dropFirst(maximumFiles - 1) { try? FileManager.default.removeItem(at: url) }
    }

    private func write(_ message: String) {
        let text = message.trimmingCharacters(in: .newlines)
        guard !text.isEmpty else { return }
        queue.async { [self] in
            guard let handle else { return }
            let stamp = formatter.string(from: Date())
            var entry = "\(stamp)  \(text)\n"
            for part in text.split(separator: "\n").dropFirst() { entry += "\(stamp)  \(part)\n" }
            if let data = entry.data(using: .utf8) { try? handle.write(contentsOf: data) }
        }
        NSLog("[CarWithin按键] %@", text)
    }
}

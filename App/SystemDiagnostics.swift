import Foundation
import Darwin

/// Evidence from outside the app: iOS keeps crash reports, daemon preferences and a unified
/// log for CarPlay. A TrollStore build may be able to read them; when the sandbox refuses,
/// the failed attempt is logged too, so one casting run still shows what was tried.
/// The CarPlay daemon never talks back over iAP2, so these are the only channels that can
/// reveal whether it crashed, gave up, or never tried.
final class SystemDiagnostics: @unchecked Sendable {
    static let shared = SystemDiagnostics()

    private let queue = DispatchQueue(label: "CarWithin.systemdiagnostics", qos: .utility)
    private var lastScan = Date.distantPast

    func scan(reason: String) {
        queue.async { [self] in
            let now = Date()
            guard now.timeIntervalSince(lastScan) >= 60 else {
                AppLog.record("系统诊断扫描跳过（距上次不足 60 秒）· \(reason)")
                return
            }
            lastScan = now
            AppLog.record("系统诊断扫描开始 · \(reason)")
            scanLogDirectories()
            scanPreferences()
            scanUnifiedLog()
            AppLog.record("系统诊断扫描结束")
        }
    }

    // MARK: 崩溃报告

    private func scanLogDirectories() {
        let directories = [
            "/var/mobile/Library/Logs/DiagnosticReports",
            "/var/mobile/Library/Logs/CrashReporter",
            "/var/mobile/Library/Logs"
        ]
        for path in directories {
            let items: [String]
            do {
                items = try FileManager.default.contentsOfDirectory(atPath: path)
            } catch {
                AppLog.record("系统诊断 · 目录 \(path) 不可读：\(error.localizedDescription)")
                continue
            }
            AppLog.record("系统诊断 · 目录 \(path) 共 \(items.count) 项")
            let sorted = items.compactMap { name -> (String, Date, URL)? in
                let url = URL(fileURLWithPath: path).appendingPathComponent(name)
                guard let date = (try? url.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate
                else { return nil }
                return (name, date, url)
            }.sorted { $0.1 > $1.1 }
            let recent = sorted.filter { Date().timeIntervalSince($0.1) < 1800 }
            if !recent.isEmpty {
                AppLog.record("系统诊断 · \(path) 最近 30 分钟 \(recent.count) 项：\(recent.prefix(20).map { "\($0.0)（\(Self.stamp($0.1))）" }.joined(separator: "，"))")
            }
            for (name, date, url) in recent {
                let lower = name.lowercased()
                guard lower.contains("carplay") || lower.contains("accessory") || lower.contains("springboard")
                        || lower.contains("backboard") || lower.contains("acc"), name.hasSuffix(".ips") || name.hasSuffix(".crash") || name.hasSuffix(".log")
                else { continue }
                AppLog.record("系统诊断 · 匹配崩溃/诊断文件 \(name)（\(Self.stamp(date))）")
                logHead(of: url, lines: 20)
            }
        }
    }

    private func logHead(of url: URL, lines: Int) {
        guard let data = try? Data(contentsOf: url, options: .mappedIfSafe) else {
            AppLog.record("系统诊断 · \(url.lastPathComponent) 读取失败（大小 \(((try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize) ?? -1)）")
            return
        }
        let head = String(decoding: data.prefix(16384), as: UTF8.self)
        for line in head.split(separator: "\n").prefix(lines) {
            AppLog.record("系统诊断 · \(url.lastPathComponent)｜\(line.prefix(240))")
        }
    }

    // MARK: CarPlay 偏好设置

    private func scanPreferences() {
        for domain in ["com.apple.carplayd", "com.apple.carplay", "com.apple.CoreAccessories"] {
            let values = CFPreferencesCopyMultiple(nil, domain as CFString,
                                                   kCFPreferencesCurrentUser, kCFPreferencesAnyHost) as? [String: Any]
            guard let values else {
                AppLog.record("系统诊断 · 偏好域 \(domain) 读取不到（沙盒或不存在）")
                continue
            }
            let names = values.keys.sorted()
            AppLog.record("系统诊断 · 偏好域 \(domain) 共 \(names.count) 项：\(names.prefix(30).joined(separator: "，"))")
            for name in names.prefix(20) {
                let value = values[name]
                let description: String
                switch value {
                case let number as NSNumber: description = number.stringValue
                case let string as String: description = String(string.prefix(120))
                case let date as Date: description = Self.stamp(date)
                case .some(let other): description = String(describing: type(of: other))
                case .none: description = "nil"
                }
                AppLog.record("系统诊断 · \(domain)｜\(name) = \(description)")
            }
        }
    }

    // MARK: 统一日志

    private func scanUnifiedLog() {
        let path = "/usr/bin/log"
        guard FileManager.default.isExecutableFile(atPath: path) else {
            AppLog.record("系统诊断 · \(path) 不存在，无法读取统一日志（此设备不提供 log 命令）")
            return
        }
        // Foundation.Process 不存在于 iOS SDK，只能用 popen 走 /bin/sh。
        let predicate = #"process CONTAINS[c] "carplay" OR senderImagePath CONTAINS[c] "CarPlay" OR subsystem CONTAINS[c] "carplay""#
        let command = "\(path) show --last 5m --style compact --predicate '\(predicate)' 2>&1"
        guard let pipe = popen(command, "r") else {
            AppLog.record("系统诊断 · popen 启动 log show 失败（errno \(errno)）")
            return
        }
        var buffer = [CChar](repeating: 0, count: 4096)
        var lines = 0
        var bytes = 0
        var sawContent = false
        let started = Date()
        while fgets(&buffer, Int32(buffer.count), pipe) != nil {
            bytes += strlen(buffer)
            let line = String(cString: buffer).trimmingCharacters(in: .newlines)
            if !line.isEmpty {
                sawContent = true
                if lines < 120 {
                    AppLog.record("系统日志｜\(line.prefix(260))")
                    lines += 1
                }
            }
            if Date().timeIntervalSince(started) > 15 { break }
        }
        let status = pclose(pipe)
        let elapsed = String(format: "%.1f", Date().timeIntervalSince(started))
        AppLog.record("系统诊断 · log show 结束：日志 \(lines) 行、\(bytes) 字节、退出码 \(status)、耗时 \(elapsed) 秒\(sawContent ? "" : "（无 CarPlay 相关输出，说明这 5 分钟里系统守护进程没有留下记录）")")
    }

    private static func stamp(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "MM-dd HH:mm:ss"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter.string(from: date)
    }
}

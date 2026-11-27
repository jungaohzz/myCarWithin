import Darwin
import Foundation
import OSLog

/// Evidence from outside the app: iOS keeps crash reports, daemon preferences, a process table,
/// launchd state and a unified log for CarPlay. The build is TrollStore-signed with
/// no-sandbox, so these reads can actually work; every failed attempt is logged with its
/// reason, so one casting run still shows which channels the device refused.
/// The CarPlay daemon never talks back over iAP2, so this is the only place that can show
/// whether carplayd runs, crashed, was throttled, or tried to connect and was stopped.
final class SystemDiagnostics: @unchecked Sendable {
    static let shared = SystemDiagnostics()

    private let queue = DispatchQueue(label: "CarWithin.systemdiagnostics", qos: .utility)
    private let captureQueue = DispatchQueue(label: "CarWithin.systemdiagnostics.capture", qos: .utility)
    private var lastScan = Date.distantPast

    // MARK: 总扫描

    func scan(reason: String) {
        queue.async { [self] in
            let now = Date()
            guard now.timeIntervalSince(lastScan) >= 60 else {
                AppLog.record("系统诊断扫描跳过（距上次不足 60 秒）· \(reason)")
                return
            }
            lastScan = now
            AppLog.record("系统诊断扫描开始 · \(reason)")
            scanPaths()
            scanLogDirectories()
            scanPreferences()
            scanDaemons()
            scanCarplayBinary()
            scanUnifiedLog()
            AppLog.record("系统诊断扫描结束")
        }
    }

    // MARK: 通用命令读取（非阻塞，带时限）

    /// iOS SDK 对 Swift 屏蔽了 Foundation.Process 和 popen/pclose，posix_spawn 是拉起
    /// /bin/sh 的唯一通道。读取设成非阻塞，这样即使被探测的命令不输出，
    /// 也不会卡死扫描队列。waitpid 阻塞回收与 pclose 语义一致：命令自带退出机制。
    private func run(command: String, maxSeconds: TimeInterval, maxLines: Int, tag: String,
                     scope: String = "系统诊断",
                     record: (String) -> Void = { AppLog.record($0) }) {
        var fds = [Int32](repeating: 0, count: 2)
        guard pipe(&fds) == 0 else {
            record("\(scope) · \(tag)：pipe 失败（errno \(errno)）")
            return
        }
        let readFd = fds[0]
        let writeFd = fds[1]

        // Darwin 上 posix_spawn_file_actions_t 是不透明指针 typedef，只能由 init 填充。
        var fileActions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&fileActions)
        posix_spawn_file_actions_addclose(&fileActions, readFd)
        posix_spawn_file_actions_adddup2(&fileActions, writeFd, STDOUT_FILENO)
        posix_spawn_file_actions_adddup2(&fileActions, writeFd, STDERR_FILENO)
        posix_spawn_file_actions_addclose(&fileActions, writeFd)

        guard let shPath = strdup("/bin/sh"), let dashC = strdup("-c"), let commandC = strdup(command) else {
            posix_spawn_file_actions_destroy(&fileActions)
            close(readFd)
            close(writeFd)
            record("\(scope) · \(tag)：spawn 参数复制失败（内存不足）")
            return
        }
        defer { free(shPath); free(dashC); free(commandC) }
        var argv: [UnsafeMutablePointer<CChar>?] = [shPath, dashC, commandC, nil]

        var pid: pid_t = 0
        let spawnResult = posix_spawn(&pid, shPath, &fileActions, nil, &argv, environ)
        posix_spawn_file_actions_destroy(&fileActions)
        close(writeFd)
        guard spawnResult == 0 else {
            close(readFd)
            record("\(scope) · \(tag)：posix_spawn 失败（错误码 \(spawnResult)，进程启动被拒绝）")
            return
        }

        let flags = fcntl(readFd, F_GETFL)
        if flags >= 0 { _ = fcntl(readFd, F_SETFL, flags | O_NONBLOCK) }
        var pending: [UInt8] = []
        var lines = 0
        var totalBytes = 0
        let deadline = Date().addingTimeInterval(maxSeconds)
        while Date() < deadline {
            var chunk = [UInt8](repeating: 0, count: 4096)
            let count = read(readFd, &chunk, chunk.count)
            if count > 0 {
                pending.append(contentsOf: chunk[0..<count])
            } else if count == 0 {
                if pending.isEmpty { break }
                pending.append(0x0A) // fgets 会补出无换行的末行，EOF 时同样冲刷
            } else if errno == EAGAIN || errno == EINTR {
                usleep(100_000)
            } else {
                break
            }
            while let newline = pending.firstIndex(of: 0x0A) {
                let text = String(decoding: pending[0..<newline], as: UTF8.self)
                    .trimmingCharacters(in: .newlines)
                pending.removeSubrange(0...newline)
                guard !text.isEmpty else { continue }
                totalBytes += text.utf8.count
                if lines < maxLines {
                    record("\(tag)｜\(text.prefix(300))")
                    lines += 1
                }
            }
            if count == 0 { break }
        }
        close(readFd)
        var status: Int32 = 0
        _ = waitpid(pid, &status, 0)
        record("\(scope) · \(tag) 结束：输出 \(lines) 行 / \(totalBytes) 字节")
    }

    // MARK: 路径与崩溃报告

    private func scanPaths() {
        let paths = ["/usr/libexec/carplayd", "/usr/bin/log", "/bin/launchctl", "/usr/bin/ps",
                     "/usr/sbin/tcpdump", "/usr/bin/strings", "/usr/bin/grep", "/bin/sh",
                     "/var/mobile/Library/Logs/DiagnosticReports", "/var/mobile/Library/Logs/CrashReporter"]
        let present = paths.map { "\($0)=\(FileManager.default.fileExists(atPath: $0) ? "有" : "无")" }
        AppLog.record("系统诊断 · 关键路径：\(present.joined(separator: "，"))")
    }

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
        for file in ["/var/mobile/Library/Preferences/com.apple.carplay.plist",
                     "/var/mobile/Library/Preferences/com.apple.carplayd.plist",
                     "/var/mobile/Library/Preferences/com.apple.CoreAccessories.plist"] {
            let size = (try? FileManager.default.attributesOfItem(atPath: file)[.size] as? Int) ?? nil
            AppLog.record("系统诊断 · 偏好文件 \(file) \(size.map { "\($0) 字节" } ?? "不存在或不可读")")
        }
    }

    // MARK: 守护进程（carplayd 是否运行 / 崩溃 / 被 launchd 节流）

    private func scanDaemons() {
        run(command: #"ps -axo pid,ppid,user,comm 2>&1 | grep -i -E "carplay|accessor|accd|backboard|airplay" | head -40"#,
            maxSeconds: 8, maxLines: 40, tag: "进程清单")
        run(command: #"launchctl list 2>&1 | grep -i -E "carplay|accessor|accd" | head -40"#,
            maxSeconds: 8, maxLines: 40, tag: "launchctl 列表")
        run(command: #"launchctl print system/com.apple.carplayd 2>&1 | head -60"#,
            maxSeconds: 8, maxLines: 60, tag: "carplayd 任务状态")
        run(command: #"launchctl print system/com.apple.accessoryd 2>&1 | head -40"#,
            maxSeconds: 8, maxLines: 40, tag: "accessoryd 任务状态")
    }

    // MARK: carplayd 二进制里的协议线索

    private func scanCarplayBinary() {
        run(command: #"grep -a -o -E ".{0,24}(rtsp|RTSP|7000|4301|StartSession|CarPlay).{0,24}" /usr/libexec/carplayd 2>&1 | head -120"#,
            maxSeconds: 15, maxLines: 120, tag: "carplayd 二进制")
    }

    // MARK: 统一日志（OSLogStore API 通道）

    /// posix_spawn 在 iOS 15.6 的 TrollStore 环境里拿不到 /bin/sh（ENOENT），命令行日志通道
    /// 整体失效。OSLogStore 是 iOS 15 的公开 API，进程内直接读统一日志，不经过任何外部
    /// 进程：system 域若被拒就退回本进程域，两种结果都写进日志作为证据。
    private func openUnifiedLogStore() -> OSLogStore? {
        do {
            let store = try OSLogStore(scope: .system)
            AppLog.record("OSLogStore · system 域已打开（进程内读统一日志，不依赖命令行工具）")
            return store
        } catch {
            AppLog.record("OSLogStore · system 域打开失败：\(error.localizedDescription)")
        }
        do {
            let store = try OSLogStore(scope: .currentProcessIdentifier)
            AppLog.record("OSLogStore · 退回本进程域（只能看到本进程，看不到 carplayd）")
            return store
        } catch {
            AppLog.record("OSLogStore · 本进程域也打开失败：\(error.localizedDescription)（统一日志 API 通道不可用）")
            return nil
        }
    }

    /// 每次扫描各自创建：scan 的 queue 与 streamLogs 的 captureQueue 会并发调用，
    /// DateFormatter 不是线程安全的，不能共享缓存实例。
    private func makeEntryStamp() -> DateFormatter {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter
    }

    private func formatUnifiedLine(_ entry: OSLogEntry, stamp: DateFormatter) -> String {
        let time = stamp.string(from: entry.date)
        if let log = entry as? OSLogEntryLog {
            return "\(time) [\(log.process)｜\(log.subsystem)/\(log.category)] \(log.composedMessage)"
        }
        return "\(time) \(String(describing: entry))"
    }

    /// 反向迭代（从新到旧）而不是正向：正向走到日志头部时迭代器可能等待新条目，
    /// 反向永远在历史里走，条数/时间窗先到即停，每次扫描都有界。
    /// 返回本轮收集到的条数；读取失败也记一行，失败本身是证据。
    @discardableResult
    private func sweepUnifiedLog(store: OSLogStore, predicate: NSPredicate, since: TimeInterval,
                                 maxEntries: Int, tag: String, record: (String) -> Void) -> Int {
        do {
            let windowStart = Date().addingTimeInterval(-since)
            let position = store.position(date: windowStart)
            let enumerator = try store.getEntries(with: .reverse, at: position, matching: predicate)
            let stamp = makeEntryStamp()
            var lines: [String] = []
            // OSLogEnumerator 的文档用法是 Sequence for-in；反向顺序走到窗口起点即停。
            for entry in enumerator {
                if entry.date < windowStart { break }
                guard lines.count < maxEntries else { break }
                lines.append(formatUnifiedLine(entry, stamp: stamp))
            }
            lines.reversed().forEach { record("\(tag)｜\($0)") }
            return lines.count
        } catch {
            record("\(tag)｜OSLogStore 读取失败：\(error.localizedDescription)")
            return 0
        }
    }

    /// 近似 log stream：每 2 秒做一次小窗口反向扫描，窗口内条数有限，永远不阻塞在
    /// 等待新条目上。每 10 秒记录一次轮询心跳，证明通道活着。
    private func pollUnifiedLog(store: OSLogStore, predicate: NSPredicate, seconds: Int,
                                tag: String, record: (String) -> Void) {
        let start = Date()
        var cursor = start
        var polls = 0
        while Date().timeIntervalSince(start) < TimeInterval(seconds) {
            Thread.sleep(forTimeInterval: 2)
            let now = Date()
            let window = max(1.0, now.timeIntervalSince(cursor))
            let count = sweepUnifiedLog(store: store, predicate: predicate, since: window,
                                        maxEntries: 150, tag: tag, record: record)
            cursor = now
            polls += 1
            if polls % 5 == 0 {
                record("\(tag)｜轮询心跳：已运行 \(Int(now.timeIntervalSince(start))) 秒，最近窗口 \(count) 条")
            }
        }
    }

    private static let carPlayPredicate = NSPredicate(
        format: "process CONTAINS[c] %@ OR process CONTAINS[c] %@ OR eventMessage CONTAINS[c] %@ OR subsystem CONTAINS[c] %@",
        "carplay", "accessor", "CarPlay", "carplay")

    private static let buttonPredicate = NSPredicate(
        format: "eventMessage CONTAINS[c] %@ OR eventMessage CONTAINS[c] %@ OR eventMessage CONTAINS[c] %@ OR eventMessage CONTAINS[c] %@ OR eventMessage CONTAINS[c] %@ OR eventMessage CONTAINS[c] %@ OR eventMessage CONTAINS[c] %@ OR eventMessage CONTAINS[c] %@ OR eventMessage CONTAINS[c] %@ OR eventMessage CONTAINS[c] %@ OR eventMessage CONTAINS[c] %@ OR subsystem CONTAINS[c] %@ OR process CONTAINS[c] %@",
        "IOHID", "HIDEvent", "hidReport", "keyboard", "button", "knob", "steering", "wheel",
        "mediaRemote", "iAP2", "accessory", "HID", "carplay")

    // MARK: 统一日志（已发生的）

    private func scanUnifiedLog() {
        if let store = openUnifiedLogStore() {
            sweepUnifiedLog(store: store, predicate: Self.carPlayPredicate, since: 300,
                            maxEntries: 120, tag: "系统日志(OSLogStore)") { AppLog.record($0) }
        } else {
            AppLog.record("系统日志 · OSLogStore 不可用，只剩命令行通道")
        }
        let predicate = #"process CONTAINS[c] "carplay" OR senderImagePath CONTAINS[c] "CarPlay" OR subsystem CONTAINS[c] "carplay""#
        run(command: "log show --last 5m --style compact --predicate '\(predicate)' 2>&1 | head -c 150000",
            maxSeconds: 20, maxLines: 120, tag: "系统日志(命令行)")
    }

    // MARK: 按键日志（投屏成功后按键取证）

    /// 车机物理按键若被 iOS 看到，会先经过 HID / BackBoard 再到 carplayd。
    /// 这里把统一日志里的按键相关行（HID、键盘、旋钮、方向盘、iAP2 配件）单独收集成
    /// 按键日志文件，并附上 App 自己发出的 HID 报告作为格式参照，便于分析按键如何回传。
    func collectButtonLogs(seconds: Int) {
        captureQueue.async { [self] in
            ButtonLog.shared.startSession()
            ButtonLog.shared.record("开始收集 · 约 \(seconds) 秒 · 请在收集期间按下车上的按键")
            if let store = openUnifiedLogStore() {
                ButtonLog.shared.record("按键日志通道 · OSLogStore（system 域）")
                sweepUnifiedLog(store: store, predicate: Self.buttonPredicate, since: 180,
                                maxEntries: 300, tag: "最近 3 分钟") { ButtonLog.record($0) }
                pollUnifiedLog(store: store, predicate: Self.buttonPredicate, seconds: seconds,
                               tag: "实时") { ButtonLog.record($0) }
            } else {
                ButtonLog.shared.record("按键日志通道 · OSLogStore 不可用，退回命令行（本机已证实 ENOENT）")
            }
            run(command: "log show --last 3m --style compact --predicate '\(Self.buttonShellPredicate)' 2>&1 | head -c 200000",
                maxSeconds: 25, maxLines: 300, tag: "最近 3 分钟(命令行)", scope: "按键日志", record: ButtonLog.record)
            ButtonLog.shared.record("收集结束")
        }
    }

    /// 仅供命令行通道使用的谓词字符串（与 buttonPredicate 同一筛选口径）。
    private static let buttonShellPredicate = #"(eventMessage CONTAINS[c] "IOHID" OR eventMessage CONTAINS[c] "HIDEvent" OR eventMessage CONTAINS[c] "hidReport" OR eventMessage CONTAINS[c] "keyboard" OR eventMessage CONTAINS[c] "button" OR eventMessage CONTAINS[c] "knob" OR eventMessage CONTAINS[c] "steering" OR eventMessage CONTAINS[c] "wheel" OR eventMessage CONTAINS[c] "mediaRemote" OR eventMessage CONTAINS[c] "iAP2" OR eventMessage CONTAINS[c] "accessory" OR subsystem CONTAINS[c] "HID" OR process CONTAINS[c] "carplay")"#

    // MARK: 实时日志流 / 网络抓包（投屏窗口内调用）

    /// 在投屏尝试期间实时记录 CarPlay 相关系统日志：daemon 的拒绝/崩溃会当场出现，
    /// 不用等它写进归档。OSLogStore 轮询通道优先；命令行通道作为对照保留。
    func streamLogs(seconds: Int) {
        captureQueue.async { [self] in
            AppLog.record("实时系统日志开始 · 约 \(seconds) 秒 · CarPlay 相关")
            if let store = openUnifiedLogStore() {
                sweepUnifiedLog(store: store, predicate: Self.carPlayPredicate, since: 60,
                                maxEntries: 200, tag: "实时系统日志(OSLogStore)") { AppLog.record($0) }
                pollUnifiedLog(store: store, predicate: Self.carPlayPredicate, seconds: seconds,
                               tag: "实时系统日志(OSLogStore)") { AppLog.record($0) }
            } else {
                AppLog.record("实时系统日志 · OSLogStore 不可用，退回命令行通道")
            }
            let predicate = #"process CONTAINS[c] "carplay" OR subsystem CONTAINS[c] "carplay" OR eventMessage CONTAINS[c] "CarPlay""#
            run(command: "log stream --style compact --predicate '\(predicate)' 2>&1 & TS=$!; sleep \(seconds); kill -TERM $TS 2>/dev/null",
                maxSeconds: Double(seconds) + 6, maxLines: 200, tag: "实时系统日志(命令行)")
        }
    }

    /// tcpdump 判断守护进程到底有没有向本机端口发起连接：抓到了就是自己这一侧的问题，
    /// 抓不到就是 carplayd 根本没尝试。没有 tcpdump 或没权限同样写入日志。
    func captureNetwork(interface: String, seconds: Int) {
        captureQueue.async { [self] in
            guard FileManager.default.fileExists(atPath: "/usr/sbin/tcpdump") else {
                AppLog.record("网络抓包跳过 · 本机没有 /usr/sbin/tcpdump（只能靠监听器和回连自测间接判断）")
                return
            }
            let filter = interface == "lo0" ? "tcp port 7000" : "tcp port 7000 or arp"
            AppLog.record("网络抓包开始 · \(interface) · 约 \(seconds) 秒 · 过滤 \(filter)")
            run(command: "tcpdump -n -i \(interface) -c 120 \"\(filter)\" 2>&1 & TP=$!; sleep \(seconds); kill -TERM $TP 2>/dev/null",
                maxSeconds: Double(seconds) + 6, maxLines: 120, tag: "抓包 \(interface)")
        }
    }

    // MARK: 自检：本机监听端口能否回连

    /// 证明 RTSP 端口在本机可回连；这样如果抓包也看不到 carplayd 的包，
    /// 就能确定是守护进程没尝试，而不是我们的监听器有问题。
    func selfConnectTest(port: UInt16) {
        captureQueue.async {
            let fd = socket(AF_INET, SOCK_STREAM, 0)
            guard fd >= 0 else {
                AppLog.record("回连自测 · socket 创建失败（errno \(errno)）")
                return
            }
            defer { close(fd) }
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = port.bigEndian
            address.sin_addr.s_addr = inet_addr("127.0.0.1")
            let result = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                    connect(fd, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            if result == 0 {
                AppLog.record("回连自测 · 成功连上 127.0.0.1:\(port)，设备监听端口可回连（carplayd 若尝试连接一定能到达）")
            } else {
                let code = errno
                AppLog.record("回连自测 · 连接 127.0.0.1:\(port) 失败 errno \(code)（\(String(cString: strerror(code)))）")
            }
        }
    }

    // MARK: 尝试让 launchd 启动 carplayd

    /// iOS 15 上 carplayd 可能根本没被拉起或被节流；kickstart 不需要重启、失败也能看原因。
    func kickstartCarPlayDaemon() {
        captureQueue.async { [self] in
            AppLog.record("carplayd 启动实验 · launchctl kickstart system/com.apple.carplayd")
            run(command: "launchctl kickstart system/com.apple.carplayd 2>&1; echo 退出码=$?",
                maxSeconds: 6, maxLines: 20, tag: "carplayd 启动实验")
        }
    }

    // MARK: XPC 直探（不依赖任何外部进程的守护进程证据通道）

    /// dlsym 动态解析 bootstrap_look_up/bootstrap_port，避免链接期依赖；TrollStore 平台
    /// 签名 + no-sandbox 下，launchd 命名空间里能查到什么、被拒绝到什么程度都是证据。
    private func bootstrapLookupResult(_ service: String) -> (kernReturn: Int32, port: UInt32)? {
        typealias Lookup = @convention(c) (UInt32, UnsafePointer<CChar>, UnsafeMutablePointer<UInt32>) -> Int32
        guard let lookupSymbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "bootstrap_look_up") else { return nil }
        guard let portSymbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "bootstrap_port") else { return nil }
        let lookup = unsafeBitCast(lookupSymbol, to: Lookup.self)
        let bootstrapPort = portSymbol.assumingMemoryBound(to: UInt32.self).pointee
        var port: UInt32 = 0
        let result = service.withCString { pointer in
            lookup(bootstrapPort, pointer, &port)
        }
        return (result, port)
    }

    private final class XPCProbeState {
        var reported = false
    }

    private func probeXPCConnection(_ name: String) {
        let state = XPCProbeState()
        let semaphore = DispatchSemaphore(value: 0)
        let connection = NSXPCConnection(machServiceName: name, options: [])
        let started = Date()
        connection.invalidationHandler = {
            let elapsed = Int(Date().timeIntervalSince(started) * 1000)
            if state.reported { return }
            state.reported = true
            AppLog.record("XPC 探测 · \(name) · 连接 \(elapsed) 毫秒后失效（服务拒绝或 App 无权限）")
            semaphore.signal()
        }
        connection.resume()
        if semaphore.wait(timeout: .now() + 2.5) == .timedOut, !state.reported {
            state.reported = true
            AppLog.record("XPC 探测 · \(name) · 2.5 秒未失效（连接存活：服务接受了 App，只是没有协议交互）")
        }
        connection.invalidate()
    }

    /// 逐个查找候选 Mach 服务名：命中（kern_return 0）就再做一次 NSXPCConnection 握手；
    /// 没命中时错误码本身说明该服务是否对 App 的命名空间可见。
    func probeCarPlayXPC() {
        captureQueue.async { [self] in
            let candidates = [
                "com.apple.carplayd",
                "com.apple.carplayd.app.service",
                "com.apple.carplayd.control",
                "com.apple.carplayd.control.service",
                "com.apple.carplayd.service",
                "com.apple.CarPlayServer",
                "com.apple.accessoryd",
                "com.apple.coreaccessoriesd",
                "com.apple.CoreAccessories.server",
                "com.apple.iapd",
            ]
            AppLog.record("XPC 探测开始 · bootstrap 查找 \(candidates.count) 个候选 Mach 服务名")
            for name in candidates {
                guard let (result, port) = bootstrapLookupResult(name) else {
                    AppLog.record("XPC 探测 · \(name)：bootstrap_look_up 符号解析失败")
                    continue
                }
                if result == 0 {
                    AppLog.record("XPC 探测 · \(name)：bootstrap 命中（端口 \(port)），做 NSXPCConnection 握手")
                    probeXPCConnection(name)
                } else {
                    AppLog.record("XPC 探测 · \(name)：bootstrap 错误码 \(result)（服务不在 App 可见的命名空间）")
                }
            }
            AppLog.record("XPC 探测结束")
        }
    }

    private static func stamp(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "MM-dd HH:mm:ss"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter.string(from: date)
    }
}

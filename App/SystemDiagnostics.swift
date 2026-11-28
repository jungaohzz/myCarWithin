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
    // Concurrent so the 60-second log stream no longer queues behind the 70-second
    // capture window; each job owns its fds/pids and AppLog serializes its own writes.
    private let captureQueue = DispatchQueue(label: "CarWithin.systemdiagnostics.capture",
                                             qos: .utility, attributes: .concurrent)
    private var lastScan = Date.distantPast

    // MARK: 本轮诊断进度（真实完成数 / 任务总数）

    private var roundTotal = 0
    private var roundDone = 0
    private var roundHandler: ((Int, Int) -> Void)?
    private let roundLock = NSLock()

    /// 登记本机 CarPlay 启动后这一轮的采集任务总数，每项收口时调 advanceRound。
    /// 进度来自真实回调而非时间估算：抓包/监听窗口结束、扫描跑完才计一项。
    func beginRound(total: Int, onProgress: @escaping (_ done: Int, _ total: Int) -> Void) {
        let count = max(total, 1)
        roundLock.lock()
        roundTotal = count
        roundDone = 0
        roundHandler = onProgress
        roundLock.unlock()
        onProgress(0, count)
    }

    func cancelRound() {
        roundLock.lock()
        roundTotal = 0
        roundDone = 0
        roundHandler = nil
        roundLock.unlock()
    }

    func advanceRound() {
        roundLock.lock()
        guard roundTotal > 0 else { roundLock.unlock(); return }
        roundDone += 1
        let done = min(roundDone, roundTotal)
        let total = roundTotal
        let handler = roundHandler
        if roundDone >= roundTotal { roundHandler = nil }
        roundLock.unlock()
        if let handler { DispatchQueue.main.async { handler(done, total) } }
    }

    // MARK: 总扫描

    func scan(reason: String, completion: (() -> Void)? = nil) {
        queue.async { [self] in
            defer { completion?() }
            let now = Date()
            guard now.timeIntervalSince(lastScan) >= 60 else {
                AppLog.record("系统诊断扫描跳过（距上次不足 60 秒）· \(reason)")
                return
            }
            lastScan = now
            AppLog.record("系统诊断扫描开始 · \(reason)")
            scanPaths()
            scanCarPlayComponents()
            scanAllMachServices()
            scanCoreAccessoriesClasses()
            scanProcessTable()
            scanRemoteProcessImages()
            scanSharedCache()
            scanSocketTable()
            scanKeychainGroups()
            scanPortOccupancy([7000, 49152, 53000, 3689, 8866, 8009, 47998, 4000, 4010, 61500, 47000])
            scanEntitlements()
            scanComponentDirectories()
            scanCarPlayPreferenceFiles()
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

    private var bonjourProbe: BonjourBrowseProbe?

    private func scanPaths() {
        let paths = ["/usr/libexec/carplayd", "/usr/sbin/carplayd", "/usr/libexec/carkitd",
                     "/usr/libexec/airplayd", "/usr/sbin/airplayd", "/usr/libexec/iapd",
                     "/usr/libexec/accessoryd", "/usr/libexec/backboardd",
                     "/usr/bin/log", "/bin/launchctl", "/usr/bin/ps",
                     "/usr/sbin/tcpdump", "/usr/bin/strings", "/usr/bin/grep", "/bin/sh",
                     "/System/Library/PrivateFrameworks/CarPlay.framework/CarPlay",
                     "/System/Library/PrivateFrameworks/CarPlayServices.framework/CarPlayServices",
                     "/System/Library/PrivateFrameworks/CarPlayUIServices.framework/CarPlayUIServices",
                     "/System/Library/PrivateFrameworks/CarKit.framework/CarKit",
                     "/System/Library/PrivateFrameworks/CarAccessoryFramework.framework/CarAccessoryFramework",
                     "/System/Library/LaunchDaemons/com.apple.carplayd.plist",
                     "/System/Library/LaunchDaemons/com.apple.carkitd.plist",
                     "/var/mobile/Library/Logs/CarPlay", "/var/mobile/Library/CarPlay", "/var/db/CarPlay",
                     "/var/mobile/Library/Logs/DiagnosticReports", "/var/mobile/Library/Logs/CrashReporter"]
        let present = paths.map { path -> String in
            guard FileManager.default.fileExists(atPath: path) else { return "\(path)=无" }
            let size = (try? FileManager.default.attributesOfItem(atPath: path))?[.size] as? Int
            return "\(path)=有(\(size.map { "\($0)B" } ?? "大小?"))"
        }
        AppLog.record("系统诊断 · 关键路径：\(present.joined(separator: "，"))")
    }

    // MARK: 系统里装了哪些 CarPlay 组件

    /// iOS 15.6 到底有没有等价进程：列出 launchd 任务清单和 CarPlay 相关框架，
    /// 再从候选二进制里搜 “4301 / StartSession / CarPlay” 字符串——谁实现了
    /// 0x4301 的消费逻辑，字符串就出现在谁里面。
    private func scanCarPlayComponents() {
        let daemons = ["/System/Library/LaunchDaemons", "/System/Library/LaunchAgents"]
        for directory in daemons {
            let items = (try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? []
            let matched = items.filter { name in
                let lower = name.lowercased()
                return lower.contains("carplay") || lower.contains("carkit") || lower.contains("airplay")
                    || lower.contains("accessory") || lower.contains("iap")
            }.sorted()
            AppLog.record("系统诊断 · \(directory) 共 \(items.count) 项，CarPlay/配件相关 \(matched.count) 项：\(matched.prefix(30).joined(separator: "，"))")
            for name in matched.prefix(10) {
                let path = directory + "/" + name
                guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                      let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any]
                else {
                    AppLog.record("系统诊断 · 任务 \(name) 不可解析")
                    continue
                }
                let services = (plist["MachServices"] as? [String: Any])?.keys.sorted() ?? []
                let program = (plist["Program"] as? String) ?? (plist["BundleProgram"] as? String) ?? "?"
                let runAtLoad = plist["RunAtLoad"] as? Bool ?? false
                AppLog.record("系统诊断 · 任务 \(name)：程序 \(program)，RunAtLoad=\(runAtLoad)，MachServices=\(services.joined(separator: "，" ) )")
                // launchctl disable 状态写在 /var/db/com.apple.xpc.launchd/disabled.*.plist。
                let disabledPath = "/var/db/com.apple.xpc.launchd/disabled.501.plist"
                if let disabled = try? Data(contentsOf: URL(fileURLWithPath: disabledPath)),
                   let dictionary = try? PropertyListSerialization.propertyList(from: disabled, options: [], format: nil) as? [String: Any] {
                    let label = name.replacingOccurrences(of: ".plist", with: "")
                    if let state = dictionary[label] { AppLog.record("系统诊断 · 禁用状态 \(label) = \(state)") }
                }
            }
        }
        let frameworks = (try? FileManager.default.contentsOfDirectory(atPath: "/System/Library/PrivateFrameworks")) ?? []
        let carFrameworks = frameworks.filter { $0.lowercased().contains("car") }.sorted()
        AppLog.record("系统诊断 · PrivateFrameworks 共 \(frameworks.count) 项，名字含 Car 的 \(carFrameworks.count) 项：\(carFrameworks.prefix(40).joined(separator: "，"))")
        scanBinarySignatures()
    }

    /// 任务文件名不匹配但服务名匹配的情况会被上一个函数漏掉——这里读取全部
    /// plist 的 MachServices 键再过滤，服务名才是 XPC 世界的真实名字。
    private func scanAllMachServices() {
        let directories = ["/System/Library/LaunchDaemons", "/System/Library/LaunchAgents",
                           "/Library/LaunchDaemons", "/Library/LaunchAgents"]
        var all: Set<String> = []
        var total = 0
        for directory in directories {
            let items = (try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? []
            for name in items where name.hasSuffix(".plist") {
                let path = directory + "/" + name
                guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                      let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any]
                else { continue }
                total += 1
                if let services = (plist["MachServices"] as? [String: Any])?.keys {
                    all.formUnion(services)
                }
            }
        }
        let matched = all.filter { name in
            let lower = name.lowercased()
            return lower.contains("carplay") || lower.contains("carplayd") || lower.contains("airplay")
                || lower.contains("accessor") || lower.contains("iap") || lower.contains("carp")
        }.sorted()
        AppLog.record("XPC 全量清单 · 解析 \(total) 个 launchd 任务，MachServices 共 \(all.count) 个，配件相关 \(matched.count) 个：\(matched.prefix(50).joined(separator: "，"))")
        probeMachServices(matched)
    }

    /// 进程表是“系统里有没有消费 0x4301 的进程”的直接答案。ps 命令在 iOS 上
    /// 不存在，libproc 是唯一通道（TrollStore 无沙盒下可读全表）。
    private func scanProcessTable() {
        let summary = DirectAccessoryTransport.processListSummary()
        AppLog.record("系统诊断 · 进程表：\(summary)")
        let detail = DirectAccessoryTransport.processDetailFor(["iapd", "carplay", "accessory", "airplay", "backboard"])
        AppLog.record("系统诊断 · 关键进程详情：\(detail.isEmpty ? "无匹配" : detail)")
    }

    private func scanEntitlements() {
        AppLog.record("系统诊断 · 本进程 entitlements：\(DirectAccessoryTransport.ownEntitlements())")
    }

    /// usr/libexec 是守护进程的家；SpringBoardPlugins 与 CoreServices 是界面侧。
    /// 谁的名字里带 car/play/accessory/iap，谁就可能在消费 CarPlay 会话。
    private func scanComponentDirectories() {
        let targets: [(String, (String) -> Bool)] = [
            ("/usr/libexec", { name in
                let lower = name.lowercased()
                return lower.contains("car") || lower.contains("play") || lower.contains("accessor")
                    || lower.contains("iap") || lower.contains("airport") || lower.contains("wifi")
            }),
            ("/System/Library/SpringBoardPlugins", { _ in true }),
            ("/System/Library/CoreServices", { name in
                let lower = name.lowercased()
                return lower.contains("car") || lower.contains("play") || lower.contains("accessor")
            }),
            ("/Library/LaunchDaemons", { _ in true }),
        ]
        for (directory, filter) in targets {
            let items = (try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? []
            let matched = items.filter(filter).sorted()
            AppLog.record("系统诊断 · \(directory) 共 \(items.count) 项，匹配 \(matched.count) 项：\(matched.prefix(40).joined(separator: "，"))")
        }
        for path in ["/var/jb", "/var/containers/Bundle/trollstore", "/usr/libexec/carplayd"] {
            AppLog.record("系统诊断 · \(path) = \(FileManager.default.fileExists(atPath: path) ? "存在" : "不存在")")
        }
    }

    /// 偏好目录里所有带 carplay/accessory 关键字的域全读出来：
    /// carplayd 若曾在某处留下配置，会在这里出现。
    private func scanCarPlayPreferenceFiles() {
        let directory = "/var/mobile/Library/Preferences"
        let items = (try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? []
        let matched = items.filter { name in
            let lower = name.lowercased()
            return lower.contains("car") || lower.contains("play") || lower.contains("accessor") || lower.contains("iap")
        }.sorted()
        AppLog.record("系统诊断 · 偏好文件：\(directory) 共 \(items.count) 项，匹配 \(matched.count) 项：\(matched.prefix(30).joined(separator: "，"))")
        for name in matched.prefix(15) {
            let path = directory + "/" + name
            let size = (try? FileManager.default.attributesOfItem(atPath: path))?[.size] as? Int ?? -1
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any]
            else {
                AppLog.record("系统诊断 · 偏好文件 \(name) 不可解析（\(size)B）")
                continue
            }
            let keys = plist.keys.sorted().prefix(12)
            AppLog.record("系统诊断 · 偏好文件 \(name) 共 \(plist.count) 键：\(keys.joined(separator: "，"))")
        }
    }

    /// plist 里声明的服务名是权威清单：逐个 bootstrap 查找，命中就真连一次，
    /// 用连接握手结果区分“服务存在但不可见”和“可见但拒绝外部客户端”。
    private func probeMachServices(_ names: [String]) {
        let unique = Array(Set(names)).sorted().filter { name in
            let lower = name.lowercased()
            return lower.contains("car") || lower.contains("air")
                || lower.contains("accessor") || lower.contains("iap")
        }
        guard !unique.isEmpty else {
            AppLog.record("XPC 清单探测 · launchd plist 里没有 Car/Air/配件相关 MachServices")
            return
        }
        AppLog.record("XPC 清单探测 · 候选 \(unique.count) 个：\(unique.prefix(40).joined(separator: "，"))")
        for name in unique.prefix(40) {
            guard let (result, port) = bootstrapLookupResult(name) else { continue }
            if result == 0 {
                AppLog.record("XPC 清单探测 · \(name)：命中（端口 \(port)），开始真实连接")
                DirectAccessoryTransport.xpcProbe(name) { AppLog.record($0) }
            } else {
                AppLog.record("XPC 清单探测 · \(name)：错误码 \(result)")
            }
        }
    }

    /// CoreAccessories 自己导出了哪些 CarPlay 相关类：如果 15.6 的库里就有
    /// 会话/播放类，说明逻辑存在、只差触发条件；没有则是系统版本硬限制的旁证。
    private func scanCoreAccessoriesClasses() {
        let summary = DirectAccessoryTransport.coreAccessoriesClassSummary()
        AppLog.record("系统诊断 · CoreAccessories 类枚举：\(String(summary.prefix(4000)))")
    }

    /// 在候选二进制里找协议字符串：命中 “4301” 等说明该进程实现了 CarPlay 会话启动。
    private func scanBinarySignatures() {
        let binaries = ["/usr/libexec/iapd", "/usr/libexec/backboardd",
                        "/System/Library/PrivateFrameworks/CoreAccessories.framework/CoreAccessories",
                        "/System/Library/PrivateFrameworks/CarPlay.framework/CarPlay",
                        "/System/Library/PrivateFrameworks/CarKit.framework/CarKit",
                        "/System/Library/PrivateFrameworks/CarAccessoryFramework.framework/CarAccessoryFramework"]
        let needles = ["4301", "StartSession", "startSession", "CarPlay", "carplayd", "accessoryd", "iapd"]
        for path in binaries {
            guard let size = (try? FileManager.default.attributesOfItem(atPath: path))?[.size] as? Int,
                  size > 0 else {
                AppLog.record("系统诊断 · 二进制 \(path) 不存在或为空，跳过字符串搜索")
                continue
            }
            guard size < 80 * 1024 * 1024 else {
                AppLog.record("系统诊断 · 二进制 \(path) 太大（\(size)B），跳过字符串搜索")
                continue
            }
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe) else {
                AppLog.record("系统诊断 · 二进制 \(path) 读取失败（\(size)B）")
                continue
            }
            for needle in needles {
                let needleData = Data(needle.utf8)
                var searchStart = data.startIndex
                var hits = 0
                var samples: [String] = []
                while hits < 200, searchStart < data.endIndex,
                      let range = data.range(of: needleData, in: searchStart..<data.endIndex) {
                    hits += 1
                    if samples.count < 3 {
                        let lower = max(data.startIndex, range.lowerBound - 24)
                        let upper = min(data.endIndex, range.upperBound + 24)
                        let context = data[lower..<upper].map { byte -> UInt8 in
                            (32...126).contains(byte) ? byte : 46
                        }
                        samples.append(String(decoding: context, as: UTF8.self))
                    }
                    searchStart = range.upperBound
                }
                if hits > 0 {
                    AppLog.record("系统诊断 · \(path) 含 “\(needle)” \(hits) 次：(命中片段上界 200)\(samples.map { "｜\($0)" }.joined())")
                }
            }
        }
    }

    private func scanLogDirectories() {
        let directories = [
            "/var/mobile/Library/Logs/DiagnosticReports",
            "/var/mobile/Library/Logs/CrashReporter",
            "/var/mobile/Library/Logs",
            "/var/log"
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

    // MARK: 远程镜像 / 共享缓存 / 套接字表 / Keychain / 端口占用

    private func logBlock(_ tag: String, _ text: String) {
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            AppLog.record("系统诊断 · \(tag)｜\(line)")
        }
    }

    /// task_for_pid + 远程 dyld 镜像枚举：正在运行的 iapd/backboardd/SpringBoard 是否
    /// 加载了 CarPlay 代码。区分“代码在系统里但没进程用”与“这些进程里根本没有”。
    private func scanRemoteProcessImages() {
        logBlock("远程镜像", DirectAccessoryTransport.remoteImageListForProcessNames(["iapd", "backboardd", "SpringBoard"]))
    }

    /// _dyld_shared_cache_contains_path：CarPlay 相关框架是否存在于系统镜像，
    /// 与是否有进程加载它们无关。
    private func scanSharedCache() {
        logBlock("共享缓存", DirectAccessoryTransport.sharedCacheContainment())
    }

    /// 内核 TCP 套接字表原始快照：系统里有没有进程在监听 CarPlay/RTSP 端口。
    private func scanSocketTable() {
        logBlock("套接字表", DirectAccessoryTransport.tcpSocketTableSummary())
    }

    /// 配件相关 Keychain 组：配对凭据是会话准入条件之一。
    private func scanKeychainGroups() {
        logBlock("Keychain", DirectAccessoryTransport.keychainSummary())
    }

    /// bind 占用探测：本机是否已有进程在监听 CarPlay 相关端口。本 App 自己监听的
    /// 7001/7002/7100/5000/62078 不能进来，否则是自己的监听冒充证据。
    private func scanPortOccupancy(_ ports: [UInt16]) {
        for port in ports {
            let fd = socket(AF_INET, SOCK_STREAM, 0)
            guard fd >= 0 else {
                AppLog.record("端口占用 · \(port)：socket 失败 errno \(errno)")
                continue
            }
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = port.bigEndian
            address.sin_addr.s_addr = in_addr_t(INADDR_ANY)
            let bound = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            if bound == 0 {
                AppLog.record("端口占用 · \(port)：空闲（系统里没有进程监听）")
                close(fd)
            } else {
                let code = errno
                close(fd)
                if code == EADDRINUSE {
                    AppLog.record("端口占用 · \(port)：被占用（有进程在监听）")
                } else {
                    AppLog.record("端口占用 · \(port)：bind 失败 errno \(code)（非占用）")
                }
            }
        }
    }

    // MARK: CarPlay 偏好设置

    private func scanPreferences() {
        let domains = ["com.apple.carplayd", "com.apple.carplay", "com.apple.CoreAccessories",
                       "com.apple.iapd", "com.apple.carkit", "com.apple.AccessorySettings",
                       "com.apple.airplay"]
        let scopes: [(user: CFString, scope: String, quiet: Bool)] = [
            (kCFPreferencesCurrentUser, "CurrentUser", false),
            (kCFPreferencesAnyUser, "AnyUser", true)
        ]
        for entry in scopes {
            for domain in domains {
                scanPreferenceDomain(domain, user: entry.user, scope: entry.scope, quiet: entry.quiet)
            }
        }
        for file in ["/var/mobile/Library/Preferences/com.apple.carplay.plist",
                     "/var/mobile/Library/Preferences/com.apple.carplayd.plist",
                     "/var/mobile/Library/Preferences/com.apple.CoreAccessories.plist",
                     "/var/mobile/Library/Preferences/com.apple.iapd.plist",
                     "/var/mobile/Library/Preferences/com.apple.AccessorySettings.plist"] {
            let size = (try? FileManager.default.attributesOfItem(atPath: file)[.size] as? Int) ?? nil
            AppLog.record("系统诊断 · 偏好文件 \(file) \(size.map { "\($0) 字节" } ?? "不存在或不可读")")
        }
    }

    private func scanPreferenceDomain(_ domain: String, user: CFString, scope: String, quiet: Bool) {
        let values = CFPreferencesCopyMultiple(nil, domain as CFString,
                                               user, kCFPreferencesAnyHost) as? [String: Any]
        guard let values else {
            // AnyUser 域大多不存在，安静跳过，避免刷屏干扰 CurrentUser 的证据。
            if !quiet { AppLog.record("系统诊断 · 偏好域 \(domain) 读取不到（沙盒或不存在）") }
            return
        }
        let names = values.keys.sorted()
        AppLog.record("系统诊断 · 偏好域 \(domain)（\(scope)）共 \(names.count) 项：\(names.prefix(30).joined(separator: "，"))")
        for name in names.prefix(20) {
            let value = values[name]
            let description: String
            switch value {
            case let number as NSNumber: description = number.stringValue
            case let string as String: description = String(string.prefix(120))
            case let date as Date: description = Self.stamp(date)
            case let data as Data:
                let hex = data.prefix(48).map { String(format: "%02x", $0) }.joined()
                description = "Data \(data.count)B 开头 \(hex)"
            case let array as [Any]: description = "数组 \(array.count) 项：\(String(describing: array.prefix(5)))"
            case let dictionary as [String: Any]: description = "字典 \(dictionary.count) 键：\(dictionary.keys.sorted().prefix(8).joined(separator: "，"))"
            case .some(let other): description = String(describing: type(of: other))
            case .none: description = "nil"
            }
            AppLog.record("系统诊断 · \(domain)（\(scope)）｜\(name) = \(description)")
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
    /// 整体失效。OSLogStore 是 iOS 15 的公开 API，但它只有本进程域——`.system` 作用域在
    /// iOS 上是编译期不可用（macOS 专属，本次 CI 已实测报错），所以这个通道只能看到本 App
    /// 自己的日志，看不到 carplayd。日志里写明这一点，避免把空结果误读成“守护进程没动静”。
    private func openUnifiedLogStore() -> OSLogStore? {
        do {
            let store = try OSLogStore(scope: .currentProcessIdentifier)
            AppLog.record("OSLogStore · 本进程域已打开。边界：`.system` 域在 iOS 上编译期不可用，公开 API 读不到 carplayd 的日志，通道内只有本 App 自己的行")
            return store
        } catch {
            AppLog.record("OSLogStore · 本进程域打开失败：\(error.localizedDescription)（统一日志 API 通道不可用）")
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
            ButtonLog.record("开始收集 · 约 \(seconds) 秒 · 请在收集期间按下车上的按键")
            if let store = openUnifiedLogStore() {
                ButtonLog.record("按键日志通道 · OSLogStore（本进程域；系统域在 iOS 上不可用，车机按键若走 carplayd 这里看不到）")
                sweepUnifiedLog(store: store, predicate: Self.buttonPredicate, since: 180,
                                maxEntries: 300, tag: "最近 3 分钟") { ButtonLog.record($0) }
                pollUnifiedLog(store: store, predicate: Self.buttonPredicate, seconds: seconds,
                               tag: "实时") { ButtonLog.record($0) }
            } else {
                ButtonLog.record("按键日志通道 · OSLogStore 不可用，退回命令行（本机已证实 ENOENT）")
            }
            run(command: "log show --last 3m --style compact --predicate '\(Self.buttonShellPredicate)' 2>&1 | head -c 200000",
                maxSeconds: 25, maxLines: 300, tag: "最近 3 分钟(命令行)", scope: "按键日志", record: ButtonLog.record)
            ButtonLog.record("收集结束")
        }
    }

    /// 仅供命令行通道使用的谓词字符串（与 buttonPredicate 同一筛选口径）。
    private static let buttonShellPredicate = #"(eventMessage CONTAINS[c] "IOHID" OR eventMessage CONTAINS[c] "HIDEvent" OR eventMessage CONTAINS[c] "hidReport" OR eventMessage CONTAINS[c] "keyboard" OR eventMessage CONTAINS[c] "button" OR eventMessage CONTAINS[c] "knob" OR eventMessage CONTAINS[c] "steering" OR eventMessage CONTAINS[c] "wheel" OR eventMessage CONTAINS[c] "mediaRemote" OR eventMessage CONTAINS[c] "iAP2" OR eventMessage CONTAINS[c] "accessory" OR subsystem CONTAINS[c] "HID" OR process CONTAINS[c] "carplay")"#

    // MARK: 实时日志流 / 网络抓包（投屏窗口内调用）

    /// 在投屏尝试期间实时记录 CarPlay 相关系统日志：daemon 的拒绝/崩溃会当场出现，
    /// 不用等它写进归档。OSLogStore 轮询通道优先；命令行通道作为对照保留。
    func streamLogs(seconds: Int, completion: (() -> Void)? = nil) {
        captureQueue.async { [self] in
            defer { completion?() }
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
    func captureNetwork(interface: String, seconds: Int, completion: (() -> Void)? = nil) {
        captureQueue.async { [self] in
            defer { completion?() }
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

    // MARK: 多端口监听（系统可能回连到别的端口）

    /// 0x4301 里的端口是我们替系统填的，但真机可能按自己的表回连其他端口。
    /// 同时监听 CarPlay/AirPlay 常用端口：任何来源的连接都记下来，哪怕端口不对。
    /// bind 失败也是证据——说明已有进程占着这个端口。
    func listenProbePorts(_ ports: [UInt16], seconds: Int, completion: (() -> Void)? = nil) {
        captureQueue.async { [self] in
            var descriptors: [Int32] = []
            for port in ports {
                let fd = socket(AF_INET, SOCK_STREAM, 0)
                guard fd >= 0 else {
                    AppLog.record("端口监听 · \(port)：socket 失败 errno \(errno)")
                    continue
                }
                var reuse: Int32 = 1
                _ = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
                var address = sockaddr_in()
                address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                address.sin_family = sa_family_t(AF_INET)
                address.sin_port = port.bigEndian
                address.sin_addr.s_addr = in_addr_t(INADDR_ANY)
                let bound = withUnsafePointer(to: &address) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
                guard bound == 0 else {
                    AppLog.record("端口监听 · \(port)：bind 失败 errno \(errno)（端口已被其他进程占用或无权限）")
                    close(fd)
                    continue
                }
                guard listen(fd, 8) == 0 else {
                    AppLog.record("端口监听 · \(port)：listen 失败 errno \(errno)")
                    close(fd)
                    continue
                }
                AppLog.record("端口监听 · \(port)：已监听，等待系统回连")
                descriptors.append(fd)
                DispatchQueue.global(qos: .utility).async {
                    while true {
                        var peer = sockaddr_in()
                        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
                        let client = withUnsafeMutablePointer(to: &peer) { pointer in
                            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                                accept(fd, $0, &length)
                            }
                        }
                        if client < 0 { return }
                        var host = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                        var peerAddress = peer.sin_addr
                        _ = inet_ntop(AF_INET, &peerAddress, &host, socklen_t(INET_ADDRSTRLEN))
                        let source = String(cString: host)
                        AppLog.record("端口监听 · \(port)：收到连接，来源 \(source):\(UInt16(bigEndian: peer.sin_port))")
                        close(client)
                    }
                }
            }
            guard !descriptors.isEmpty else {
                AppLog.record("端口监听 · 没有端口监听成功")
                completion?()
                return
            }
            captureQueue.asyncAfter(deadline: .now() + .seconds(seconds)) { [self] in
                for fd in descriptors { close(fd) }
                AppLog.record("端口监听 · 结束，关闭 \(descriptors.count) 个监听端口")
                completion?()
            }
        }
    }

    // MARK: Bonjour（系统是否广播 CarPlay 服务）

    /// 无线 CarPlay 的发现走 Bonjour：如果系统里有任何会话组件在广播
    /// _carplay/_airplay/_raop 服务，浏览这里就能看到；全空则说明根本没有。
    func browseCarPlayServices(seconds: Int, completion: (() -> Void)? = nil) {
        // NSNetServiceBrowser 依赖 run loop，必须在主线程启动。
        DispatchQueue.main.async { [self] in
            let probe = BonjourBrowseProbe()
            bonjourProbe = probe
            probe.start(types: ["_carplay._tcp.", "_carplay-rtsp._tcp.", "_airplay._tcp.",
                                "_raop._tcp.", "_iapp._tcp.", "_appletv-v2._tcp."], seconds: seconds,
                        completion: completion)
        }
    }

    // MARK: 自检：本机监听端口能否回连

    /// 证明 RTSP 端口在本机可回连；这样如果抓包也看不到 carplayd 的包，
    /// 就能确定是守护进程没尝试，而不是我们的监听器有问题。
    func selfConnectTest(port: UInt16, completion: (() -> Void)? = nil) {
        captureQueue.async {
            defer { completion?() }
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
    func kickstartCarPlayDaemon(completion: (() -> Void)? = nil) {
        captureQueue.async { [self] in
            defer { completion?() }
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

    /// 逐个查找候选 Mach 服务名。NSXPCConnection 的 machServiceName 初始化在 iOS 上
    /// 编译期不可用（macOS 专属），能做的握手就是 bootstrap_look_up：kern_return 0
    /// 表示服务在 launchd 里注册且本 App 的命名空间可见，错误码则表示不可见。这就是
    /// 本实验的证据终点，不再有“连接存活”这一步。
    func probeCarPlayXPC(completion: (() -> Void)? = nil) {
        captureQueue.async { [self] in
            defer { completion?() }
            let candidates = [
                "com.apple.carplayd",
                "com.apple.carplayd.app.service",
                "com.apple.carplayd.control",
                "com.apple.carplayd.control.service",
                "com.apple.carplayd.service",
                "com.apple.carplayd.agent",
                "com.apple.CarPlayServer",
                "com.apple.CarPlay",
                "com.apple.carkitd",
                "com.apple.CarKit",
                "com.apple.airplayd",
                "com.apple.airplayd.service",
                "com.apple.accessoryd",
                "com.apple.coreaccessoriesd",
                "com.apple.CoreAccessories.server",
                "com.apple.iapd",
                "com.apple.iap2d",
                "com.apple.wifid",
            ]
            AppLog.record("XPC 探测开始 · bootstrap 查找 \(candidates.count) 个候选 Mach 服务名（iOS 上 NSXPC 只支持 listener 端点，服务名查找结果就是证据终点）")
            for name in candidates {
                guard let (result, port) = bootstrapLookupResult(name) else {
                    AppLog.record("XPC 探测 · \(name)：bootstrap_look_up 符号解析失败")
                    continue
                }
                if result == 0 {
                    AppLog.record("XPC 探测 · \(name)：bootstrap 命中（端口 \(port)）——服务已注册且对本 App 可见")
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

/// NSNetServiceBrowser 需要 Objective-C 运行时承担 delegate 回调；
/// 结果全部写进日志，不依赖任何系统进程配合。
final class BonjourBrowseProbe: NSObject, NSNetServiceBrowserDelegate, NSNetServiceDelegate {
    private var browsers: [NSNetServiceBrowser] = []
    private var services: [NSNetService] = []
    private var seen: Set<String> = []

    func start(types: [String], seconds: Int, completion: (() -> Void)? = nil) {
        AppLog.record("Bonjour 浏览开始 · \(seconds) 秒 · 类型 \(types.joined(separator: "，"))")
        for type in types {
            let browser = NSNetServiceBrowser()
            browser.delegate = self
            browser.searchForServices(ofType: type, inDomain: "local.")
            browsers.append(browser)
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(seconds)) { [weak self] in
            guard let self else { return }
            for browser in self.browsers { browser.stop() }
            self.browsers.removeAll()
            AppLog.record(self.seen.isEmpty
                ? "Bonjour 浏览结束 · 未发现任何 CarPlay/AirPlay 服务（系统侧没有广播）"
                : "Bonjour 浏览结束 · 共发现 \(self.seen.count) 个服务")
            completion?()
        }
    }

    func netServiceBrowser(_ browser: NSNetServiceBrowser, didFind service: NSNetService, moreComing: Bool) {
        let key = "\(service.type)|\(service.name)"
        guard !seen.contains(key) else { return }
        seen.insert(key)
        AppLog.record("Bonjour 发现 · \(service.type) \(service.name)（\(service.domain)）")
        service.delegate = self
        services.append(service)
        service.resolve(withTimeout: 2)
    }

    func netServiceBrowser(_ browser: NSNetServiceBrowser, didNotSearch errorDict: [String: NSNumber]) {
        AppLog.record("Bonjour 浏览失败 · \(errorDict)")
    }

    func netServiceDidResolveAddress(_ sender: NSNetService) {
        AppLog.record("Bonjour 解析 · \(sender.type) \(sender.name) → \(sender.hostName ?? "?"):\(sender.port)")
    }

    func netService(_ sender: NSNetService, didNotResolve errorDict: [String: NSNumber]) {
        AppLog.record("Bonjour 解析失败 · \(sender.type) \(sender.name)：\(errorDict)")
    }
}

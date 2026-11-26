import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Finds the instrument when its address was not entered: unicast TCP probes every host of the
/// phone's own Wi-Fi subnet (the announcement port only answers when the instrument is casting).
enum TailingDiscovery {
    static let savedAddressKey = "zeehoLastDiscoveredAddress"

    static func candidates(localIP: String, netmask: String, previousIP: String?) -> [String] {
        guard let ip = number(localIP), let mask = number(netmask), mask > 0,
              mask != UInt32.max else { return [] }
        let hostMask = ~mask
        guard hostMask & (hostMask + 1) == 0 else { return [] }
        let network = ip & mask, broadcast = network | hostMask
        let scanMask = max(mask, 0xffff_ff00)
        let scanNetwork = ip & scanMask, scanBroadcast = scanNetwork | ~scanMask
        let first = hostMask == 1 ? network : network + 1
        let last = hostMask == 1 ? broadcast : broadcast - 1
        var addresses: [UInt32] = []
        var seen = Set<UInt32>()
        func add(_ candidate: UInt32) {
            guard candidate >= first, candidate <= last, candidate != ip,
                  seen.insert(candidate).inserted else { return }
            addresses.append(candidate)
        }
        if let previousIP, let previous = number(previousIP) { add(previous) }
        add(first)
        add(scanNetwork + 1)
        if scanBroadcast > scanNetwork { add(scanBroadcast - 1) }
        add(last)
        let scanFirst = hostMask == 1 ? scanNetwork : scanNetwork + 1
        let scanLast = hostMask == 1 ? scanBroadcast : scanBroadcast - 1
        if scanFirst <= scanLast {
            for candidate in scanFirst...scanLast { add(candidate) }
        }
        return addresses.map(text)
    }

    private static func number(_ address: String) -> UInt32? {
        let parts = address.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var result: UInt32 = 0
        for part in parts {
            guard !part.isEmpty, part.allSatisfy({ $0 >= "0" && $0 <= "9" }),
                  let byte = UInt8(part) else { return nil }
            result = (result << 8) | UInt32(byte)
        }
        return result
    }

    private static func text(_ value: UInt32) -> String {
        "\(value >> 24).\((value >> 16) & 255).\((value >> 8) & 255).\(value & 255)"
    }

    #if canImport(Darwin)
    private static func interfaceInfo(localIP: String) -> (name: String, netmask: String)? {
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0 else { return nil }
        defer { freeifaddrs(first) }
        var current = first
        while let entry = current {
            defer { current = entry.pointee.ifa_next }
            guard let address = entry.pointee.ifa_addr,
                  address.pointee.sa_family == UInt8(AF_INET),
                  let mask = entry.pointee.ifa_netmask,
                  entry.pointee.ifa_flags & UInt32(IFF_UP) != 0,
                  entry.pointee.ifa_flags & UInt32(IFF_LOOPBACK) == 0 else { continue }
            let ip = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                UInt32(bigEndian: $0.pointee.sin_addr.s_addr)
            }
            guard text(ip) == localIP else { continue }
            let value = mask.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                text(UInt32(bigEndian: $0.pointee.sin_addr.s_addr))
            }
            return (String(cString: entry.pointee.ifa_name), value)
        }
        return nil
    }

    private static func subnetText(localIP: String, netmask: String) -> String {
        guard let ip = number(localIP), let mask = number(netmask) else { return "未知网段" }
        return "\(text(ip & mask))/\(mask.nonzeroBitCount)"
    }

    static func connect(localIP: String, port: UInt16, log: @escaping (String) -> Void = { _ in },
                        track: @escaping (TailingSocket) throws -> TailingSocket,
                        check: @escaping () throws -> Void) throws -> (address: String, socket: TailingSocket) {
        guard let interface = interfaceInfo(localIP: localIP) else {
            throw TailingError.protocolFailure("无法读取当前 Wi-Fi 子网，请连接仪表 Wi-Fi，或关闭自动查找并填写仪表 IP")
        }
        guard !interface.name.hasPrefix("pdp_ip") else {
            throw TailingError.protocolFailure("本机地址 \(localIP) 是蜂窝网络（\(interface.name)），自动查找只能扫描 Wi-Fi。请先在系统设置连接仪表 Wi-Fi，再启动投屏")
        }
        let mask = interface.netmask
        let subnet = subnetText(localIP: localIP, netmask: mask)
        let addresses = candidates(localIP: localIP, netmask: mask,
                                   previousIP: UserDefaults.standard.string(forKey: savedAddressKey))
        guard !addresses.isEmpty else {
            throw TailingError.protocolFailure("无法从本机地址 \(localIP)/\(mask) 生成扫描列表，请关闭自动查找并填写仪表 IP")
        }
        log("自动查找：本机 \(localIP)（\(interface.name)），网段 \(subnet)，候选 \(addresses.count) 个地址")
        let denied = Counter()
        let passes = 4
        for pass in 1...passes {
            try check()
            let passStarted = ProcessInfo.processInfo.systemUptime
            if pass > 1 { log("自动查找第 \(pass)/\(passes) 轮，继续扫描 \(subnet)…") }
            var batch = 0
            for start in stride(from: 0, to: addresses.count, by: 16) {
                try check()
                batch += 1
                let results = Connections()
                let group = DispatchGroup()
                for address in addresses[start..<min(start + 16, addresses.count)] {
                    group.enter()
                    DispatchQueue.global(qos: .userInitiated).async {
                        defer { group.leave() }
                        var socket: TailingSocket?
                        do {
                            try check()
                            let next = try track(TailingSocket.create())
                            socket = next
                            try next.connect(localIP: localIP, remoteIP: address, port: port, timeout: 0.4)
                            try check()
                            results.add(address: address, socket: next)
                        } catch {
                            socket?.close()
                            if let tailing = error as? TailingError, case .system(_, let code) = tailing, code == EPERM {
                                denied.increment()
                            }
                        }
                    }
                }
                group.wait()
                let connected = results.take()
                log("自动查找第 \(pass)/\(passes) 轮第 \(batch) 批：\(start + 1)–\(min(start + 16, addresses.count)) / \(addresses.count)，连接成功 \(connected.count) 个")
                do { try check() }
                catch { connected.forEach { $0.socket.close() }; throw error }
                for address in addresses[start..<min(start + 16, addresses.count)] {
                    if let selected = connected.first(where: { $0.address == address }) {
                        connected.filter { $0.address != address }.forEach { $0.socket.close() }
                        log(String(format: "自动查找命中 %@:%d（第 %d 轮第 %d 批，耗时 %.1f 秒）", address, Int(port), pass, batch,
                                   ProcessInfo.processInfo.systemUptime - passStarted))
                        return selected
                    }
                }
            }
            if pass < passes {
                log(String(format: "第 %d 轮未发现仪表 10930 端口（扫描 %d 个地址，耗时 %.1f 秒），3 秒后重试（仪表投屏页可能尚未就绪）",
                           pass, addresses.count, ProcessInfo.processInfo.systemUptime - passStarted))
                for _ in 0..<30 {
                    try check()
                    Thread.sleep(forTimeInterval: 0.1)
                }
            } else {
                log(String(format: "第 %d 轮仍未发现仪表（扫描 %d 个地址，耗时 %.1f 秒，EPERM %d 次）",
                           pass, addresses.count, ProcessInfo.processInfo.systemUptime - passStarted, denied.peek()))
            }
        }
        if denied.take() > 0 {
            throw TailingError.protocolFailure("自动查找被系统拒绝访问局域网（EPERM）。请到 iPhone「设置 → 隐私与安全性 → 本地网络」把 CarWithin 打开后重试")
        }
        throw TailingError.timeout("自动查找未发现仪表（本机 \(localIP)，网段 \(subnet)，共 \(passes) 轮）。请确认已连接仪表 Wi-Fi 并打开仪表投屏；若刚打开投屏页，可稍等几秒再启动，或关闭自动查找后填写仪表 IP")
    }

    private final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var value = 0
        func increment() { lock.lock(); value += 1; lock.unlock() }
        func take() -> Int { lock.lock(); defer { lock.unlock() }; let result = value; value = 0; return result }
        func peek() -> Int { lock.lock(); defer { lock.unlock() }; return value }
    }

    private final class Connections: @unchecked Sendable {
        private let lock = NSLock()
        private var values: [(address: String, socket: TailingSocket)] = []

        func add(address: String, socket: TailingSocket) {
            lock.lock(); defer { lock.unlock() }
            values.append((address: address, socket: socket))
        }

        func take() -> [(address: String, socket: TailingSocket)] {
            lock.lock(); defer { lock.unlock() }
            let result = values
            values.removeAll()
            return result
        }
    }
    #endif
}

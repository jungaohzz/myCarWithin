import Foundation

/// Main-queue session for the direct accessory transport.
final class SameDeviceProbe {
    private let transport = DirectAccessoryTransport()
    private var parser = IAP2Parser()
    private var generation = UUID()
    private var active = false
    private var linked = false
    private var authenticated = false
    private var identified = false
    private var sequence: UInt8 = 0x10
    private var acknowledgement: UInt8 = 0
    private var lastPayloadSequence: UInt8?
    private var session: UInt8 = 1
    private var identity: AccessoryIdentity?
    private var configuration: ReceiverConfiguration?
    private var messageBytes = Data()
    private var requested = false
    private var controlConnected = false
    private var expectsLocalControl = true
    private var sessionRequests = 0
    private var packetsReceived = 0
    private var messagesReceived = 0
    private var chunksReceived = 0
    private var startedAt = DispatchTime.now()
    private var heartbeatTimer: DispatchSourceTimer?
    // iOS 15 实验开关：同一轮日志里能看到实际使用的组合。
    private var experimentTransportType: UInt = 2
    private var effectiveTransportType: UInt = 2
    private var experimentWifiOnly = false
    private var experimentSkipWifi = false
    private var experimentLoopback = false
    // 0x4300 提供的传输标识：系统为本机端点生成的值，0x4301 匹配实验用它回填参数 3。
    private var availableTransports: [(type: UInt8, identifier: String)] = []
    private var experimentMatchIdent = false
    private var experimentAccSelfAuth = true
    private var experimentEndpointInitSelf = true
    private var experimentPropertyHandlers = true
    private var experimentExplicitPublish = false
    var onLog: ((String) -> Void)?

    private func hexPreview(_ data: Data, limit: Int = 96) -> String {
        let text = data.prefix(limit).map { String(format: "%02X", $0) }.joined(separator: " ")
        return data.count > limit ? "\(text) …（共 \(data.count) 字节）" : text
    }
    var onFinished: ((String) -> Void)?
    var onStage: ((String) -> Void)?

    func start(configuration: ReceiverConfiguration, identity: AccessoryIdentity, expectsLocalControl: Bool = true) {
        stop(); active = true; self.identity = identity; self.configuration = configuration
        self.expectsLocalControl = expectsLocalControl
        startedAt = .now()
        let defaults = UserDefaults.standard
        let rawTransport = defaults.object(forKey: "localTransportType") as? Int ?? 2
        experimentTransportType = [1, 3, 8].contains(rawTransport) ? UInt(rawTransport) : 2
        experimentWifiOnly = defaults.bool(forKey: "localWifiOnlyIdent")
        experimentSkipWifi = defaults.bool(forKey: "localSkipWifi")
        experimentLoopback = defaults.bool(forKey: "localLoopbackSession")
        experimentMatchIdent = defaults.bool(forKey: "localMatch4300Ident")
        experimentAccSelfAuth = defaults.object(forKey: "localAccSelfAuth") as? Bool ?? true
        experimentEndpointInitSelf = defaults.object(forKey: "localEndpointInitSelf") as? Bool ?? true
        experimentPropertyHandlers = defaults.object(forKey: "localPropertyHandlers") as? Bool ?? true
        experimentExplicitPublish = defaults.bool(forKey: "localExplicitPublish")
        transport.registerPropertyHandlers = experimentPropertyHandlers
        transport.publishExplicitly = experimentExplicitPublish
        effectiveTransportType = experimentTransportType
        let os = ProcessInfo.processInfo.operatingSystemVersion
        let wifi = configuration.ssid.isEmpty ? "Wi-Fi 未填写"
            : "Wi-Fi \(configuration.ssid)/信道 \(configuration.wifiChannel)/\(configuration.password.isEmpty ? "开放网络" : "密码 \(configuration.password.utf8.count) 字节")"
        stage("本机 CarPlay 启动 · iOS \(os.majorVersion).\(os.minorVersion).\(os.patchVersion) · 配件 \(configuration.deviceID) · 回调 \(configuration.address):\(configuration.port) · \(wifi) · 传输类型 \(experimentTransportType) · 期望控制连接=\(expectsLocalControl) · 实验：0x1D01 仅 Wi-Fi 声明=\(experimentWifiOnly ? "是" : "否")，0x4301 跳过 Wi-Fi 凭据=\(experimentSkipWifi ? "是" : "否")，0x4301 目标=127.0.0.1=\(experimentLoopback ? "是" : "否")，0x4301 标识回填 0x4300=\(experimentMatchIdent ? "是" : "否")，ACC 自证=\(experimentAccSelfAuth ? "开" : "关")，端点 iAP2_Initialized 自填=\(experimentEndpointInitSelf ? "开" : "关")，属性回调注册=\(experimentPropertyHandlers ? "开" : "关")，显式发布连接=\(experimentExplicitPublish ? "是" : "否")")
        onLog?("本机传输能力（CoreAccessories）：" + String(DirectAccessoryTransport.apiSummary().prefix(1500)))
        // 0x4300 的系统生成标识长得像 en0 MAC（28:02:44:b1:2b:c2）；把本机 MAC 打出来比对。
        // iOS 可能对 App 返回 02:00:00:00:00:00，这本身也是证据。
        onLog?("本机 en0 MAC · \(ReceiverConfiguration.wifiMACAddress() ?? "读取失败")（用于比对 0x4300 系统生成标识）")
        transport.onDiagnostic = { [weak self] message in
            self?.onLog?(message)
        }
        if !AppLog.localCarPlaySupport.supported { onLog?("警告：\(AppLog.localCarPlaySupport.summary)") }
        let run = generation
        transport.onData = { [weak self] data in self?.receive(data) }
        do {
            // Type 2 is the Wi-Fi accessory connection; type 8 is the iOS 15 experiment.
            do {
                try transport.start(withIdentifier: configuration.deviceID, transportType: experimentTransportType)
            } catch {
                guard experimentTransportType != 2 else { throw error }
                onLog?("传输类型 \(experimentTransportType) 失败（\(error.localizedDescription)），回退传输类型 2")
                effectiveTransportType = 2
                try transport.start(withIdentifier: configuration.deviceID, transportType: 2)
            }
            stage("已创建本机配件端点（传输类型 \(effectiveTransportType)，CoreAccessories 连接类型 \(transport.connectionTypeDescription ?? "?")），正在建立 iAP2")
            transport.dumpConnectionState("端点创建后基线")
            startHeartbeat()
            try transport.send(IAP2Packet.presence)
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { [weak self] in
                guard let self, self.active, self.generation == run else { return }
                do {
                    let syn = IAP2Packet(control: 0x80, sequence: self.sequence, acknowledgement: 0, session: 0,
                        payload: Data([1, 5, 8, 0, 7, 0xd0, 0, 0xfa, 3, 3, 1, 0, 1]))
                    try self.transport.send(syn.encoded())
                } catch { self.finish("本机传输写入失败：\(error.localizedDescription)") }
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 20) { [weak self] in
                guard let self, self.active, self.generation == run, !self.requested else { return }
                self.finish("会话启动超时（链路=\(self.linked)，认证=\(self.authenticated)，识别=\(self.identified)，已收 \(self.packetsReceived) 个 iAP2 包/\(self.messagesReceived) 条消息）")
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 45) { [weak self] in
                guard let self, self.active, self.generation == run, self.expectsLocalControl, !self.controlConnected else { return }
                let support = AppLog.localCarPlaySupport
                if !support.supported {
                    self.finish("未收到 CarPlay 控制连接：\(support.summary)。已发送 \(self.sessionRequests) 次 0x4301 启动请求，等待 45 秒仍无 TCP 回连——这是系统版本限制，检查 Wi-Fi 参数无法解决。请在 iOS 16.0–16.6.1 设备上测试本机 CarPlay。")
                } else {
                    self.finish("未收到 CarPlay 控制连接（已发送 \(self.sessionRequests) 次 0x4301，等待 45 秒），请检查 Wi-Fi 名称和密码后重试。兼容信道通常可保持默认值。")
                }
            }
        } catch { finish("本机传输失败：\(error.localizedDescription)") }
    }
    func stop() {
        active = false; generation = UUID(); transport.stop(); transport.onData = nil; parser = IAP2Parser()
        heartbeatTimer?.cancel(); heartbeatTimer = nil
        identity = nil; configuration = nil; messageBytes = Data(); sequence = 0x10; acknowledgement = 0
        session = 1; lastPayloadSequence = nil; linked = false; authenticated = false; identified = false; requested = false; controlConnected = false
        availableTransports = []
        sessionRequests = 0; packetsReceived = 0; messagesReceived = 0; chunksReceived = 0; startedAt = .now()
    }

    /// 每 10 秒一行，证明 iAP2 链路本身仍然活着——CarPlay 守护进程不回连时，
    /// 这行日志区分“链路死了”和“系统不理我们”。
    private func startHeartbeat() {
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + 10, repeating: 10)
        var beats = 0
        timer.setEventHandler { [weak self] in
            guard let self, self.active else { return }
            beats += 1
            let live = ReceiverConfiguration.wifiIPv4Address() ?? "无 en0 地址"
            self.onLog?("本机 iAP2 心跳 #\(beats)：包 \(self.packetsReceived)/消息 \(self.messagesReceived)，链路=\(self.linked ? "是" : "否")，认证=\(self.authenticated ? "是" : "否")，识别=\(self.identified ? "是" : "否")，0x4301 已发 \(self.sessionRequests) 次，控制连接=\(self.controlConnected ? "是" : "否")，\(self.transport.authSummary())，当前 en0=\(live)")
        }
        timer.resume()
        heartbeatTimer = timer
    }
    func didConnectControl() {
        guard active else { return }
        controlConnected = true
        stage("CarPlay 控制连接已建立，正在协商会话")
    }
    private func requestSession(_ configuration: ReceiverConfiguration) throws {
        let wifi: AccessoryMessages.WiFi?
        if experimentSkipWifi {
            wifi = nil
        } else {
            wifi = try AccessoryMessages.WiFi(ssid: configuration.ssid, password: configuration.password,
                                              channel: configuration.wifiChannel)
        }
        sessionRequests += 1
        let target = experimentLoopback ? "127.0.0.1" : configuration.address
        if !experimentLoopback {
            let live = ReceiverConfiguration.wifiIPv4Address() ?? "无 en0 地址"
            if live != configuration.address {
                onLog?("警告：0x4301 告知的地址 \(configuration.address) 与当前 en0 \(live) 不一致；守护进程若按此地址回连会连到错误主机")
            }
        }
        // 0x4301 匹配实验：参数 3 的设备标识默认是 App 自己的配件 MAC；实验时回填 0x4300
        // 里系统给出的标识（优先 MAC 样式），检验守护进程是否按这个值匹配端点。
        var deviceID = configuration.deviceID
        if experimentMatchIdent, !availableTransports.isEmpty {
            let macStyle = availableTransports.first { $0.identifier.contains(":") }?.identifier
                ?? availableTransports[0].identifier
            onLog?("0x4301 标识实验：参数 3 回填 0x4300 提供的 \(macStyle)（原 \(configuration.deviceID)）")
            deviceID = macStyle
        }
        let elapsed = Double(DispatchTime.now().uptimeNanoseconds - startedAt.uptimeNanoseconds) / 1_000_000_000
        let wifiText = wifi.map {
            "Wi-Fi \($0.ssid)（信道 \(Int($0.channel))，\($0.password.isEmpty ? "开放" : "密码 \($0.password.utf8.count) 字节")）"
        } ?? "不携带 Wi-Fi 组（实验）"
        onLog?(String(format: "第 %d 次发送 0x4301 启动 CarPlay（启动后 %.1f 秒）：目标 %@:%d，%@，标识 %@，认证=%@，识别=%@%@",
            sessionRequests, elapsed, target, Int(configuration.port), wifiText,
            deviceID, authenticated ? "是" : "否", identified ? "是" : "否",
            experimentLoopback ? "，回环实验（真实监听地址 \(configuration.address)）" : ""))
        try send(AccessoryMessages.startSession(address: target, port: configuration.port,
            deviceID: deviceID, wifi: wifi))
    }
    private func stage(_ message: String) { onLog?(message); onStage?(message) }
    private func finish(_ message: String) {
        onLog?(message)
        onLog?("本机 iAP2 会话结束：收到 \(packetsReceived) 个包、\(messagesReceived) 条消息，发送 0x4301 共 \(sessionRequests) 次")
        stop(); onFinished?(message)
    }
    private func ack() throws {
        try transport.send(IAP2Packet(control: 0x40, sequence: sequence, acknowledgement: acknowledgement, session: 0).encoded())
    }
    private func send(_ message: IAP2Message) throws {
        sequence &+= 1
        let payload = try message.encoded()
        let fields = message.parameters
            .map { "\($0.id)=\($0.value.count)B" }
            .joined(separator: "，")
        // 0x4301 含 Wi-Fi 密码，只记录字段结构不打印十六进制内容。
        let content = message.id == 0x4301 ? "（含 Wi-Fi 凭据，不打印内容）" : "：\(hexPreview(payload, limit: 320))"
        onLog?(String(format: "发送 iAP2 消息 0x%04X（%d 个参数\(fields.isEmpty ? "" : "：\(fields)")，%d 字节，seq=%d）%@",
                      message.id, message.parameters.count, payload.count, Int(sequence), content))
        try transport.send(IAP2Packet(control: 0x40, sequence: sequence, acknowledgement: acknowledgement,
            session: session, payload: payload).encoded())
    }
    private func receive(_ data: Data) {
        guard active else { return }
        do {
            chunksReceived += 1
            if chunksReceived <= 4000 {
                onLog?(String(format: "iAP2 原始数据块 #%d：%d 字节：%@", chunksReceived, data.count, hexPreview(data, limit: 48)))
            }
            for event in try parser.append(data) {
                switch event {
                case .presence: onLog?("本机 iOS 服务已响应 iAP2 在线探测")
                case .packet(let packet):
                    packetsReceived += 1
                    // 握手期数据量很小；上限放宽到 4000 个包，保证一次连接就留下全部证据。
                    if packetsReceived <= 4000 {
                        onLog?(String(format: "iAP2 收到包 #%d：control=0x%02X seq=%d ack=%d session=%d 载荷=%d 字节：%@",
                            packetsReceived, Int(packet.control), Int(packet.sequence), Int(packet.acknowledgement),
                            Int(packet.session), packet.payload.count, hexPreview(packet.payload, limit: 96)))
                    }
                    acknowledgement = packet.sequence
                    if packet.control & 0x20 != 0 { throw ProtocolError.malformed("iOS 重置了 iAP2 链路") }
                    if packet.control & 0x80 != 0 {
                        guard packet.payload.count >= 13 else { throw ProtocolError.malformed("iAP2 SYN 长度不足") }
                        session = packet.payload[packet.payload.startIndex + 10]
                        linked = true; try ack(); stage("本机 iAP2 链路已连接，正在等待配件认证")
                        continue
                    }
                    guard linked, packet.session == session, !packet.payload.isEmpty else { continue }
                    try ack()
                    if lastPayloadSequence == packet.sequence { continue }
                    lastPayloadSequence = packet.sequence
                    guard messageBytes.count + packet.payload.count <= 65535 else { throw ProtocolError.limitExceeded("iAP2 控制消息重组") }
                    messageBytes.append(packet.payload)
                    while messageBytes.count >= 6 {
                        let count = Int(messageBytes[messageBytes.startIndex + 2]) * 256 + Int(messageBytes[messageBytes.startIndex + 3])
                        guard count >= 6 else { throw ProtocolError.malformed("控制消息长度") }
                        guard messageBytes.count >= count else { break }
                        let message = try IAP2Message.parse(Data(messageBytes.prefix(count)))
                        messageBytes = Data(messageBytes.dropFirst(count))
                        try handle(message)
                        if !active { return }
                    }
                }
            }
        } catch { finish("本机配件会话失败：\(error.localizedDescription)") }
    }
    private func handle(_ message: IAP2Message) throws {
        guard let identity, let configuration else { return }
        messagesReceived += 1
        let bytes = message.parameters.reduce(0) { $0 + $1.value.count }
        onLog?(String(format: "收到 iAP2 消息 0x%04X（%d 个参数，载荷合计 %d 字节）", message.id, message.parameters.count, bytes))
        if messagesReceived <= 2000 {
            for parameter in message.parameters {
                onLog?(String(format: "  参数 %d（0x%04X）：%d 字节 %@", parameter.id, parameter.id,
                              parameter.value.count, hexPreview(parameter.value, limit: 64)))
            }
        }
        switch message.id {
        case 0xaa00:
            try send(IAP2Message(id: 0xaa01, parameters: [IAP2Parameter(id: 0, value: identity.certificateChain)]))
        case 0xaa02:
            guard let challenge = message.parameters.first(where: { $0.id == 0 })?.value else { throw ProtocolError.malformed("缺少认证挑战") }
            try send(IAP2Message(id: 0xaa03, parameters: [IAP2Parameter(id: 0, value: identity.sign(challenge: challenge))]))
        case 0xaa04: finish("iOS 拒绝了配件认证（0xAA04）")
        case 0xaa05:
            authenticated = true; stage("iOS 已接受配件认证")
            // iAP2 层认证刚通过：此刻 CoreAccessories 的连接级认证状态是最关键的证据，
            // 也是自证实验（把连接标成已认证）的最佳时机。
            transport.dumpConnectionState("iAP2 认证通过后")
            if experimentAccSelfAuth { transport.attemptSelfAuthentication() }
        case 0x1d00: try send(AccessoryMessages.identification(name: configuration.name, deviceID: configuration.deviceID,
                                                              wifiOnly: experimentWifiOnly))
        case 0x1d02:
            identified = true; stage("iOS 已接受配件识别，正在等待 CarPlay 可用通知")
            // 日志里端点属性 iAP2_Initialized 一直是 <null>：补一次显式写入，
            // 看 CoreAccessories 接受、拒绝还是忽略——三种结果都是证据。
            if experimentEndpointInitSelf {
                let accepted = transport.setEndpointProperty("iAP2_Initialized", value: true)
                onLog?("端点属性自填 · iAP2_Initialized=true 调用\(accepted ? "完成" : "未发出")")
                transport.dumpConnectionState("端点 iAP2_Initialized 自填后")
            }
        case 0x1d03:
            let rejected = message.parameters.map { String(format: "%04X:%@", $0.id, $0.value.prefix(32).map { String(format: "%02X", $0) }.joined()) }.joined(separator: ",")
            finish("iOS 拒绝了配件识别（0x1D03）：\(rejected)")
        case 0x4300:
            guard authenticated, identified else { throw ProtocolError.malformed("认证或识别完成前收到 CarPlay 可用通知") }
            var transports: [(type: UInt8, identifier: String)] = []
            for group in message.parameters {
                let nested = try IAP2Parameter.parse(group.value)
                if let value = nested.first(where: { $0.id == 0 })?.value.first {
                    let fields = nested.map { "\($0.id)=\($0.value.count)字节/\(hexPreview($0.value, limit: 32))" }
                        .joined(separator: "；")
                    onLog?("CarPlay 可用传输 \(group.id)：type=\(value)（\(fields)）")
                    if let identifier = nested.first(where: { $0.id == 1 })?.value,
                       let text = String(data: identifier, encoding: .utf8) {
                        transports.append((value, text.trimmingCharacters(in: CharacterSet(charactersIn: "\0"))))
                    }
                }
            }
            availableTransports = transports
            if !transports.isEmpty {
                onLog?("0x4300 系统生成标识：\(transports.map { "type=\($0.type)/\($0.identifier)" }.joined(separator: "，"))")
            }
            transport.dumpConnectionState("收到 0x4300 后")
            if controlConnected || (!expectsLocalControl && requested) {
                onLog?("0x4300：已有控制连接或已请求过会话，跳过重复 0x4301（控制连接=\(controlConnected)）")
                return
            }
            try requestSession(configuration)
            if !requested {
                // 0x4301 被系统受理后属性表是否变化，是“谁消费了启动请求”的直接证据。
                let run = generation
                DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self] in
                    guard let self, self.active, self.generation == run else { return }
                    self.transport.dumpConnectionState("首个 0x4301 后 5 秒")
                }
            }
            if !requested && expectsLocalControl {
                let run = generation
                for delay in [3.0, 6.0, 9.0] {
                    DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
                        guard let self, self.active, self.generation == run, !self.controlConnected else { return }
                        do { try self.requestSession(configuration) }
                        catch { self.finish("会话重试失败：\(error)") }
                    }
                }
            }
            requested = true
            stage(expectsLocalControl
                ? "已请求在 \(configuration.address):\(configuration.port) 启动 CarPlay，会话正在等待 TCP 连接"
                : "已向 \(configuration.name)（\(configuration.address):\(configuration.port)）请求 CarPlay。请保持此 App 运行并查看 iPad 画面。")
        default: onLog?(String(format: "未处理的配件消息 0x%04X", message.id))
        }
    }
}

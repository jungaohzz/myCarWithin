#import "DirectAccessoryTransport.h"
#import <TargetConditionals.h>
#import <malloc/malloc.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <xpc/xpc.h>
#import <libproc.h>
#import <sys/sysctl.h>

/// Delegate callbacks we explicitly implement. Parameters are declared as `void *` on purpose:
/// the caller retains object arguments for the duration of the call, while integer arguments
/// stay small register values, so DescribeArgument can tell them apart without ever
/// retaining or releasing a value ARC does not own.
@interface ACCDelegateTrampoline : NSObject
@property(nonatomic, copy) void (^onLog)(NSString *message);
@end

static NSString *DescribeArgument(void *pointer) {
    uintptr_t raw = (uintptr_t)pointer;
    if (raw == 0) return @"nil";
    if (raw < 0x10000) return [NSString stringWithFormat:@"数值 %lu", (unsigned long)raw];
    if (malloc_size((const void *)raw) == 0) {
        // Not a heap allocation: tagged pointers and stack values land here.
        return [NSString stringWithFormat:@"非堆指针 %lu", (unsigned long)raw];
    }
    @try {
        NSString *text = [NSString stringWithFormat:@"%@", (__bridge id)pointer];
        return text.length > 320 ? [text substringToIndex:320] : text;
    } @catch (NSException *exception) {
        return [NSString stringWithFormat:@"无法描述的堆指针 %lu", (unsigned long)raw];
    }
}

@implementation ACCDelegateTrampoline
- (void)reportLine:(NSString *)text {
    void (^block)(NSString *) = self.onLog;
    if (!block) return;
    dispatch_async(dispatch_get_main_queue(), ^{ block(text); });
}
- (void)propertiesDidChange:(void *)properties forConnectionWithUUID:(void *)uuid previousProperties:(void *)previous {
    [self reportLine:[NSString stringWithFormat:@"ACC 委托 · 连接 %@ 属性变化：%@（之前 %@）",
        DescribeArgument(uuid), DescribeArgument(properties), DescribeArgument(previous)]];
}
- (void)propertiesDidChange:(void *)properties forEndpointWithUUID:(void *)uuid previousProperties:(void *)previous connectionUUID:(void *)connection {
    [self reportLine:[NSString stringWithFormat:@"ACC 委托 · 端点 %@（连接 %@）属性变化：%@（之前 %@）",
        DescribeArgument(uuid), DescribeArgument(connection), DescribeArgument(properties), DescribeArgument(previous)]];
}
- (void)authStateDidChange:(void *)state forConnectionWithUUID:(void *)uuid previousAuthState:(void *)previous authType:(void *)type {
    [self reportLine:[NSString stringWithFormat:@"ACC 委托 · 连接 %@ 认证状态变化：%@（之前 %@，authType %@）",
        DescribeArgument(uuid), DescribeArgument(state), DescribeArgument(previous), DescribeArgument(type)]];
}
- (void)connectionIsAuthenticated:(void *)uuid {
    [self reportLine:[NSString stringWithFormat:@"ACC 委托 · connectionIsAuthenticated %@",
        DescribeArgument(uuid)]];
}
- (void)connectionWasAuthenticated:(void *)uuid {
    [self reportLine:[NSString stringWithFormat:@"ACC 委托 · connectionWasAuthenticated %@",
        DescribeArgument(uuid)]];
}
@end

@interface DirectAccessoryTransport ()
@property(nonatomic, strong) id client;
@property(nonatomic, copy) NSString *connection;
@property(nonatomic, copy) NSString *endpoint;
@property(nonatomic, strong) NSUUID *generation;
@property(nonatomic, strong) ACCDelegateTrampoline *delegateProbe;
@property(nonatomic, readwrite, copy, nullable) NSString *connectionTypeDescription;
@end

@implementation DirectAccessoryTransport
static BOOL Failed(NSError **error, NSString *message) {
    if (error) *error = [NSError errorWithDomain:@"TDSCarKit.DirectTransport" code:1
                                      userInfo:@{NSLocalizedDescriptionKey:message}];
    return NO;
}
static BOOL HasMethod(id object, NSString *name, NSUInteger arguments) {
    SEL selector = NSSelectorFromString(name);
    return [object respondsToSelector:selector] &&
           [object methodSignatureForSelector:selector].numberOfArguments == arguments + 2;
}
static Class ACCClientClass(void) {
    Class cls = NSClassFromString(@"ACCTransportClient");
    if (!cls) {
        [[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/CoreAccessories.framework"] load];
        cls = NSClassFromString(@"ACCTransportClient");
    }
    return cls;
}
+ (NSString *)apiSummary {
    @try {
        Class cls = ACCClientClass();
        if (!cls) return @"ACCTransportClient 不可用";
        NSMutableArray<NSString *> *names = [NSMutableArray arrayWithObject:@"类方法:"];
        unsigned int count = 0;
        Method *methods = class_copyMethodList(object_getClass(cls), &count);
        for (unsigned int i = 0; i < count; i++) [names addObject:NSStringFromSelector(method_getName(methods[i]))];
        free(methods);
        [names addObject:@"| 实例方法:"];
        count = 0;
        methods = class_copyMethodList(cls, &count);
        for (unsigned int i = 0; i < count; i++) [names addObject:NSStringFromSelector(method_getName(methods[i]))];
        free(methods);
        return [names componentsJoinedByString:@" "];
    } @catch (NSException *exception) {
        return [NSString stringWithFormat:@"枚举异常 %@：%@", exception.name, exception.reason];
    }
}
+ (NSString *)coreAccessoriesClassSummary {
    NSMutableString *out = [NSMutableString string];
    @try {
        unsigned int imageCount = 0;
        const char **images = objc_copyImageNames(&imageCount);
        NSMutableArray<NSString *> *loaded = [NSMutableArray array];
        char *coreImage = NULL;
        for (unsigned int i = 0; images && i < imageCount; i++) {
            NSString *path = @(images[i]);
            NSString *lower = path.lowercaseString;
            if ([lower containsString:@"car"] || [lower containsString:@"air"]
                || [lower containsString:@"accessor"] || [lower containsString:@"iap"])
                [loaded addObject:path.lastPathComponent];
            if (!coreImage && [lower containsString:@"coreaccessories.framework/coreaccessories"])
                coreImage = strdup(images[i]);
        }
        if (images) free(images);
        [out appendFormat:@"本进程已加载 Car/Air/配件镜像 %lu 个：%@。",
            (unsigned long)loaded.count, [loaded componentsJoinedByString:@"，"]];
        if (!coreImage) { [out appendString:@"CoreAccessories 镜像未加载。"]; return out; }
        unsigned int classCount = 0;
        const char **names = objc_copyClassNamesForImage(coreImage, &classCount);
        free(coreImage);
        NSMutableArray<NSString *> *matched = [NSMutableArray array];
        for (unsigned int i = 0; names && i < classCount; i++) {
            NSString *name = @(names[i]);
            NSString *lower = name.lowercaseString;
            if ([lower containsString:@"car"] || [lower containsString:@"air"]
                || [lower containsString:@"session"] || [lower containsString:@"play"]
                || [lower containsString:@"transport"] || [lower containsString:@"accessor"])
                [matched addObject:name];
        }
        if (names) free(names);
        [out appendFormat:@"CoreAccessories 共 %u 个类，命名相关的 %lu 个：%@。",
            classCount, (unsigned long)matched.count,
            [[matched subarrayWithRange:NSMakeRange(0, MIN(matched.count, (NSUInteger)40))] componentsJoinedByString:@"，"]];
        unsigned int dumped = 0;
        for (NSString *name in matched) {
            if (dumped >= 3) break;
            if (!([name.lowercaseString containsString:@"play"] || [name.lowercaseString containsString:@"session"])) continue;
            Class cls = NSClassFromString(name);
            if (!cls) continue;
            unsigned int methodCount = 0;
            Method *methods = class_copyMethodList(cls, &methodCount);
            NSMutableArray<NSString *> *selectors = [NSMutableArray array];
            for (unsigned int i = 0; methods && i < methodCount && i < 30; i++)
                [selectors addObject:NSStringFromSelector(method_getName(methods[i]))];
            if (methods) free(methods);
            [out appendFormat:@"%@ 方法：%@。", name, [selectors componentsJoinedByString:@" "]];
            dumped++;
        }
    } @catch (NSException *exception) {
        [out appendFormat:@"类枚举异常 %@：%@", exception.name, exception.reason];
    }
    return out;
}
+ (NSArray<NSDictionary<NSString *, id> *> *)processSnapshot {
    NSMutableArray<NSDictionary<NSString *, id> *> *rows = [NSMutableArray array];
    int capacity = 4096;
    pid_t *pids = calloc((size_t)capacity, sizeof(pid_t));
    if (!pids) return rows;
    int bytes = proc_listpids(PROC_ALL_PIDS, 0, pids, capacity * (int)sizeof(pid_t));
    int count = bytes / (int)sizeof(pid_t);
    for (int i = 0; i < count; i++) {
        pid_t pid = pids[i];
        if (pid <= 0) continue;
        char name[64] = {0};
        char path[4096] = {0};
        proc_name(pid, name, sizeof(name));
        proc_pidpath(pid, path, sizeof(path));
        struct proc_bsdinfo info = {0};
        NSString *started = @"?";
        if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) > 0) {
            started = [NSString stringWithFormat:@"ppid=%d uid=%u start=%llu", (int)info.pbi_ppid,
                       (unsigned int)info.pbi_uid, (unsigned long long)info.pbi_start_tvsec];
        }
        [rows addObject:@{@"pid": @(pid), @"name": name[0] ? @(name) : @"",
                          @"path": path[0] ? @(path) : @"", @"info": started}];
    }
    free(pids);
    return rows;
}
+ (NSString *)processListSummary {
    NSArray<NSDictionary<NSString *, id> *> *rows = [self processSnapshot];
    NSMutableString *out = [NSMutableString stringWithFormat:@"内核进程表共 %lu 个进程。", (unsigned long)rows.count];
    NSMutableArray<NSString *> *interesting = [NSMutableArray array];
    for (NSDictionary *row in rows) {
        NSString *text = [NSString stringWithFormat:@"%@ %@", row[@"name"], row[@"path"]].lowercaseString;
        if ([text containsString:@"car"] || [text containsString:@"play"]
            || [text containsString:@"accessor"] || [text containsString:@"iap"]
            || [text containsString:@"springboard"] || [text containsString:@"backboard"])
            [interesting addObject:[NSString stringWithFormat:@"%@(pid %@)", row[@"name"], row[@"pid"]]];
    }
    [out appendFormat:@" Car/配件/界面相关 %lu 个：%@", (unsigned long)interesting.count,
        [interesting componentsJoinedByString:@"，"]];
    return out;
}
+ (NSString *)processDetailFor:(NSArray<NSString *> *)needles {
    NSArray<NSDictionary<NSString *, id> *> *rows = [self processSnapshot];
    NSMutableArray<NSString *> *matched = [NSMutableArray array];
    for (NSDictionary *row in rows) {
        NSString *text = [NSString stringWithFormat:@"%@ %@", row[@"name"], row[@"path"]].lowercaseString;
        for (NSString *needle in needles) {
            if ([text containsString:needle.lowercaseString]) {
                [matched addObject:[NSString stringWithFormat:@"%@ pid=%@ %@ %@",
                    row[@"name"], row[@"pid"], row[@"path"], row[@"info"]]];
                break;
            }
        }
    }
    return [matched componentsJoinedByString:@"｜"];
}
+ (NSString *)ownEntitlements {
    typedef void *(*CreateFromSelf)(const void *);
    typedef void *(*CopyValue)(void *, void *, void *);
    void *security = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
    if (!security) return @"Security.framework 打不开";
    CreateFromSelf create = (CreateFromSelf)dlsym(security, "SecTaskCreateFromSelf");
    CopyValue copy = (CopyValue)dlsym(security, "SecTaskCopyValueForEntitlement");
    if (!create || !copy) { dlclose(security); return @"SecTask 符号缺失"; }
    void *task = create(NULL);
    if (!task) { dlclose(security); return @"SecTaskCreateFromSelf 返回空"; }
    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    for (NSString *key in @[@"platform-application", @"com.apple.private.security.no-sandbox",
                            @"com.apple.private.security.no-container",
                            @"com.apple.private.security.storage.Keychains",
                            @"com.apple.developer.networking.wifi-info",
                            @"com.apple.private.network.socketfilterfw"]) {
        void *value = copy(task, (__bridge void *)key, NULL);
        if (!value) { [lines addObject:[NSString stringWithFormat:@"%@=缺失", key]]; continue; }
        NSString *text = [(__bridge id)value description];
        [lines addObject:[NSString stringWithFormat:@"%@=%@", key, text]];
        CFRelease(value);
    }
    CFRelease(task);
    dlclose(security);
    return [lines componentsJoinedByString:@"，"];
}
+ (void)xpcProbe:(NSString *)service log:(void (^)(NSString *))log {
    if (service.length == 0 || !log) return;
    xpc_connection_t connection = xpc_connection_create_mach_service(service.UTF8String, NULL, 0);
    if (!connection) {
        log([NSString stringWithFormat:@"XPC 连接 · %@：创建失败", service]);
        return;
    }
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        if (event == XPC_ERROR_CONNECTION_INVALID) {
            log([NSString stringWithFormat:@"XPC 连接 · %@：连接无效（服务拒绝或不存在）", service]);
        } else if (event == XPC_ERROR_CONNECTION_INTERRUPTED) {
            log([NSString stringWithFormat:@"XPC 连接 · %@：连接中断", service]);
        } else if (xpc_get_type(event) == XPC_TYPE_ERROR) {
            const char *text = xpc_dictionary_get_string(event, XPC_ERROR_KEY_DESCRIPTION);
            log([NSString stringWithFormat:@"XPC 连接 · %@：错误事件 %s", service, text ?: "未知"]);
        } else if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
            log([NSString stringWithFormat:@"XPC 连接 · %@：收到字典回复（对端接受了空客户端）", service]);
        } else {
            log([NSString stringWithFormat:@"XPC 连接 · %@：收到非字典事件", service]);
        }
    });
    xpc_connection_resume(connection);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        pid_t pid = xpc_connection_get_pid(connection);
        log([NSString stringWithFormat:@"XPC 连接 · %@：1.5 秒后对端 pid=%d", service, (int)pid]);
        xpc_connection_cancel(connection);
    });
}
- (void)reportDiag:(NSString *)text {
    void (^block)(NSString *) = self.onDiagnostic;
    if (!block) return;
    dispatch_async(dispatch_get_main_queue(), ^{ block(text); });
}
- (BOOL)startWithIdentifier:(NSString *)identifier transportType:(NSUInteger)transportType error:(NSError **)error {
    [self stop];
    if (transportType != 1 && transportType != 2 && transportType != 3 && transportType != 8) return Failed(error, @"不支持的本机传输类型。");
#if TARGET_OS_MACCATALYST || TARGET_OS_SIMULATOR
    return Failed(error, @"This transport test requires a physical iPhone; Catalyst and Simulator are not supported.");
#else
    @try {
        Class cls = NSClassFromString(@"ACCTransportClient");
        if (!cls) {
            [[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/CoreAccessories.framework"] load];
            cls = NSClassFromString(@"ACCTransportClient");
        }
        if (!cls || !HasMethod(cls, @"sharedClient", 0))
            return Failed(error, @"CoreAccessories ACCTransportClient is unavailable on this iOS build.");
        self.client = ((id (*)(id, SEL))objc_msgSend)(cls, NSSelectorFromString(@"sharedClient"));
        NSString *create = @"createConnectionWithType:andIdentifier:";
        NSString *endpoint = @"createEndpointWithTransportType:andProtocol:andIdentifier:andDataOutHandler:forConnectionWithUUID:publishConnection:";
        if (!HasMethod(self.client, create, 2) || !HasMethod(self.client, endpoint, 6) ||
            !HasMethod(self.client, @"processIncomingData:forEndpointWithUUID:", 2) ||
            !HasMethod(self.client, @"destroyEndpointWithUUID:", 1) ||
            !HasMethod(self.client, @"destroyConnectionWithUUID:", 1)) {
            [self stop];
            return Failed(error, @"CoreAccessories transport methods are unavailable or have changed.");
        }
        // The delegate probe goes in before any connection exists, so callbacks from the very
        // first createConnection are captured. CoreAccessories calls back on its own queue.
        if (HasMethod(self.client, @"setDelegate:", 1)) {
            ACCDelegateTrampoline *trampoline = [[ACCDelegateTrampoline alloc] init];
            __weak DirectAccessoryTransport *weakSelf = self;
            trampoline.onLog = ^(NSString *message) {
                DirectAccessoryTransport *strongSelf = weakSelf;
                if (strongSelf.onDiagnostic) strongSelf.onDiagnostic(message);
            };
            self.delegateProbe = trampoline;
            ((void (*)(id, SEL, id))objc_msgSend)(self.client, NSSelectorFromString(@"setDelegate:"), trampoline);
            [self reportDiag:@"ACC 委托探针已安装（setDelegate:），本回合 CoreAccessories 的回调都会记录"];
        } else {
            [self reportDiag:@"ACC 委托探针不可用：setDelegate: 缺失"];
        }
        // The server daemon must already be running (the transport works), so this is a no-op
        // or an error; either outcome is evidence about how the client reaches the server.
        if (HasMethod(self.client, @"launchServer", 0)) {
            @try {
                ((void (*)(id, SEL))objc_msgSend)(self.client, NSSelectorFromString(@"launchServer"));
                [self reportDiag:@"已调用 launchServer（返回值类型未知，忽略）"];
            } @catch (NSException *exception) {
                [self reportDiag:[NSString stringWithFormat:@"launchServer 异常 %@", exception.name]];
            }
        }
        // Try connection type 2, then 1; the Wi-Fi endpoint uses transport type 2.
        // Which one the OS accepts is logged because iOS 15 may fall back to type 1.
        id connection = ((id (*)(id, SEL, NSUInteger, id))objc_msgSend)(self.client, NSSelectorFromString(create), 2, identifier);
        NSUInteger usedType = 2;
        if (!connection) {
            connection = ((id (*)(id, SEL, NSUInteger, id))objc_msgSend)(self.client, NSSelectorFromString(create), 1, identifier);
            usedType = 1;
        }
        if (![connection isKindOfClass:NSString.class]) {
            [self stop];
            return Failed(error, @"CoreAccessories refused the connection. This signed app may lack access to the private transport.");
        }
        self.connectionTypeDescription = usedType == 2 ? @"2" : @"1";
        self.connection = connection;
        if (self.publishExplicitly && HasMethod(self.client, @"publishConnectionWithUUID:", 1)) {
            @try {
                ((void (*)(id, SEL, id))objc_msgSend)(self.client,
                    NSSelectorFromString(@"publishConnectionWithUUID:"), self.connection);
                [self reportDiag:@"ACC 显式发布 · publishConnectionWithUUID: 已调用"];
            } @catch (NSException *exception) {
                [self reportDiag:[NSString stringWithFormat:@"ACC 显式发布 · 异常 %@", exception.name]];
            }
        }
        if (self.registerPropertyHandlers) [self installPropertyHandlers];
        self.generation = NSUUID.UUID;
        NSUUID *generation = self.generation;
        __weak DirectAccessoryTransport *weakSelf = self;
        // Transport callback signature: v32@?0@\"NSString\"8@\"NSString\"16@\"NSData\"24.
        void (^handler)(NSString *, NSString *, NSData *) = ^(NSString *a, NSString *b, NSData *data) {
            if (![data isKindOfClass:NSData.class] || data.length > 65536) return;
            NSData *copy = [data copy];
            dispatch_async(dispatch_get_main_queue(), ^{
                DirectAccessoryTransport *strongSelf = weakSelf;
                if ([strongSelf.generation isEqual:generation] && strongSelf.onData) strongSelf.onData(copy);
            });
        };
        id result = ((id (*)(id, SEL, NSUInteger, NSUInteger, id, id, id, BOOL))objc_msgSend)(
            self.client, NSSelectorFromString(endpoint), transportType, 4, nil, handler, self.connection, YES);
        if (![result isKindOfClass:NSString.class]) {
            [self stop];
            return Failed(error, @"CoreAccessories refused to publish an iAP2 endpoint.");
        }
        self.endpoint = result;
        return YES;
    } @catch (NSException *exception) {
        [self stop];
        return Failed(error, [NSString stringWithFormat:@"CoreAccessories exception: %@", exception.name]);
    }
#endif
}
- (void)dumpObjectMethod:(NSString *)name label:(NSString *)label argument:(NSString *)argument {
    if (!self.client) return;
    if (!HasMethod(self.client, name, 1)) {
        [self reportDiag:[NSString stringWithFormat:@"%@ · %@：方法不可用", label, name]];
        return;
    }
    @try {
        id result = ((id (*)(id, SEL, id))objc_msgSend)(self.client, NSSelectorFromString(name), argument);
        [self reportDiag:[NSString stringWithFormat:@"%@ · %@：%@", label, argument, DescribeArgument((__bridge void *)result)]];
    } @catch (NSException *exception) {
        [self reportDiag:[NSString stringWithFormat:@"%@ · 调用异常 %@", label, exception.name]];
    }
}
- (void)dumpSignatures {
    if (!self.client) return;
    for (NSString *name in @[@"setConnectionAuthenticated:state:",
                             @"setProperties:forConnectionWithUUID:",
                             @"setProperties:forEndpointWithUUID:",
                             @"setAccessoryInfo:forEndpointWithUUID:",
                             @"setHandler:forConnectionProperty:",
                             @"setHandler:forEndpointProperty:"]) {
        SEL selector = NSSelectorFromString(name);
        if (![self.client respondsToSelector:selector]) {
            [self reportDiag:[NSString stringWithFormat:@"ACC 方法缺失 · %@", name]];
            continue;
        }
        NSMethodSignature *signature = [self.client methodSignatureForSelector:selector];
        NSMutableString *types = [NSMutableString string];
        for (NSUInteger index = 0; index < signature.numberOfArguments; index++) {
            [types appendFormat:@"%@ ",
                [NSString stringWithUTF8String:[signature getArgumentTypeAtIndex:index] ?: "?"]];
        }
        [self reportDiag:[NSString stringWithFormat:@"ACC 签名 · %@：参数 %lu 个（%@）返回 %@",
            name, (unsigned long)signature.numberOfArguments, types,
            [NSString stringWithUTF8String:signature.methodReturnType ?: "?"]]];
    }
}
- (void)dumpConnectionState:(NSString *)tag {
    if (!self.client || !self.connection) {
        [self reportDiag:[NSString stringWithFormat:@"ACC 状态 · %@：连接不存在", tag]];
        return;
    }
    [self reportDiag:[NSString stringWithFormat:@"ACC 状态快照 · %@（连接 %@，端点 %@）", tag, self.connection, self.endpoint ?: @"无"]];
    [self dumpObjectMethod:@"identifierForConnectionWithUUID:" label:@"连接标识" argument:self.connection];
    [self dumpObjectMethod:@"propertiesForConnectionWithUUID:" label:@"连接属性" argument:self.connection];
    [self dumpObjectMethod:@"endpointUUIDsForConnectionWithUUID:" label:@"连接下端点" argument:self.connection];
    [self dumpObjectMethod:@"accessoryInfoForConnectionWithUUID:" label:@"连接配件信息" argument:self.connection];
    if (HasMethod(self.client, @"isConnectionAuthenticated:", 1)) {
        @try {
            BOOL authenticated = ((BOOL (*)(id, SEL, id))objc_msgSend)(self.client,
                NSSelectorFromString(@"isConnectionAuthenticated:"), self.connection);
            [self reportDiag:[NSString stringWithFormat:@"连接级认证 · isConnectionAuthenticated: %@",
                authenticated ? @"是" : @"否"]];
        } @catch (NSException *exception) {
            [self reportDiag:[NSString stringWithFormat:@"连接级认证 · 调用异常 %@", exception.name]];
        }
    } else {
        [self reportDiag:@"连接级认证 · isConnectionAuthenticated: 不可用"];
    }
    if (HasMethod(self.client, @"authStatusForConnectionWithUUID:authType:", 2)) {
        for (NSUInteger type = 0; type <= 7; type++) {
            @try {
                NSInteger status = ((NSInteger (*)(id, SEL, id, NSUInteger))objc_msgSend)(self.client,
                    NSSelectorFromString(@"authStatusForConnectionWithUUID:authType:"), self.connection, type);
                [self reportDiag:[NSString stringWithFormat:@"认证状态 · authType %lu → %ld", (unsigned long)type, (long)status]];
            } @catch (NSException *exception) {
                [self reportDiag:[NSString stringWithFormat:@"认证状态 · authType %lu 调用异常 %@", (unsigned long)type, exception.name]];
            }
        }
    } else {
        [self reportDiag:@"认证状态 · authStatusForConnectionWithUUID:authType: 不可用"];
    }
    if (self.endpoint.length > 0) {
        [self dumpObjectMethod:@"identifierForEndpointWithUUID:" label:@"端点标识" argument:self.endpoint];
        [self dumpObjectMethod:@"propertiesForEndpointWithUUID:" label:@"端点属性" argument:self.endpoint];
        [self dumpObjectMethod:@"accessoryInfoForEndpointWithUUID:" label:@"端点配件信息" argument:self.endpoint];
        [self dumpObjectMethod:@"connectionUUIDForEndpointWithUUID:" label:@"端点所属连接" argument:self.endpoint];
    }
    [self dumpRuntime];
    [self dumpSignatures];
}
- (NSString *)authSummary {
    if (!self.client || !self.connection) return @"ACC连接认证=无连接";
    if (!HasMethod(self.client, @"isConnectionAuthenticated:", 1)) return @"ACC连接认证=方法不可用";
    @try {
        BOOL authenticated = ((BOOL (*)(id, SEL, id))objc_msgSend)(self.client,
            NSSelectorFromString(@"isConnectionAuthenticated:"), self.connection);
        return authenticated ? @"ACC连接认证=是" : @"ACC连接认证=否";
    } @catch (NSException *exception) {
        return @"ACC连接认证=调用异常";
    }
}
- (void)attemptSelfAuthentication {
    if (!self.client || !self.connection) {
        [self reportDiag:@"ACC 自证 · 连接不存在"];
        return;
    }
    NSString *name = @"setConnectionAuthenticated:state:";
    if (!HasMethod(self.client, name, 2)) {
        [self reportDiag:@"ACC 自证 · setConnectionAuthenticated:state: 不可用"];
        return;
    }
    NSMethodSignature *signature = [self.client methodSignatureForSelector:NSSelectorFromString(name)];
    NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:signature];
    [invocation setSelector:NSSelectorFromString(name)];
    [invocation setTarget:self.client];
    [invocation retainArguments];
    NSMutableString *plan = [NSMutableString string];
    BOOL filled = YES;
    for (NSUInteger index = 2; index < signature.numberOfArguments; index++) {
        const char *type = [signature getArgumentTypeAtIndex:index];
        if (type == NULL) { filled = NO; break; }
        if (type[0] == '@') {
            void *value = (__bridge void *)self.connection;
            [invocation setArgument:&value atIndex:index];
            [plan appendString:@"对象=连接UUID "];
        } else if (strlen(type) == 1 && (type[0] == 'B' || type[0] == 'c')) {
            BOOL value = YES;
            [invocation setArgument:&value atIndex:index];
            [plan appendString:@"是(BOOL) "];
        } else if (strlen(type) == 1) {
            NSInteger value = 1;
            [invocation setArgument:&value atIndex:index];
            [plan appendString:@"1(整数) "];
        } else {
            filled = NO;
            [plan appendFormat:@"未知类型%s ", type];
        }
    }
    if (!filled) {
        [self reportDiag:[NSString stringWithFormat:@"ACC 自证 · 参数类型无法安全填充（%@），只记录签名不调用", plan]];
        return;
    }
    [self reportDiag:[NSString stringWithFormat:@"ACC 自证 · 按真实签名填参（%@）调用 setConnectionAuthenticated:state:", plan]];
    @try {
        [invocation invoke];
        [self reportDiag:[NSString stringWithFormat:@"ACC 自证 · 调用完成，随后状态：%@", [self authSummary]]];
    } @catch (NSException *exception) {
        [self reportDiag:[NSString stringWithFormat:@"ACC 自证 · 调用异常 %@，随后状态：%@", exception.name, [self authSummary]]];
    }
}
- (void)installPropertyHandlers {
    if (!self.client) return;
    __weak DirectAccessoryTransport *weakSelf = self;
    NSDictionary<NSString *, NSArray<NSString *> *> *groups = @{
        @"setHandler:forConnectionProperty:": @[@"TransportType", @"ConnectionType", @"iAP2_Initialized"],
        @"setHandler:forEndpointProperty:": @[@"iAP2_Initialized", @"CarPlayAvailable", @"CarPlayTransport"],
    };
    for (NSString *name in groups) {
        if (!HasMethod(self.client, name, 2)) {
            [self reportDiag:[NSString stringWithFormat:@"ACC 处理器 · %@ 不可用", name]];
            continue;
        }
        for (NSString *key in groups[name]) {
            void (^handler)(void *) = ^(void *value) {
                DirectAccessoryTransport *strongSelf = weakSelf;
                if (!strongSelf) return;
                dispatch_async(dispatch_get_main_queue(), ^{
                    [strongSelf reportDiag:[NSString stringWithFormat:@"ACC 处理器回调 · %@ = %@", key, DescribeArgument(value)]];
                });
            };
            @try {
                ((void (*)(id, SEL, id, id))objc_msgSend)(self.client, NSSelectorFromString(name), handler, key);
                [self reportDiag:[NSString stringWithFormat:@"ACC 处理器 · 已为 %@ 注册 %@", key, [name containsString:@"Endpoint"] ? @"端点" : @"连接"]];
            } @catch (NSException *exception) {
                [self reportDiag:[NSString stringWithFormat:@"ACC 处理器 · %@ 注册异常 %@", key, exception.name]];
            }
        }
    }
}
- (void)dumpRuntime {
    if (!self.client) return;
    @try {
        unsigned int count = 0;
        Ivar *ivars = class_copyIvarList(object_getClass(self.client), &count);
        NSMutableArray<NSString *> *names = [NSMutableArray array];
        for (unsigned int i = 0; ivars && i < count && i < 30; i++) {
            const char *name = ivar_getName(ivars[i]);
            [names addObject:name ? @(name) : @"?"];
        }
        if (ivars) free(ivars);
        [self reportDiag:[NSString stringWithFormat:@"ACC 实例变量（%u 个）：%@", count, [names componentsJoinedByString:@" "]]];
    } @catch (NSException *exception) {
        [self reportDiag:[NSString stringWithFormat:@"ACC 实例变量转储异常 %@", exception.name]];
    }
    SEL server = NSSelectorFromString(@"serverConnection");
    if ([self.client respondsToSelector:server]) {
        @try {
            id connection = ((id (*)(id, SEL))objc_msgSend)(self.client, server);
            [self reportDiag:[NSString stringWithFormat:@"ACC 服务连接 · %@", DescribeArgument((__bridge void *)connection)]];
            if (connection && [connection respondsToSelector:@selector(endpoint)]) {
                id endpoint = ((id (*)(id, SEL))objc_msgSend)(connection, NSSelectorFromString(@"endpoint"));
                [self reportDiag:[NSString stringWithFormat:@"ACC 服务连接端点 · %@", DescribeArgument((__bridge void *)endpoint)]];
            }
        } @catch (NSException *exception) {
            [self reportDiag:[NSString stringWithFormat:@"ACC 服务连接转储异常 %@", exception.name]];
        }
    }
    for (NSString *name in @[@"connectionPropertyChangeHandlers", @"endpointPropertyChangeHandlers"]) {
        SEL selector = NSSelectorFromString(name);
        if (![self.client respondsToSelector:selector]) continue;
        @try {
            id handlers = ((id (*)(id, SEL))objc_msgSend)(self.client, selector);
            [self reportDiag:[NSString stringWithFormat:@"ACC 变更处理器表 · %@：%@", name, DescribeArgument((__bridge void *)handlers)]];
        } @catch (NSException *exception) {
            [self reportDiag:[NSString stringWithFormat:@"ACC 变更处理器表 · %@ 异常 %@", name, exception.name]];
        }
    }
}
- (BOOL)writeProperty:(NSString *)key value:(id)value endpointLevel:(BOOL)endpointLevel {
    NSString *level = endpointLevel ? @"端点" : @"连接";
    if (!self.client) { [self reportDiag:[NSString stringWithFormat:@"ACC 写属性 · %@：客户端不存在", level]]; return NO; }
    if (key.length == 0) { [self reportDiag:[NSString stringWithFormat:@"ACC 写属性 · %@：键为空", level]]; return NO; }
    id target = endpointLevel ? self.endpoint : self.connection;
    if (![target isKindOfClass:NSString.class]) {
        [self reportDiag:[NSString stringWithFormat:@"ACC 写属性 · %@尚未建立（%@ = %@）", level, key, value]];
        return NO;
    }
    NSString *name = endpointLevel ? @"setProperties:forEndpointWithUUID:" : @"setProperties:forConnectionWithUUID:";
    if (!HasMethod(self.client, name, 2)) {
        [self reportDiag:[NSString stringWithFormat:@"ACC 写属性 · %@ 不可用", name]];
        return NO;
    }
    NSDictionary *properties = @{key: value ?: NSNull.null};
    @try {
        ((void (*)(id, SEL, id, id))objc_msgSend)(self.client, NSSelectorFromString(name), properties, target);
        [self reportDiag:[NSString stringWithFormat:@"ACC 写属性 · %@ %@ = %@ → 调用完成", level, key, value]];
        if (endpointLevel)
            [self dumpObjectMethod:@"propertiesForEndpointWithUUID:" label:@"写后端点属性" argument:self.endpoint];
        else
            [self dumpObjectMethod:@"propertiesForConnectionWithUUID:" label:@"写后连接属性" argument:self.connection];
        return YES;
    } @catch (NSException *exception) {
        [self reportDiag:[NSString stringWithFormat:@"ACC 写属性 · %@ 异常 %@", level, exception.name]];
        return NO;
    }
}
- (BOOL)setEndpointProperty:(NSString *)key value:(id)value {
    return [self writeProperty:key value:value endpointLevel:YES];
}
- (BOOL)setConnectionProperty:(NSString *)key value:(id)value {
    return [self writeProperty:key value:value endpointLevel:NO];
}
- (BOOL)sendData:(NSData *)data error:(NSError **)error {
    if (!self.endpoint || !self.client) return Failed(error, @"Direct transport is not open.");
    @try {
        ((void (*)(id, SEL, id, id))objc_msgSend)(self.client,
            NSSelectorFromString(@"processIncomingData:forEndpointWithUUID:"), data, self.endpoint);
        return YES;
    } @catch (NSException *exception) {
        return Failed(error, [NSString stringWithFormat:@"CoreAccessories write exception: %@", exception.name]);
    }
}
- (void)stop {
    self.generation = nil;
    @try {
        if (self.client && HasMethod(self.client, @"setDelegate:", 1))
            ((void (*)(id, SEL, id))objc_msgSend)(self.client, NSSelectorFromString(@"setDelegate:"), nil);
    } @catch (NSException *exception) { /* The probe is dropped regardless. */ }
    self.delegateProbe = nil;
    @try {
        if (self.endpoint && HasMethod(self.client, @"destroyEndpointWithUUID:", 1))
            ((void (*)(id, SEL, id))objc_msgSend)(self.client, NSSelectorFromString(@"destroyEndpointWithUUID:"), self.endpoint);
    } @catch (NSException *exception) { /* Continue cleaning up the connection. */ }
    @try {
        if (self.connection && HasMethod(self.client, @"destroyConnectionWithUUID:", 1))
            ((void (*)(id, SEL, id))objc_msgSend)(self.client, NSSelectorFromString(@"destroyConnectionWithUUID:"), self.connection);
    } @catch (NSException *exception) { /* State is cleared even when the OS refuses cleanup. */ }
    self.endpoint = nil; self.connection = nil; self.client = nil;
}
- (void)dealloc { [self stop]; }
@end

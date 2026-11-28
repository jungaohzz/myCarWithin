#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
NS_ASSUME_NONNULL_BEGIN

/// Darwin notification without <notify.h>: the iOS SDK does not publish that header to
/// Swift, and libsystem_notify only declares the entry points in it. Returns the
/// notification token, or -1 when registration failed.
int CWDarwinNotifyRegister(NSString *name, dispatch_queue_t queue, void (^handler)(void));
void CWDarwinNotifyCancel(int token);

/// Direct accessory transport. All methods and callbacks run on the main queue.
@interface DirectAccessoryTransport : NSObject
@property(nonatomic, copy, nullable) void (^onData)(NSData *data);
/// Diagnostics line from the CoreAccessories layer (delegate callbacks, properties,
/// connection-level auth state). Arrives on an arbitrary thread; hop to main before use.
@property(nonatomic, copy, nullable) void (^onDiagnostic)(NSString *message);
/// "2" or "1" once the connection exists; nil before start. Which type CoreAccessories
/// actually accepted differs across iOS versions and decides how CarPlay sees the endpoint.
@property(nonatomic, readonly, nullable) NSString *connectionTypeDescription;
/// The CoreAccessories client surface this iOS build offers, with every method name.
+ (NSString *)apiSummary;
- (BOOL)startWithIdentifier:(NSString *)identifier transportType:(NSUInteger)transportType error:(NSError **)error;
- (BOOL)sendData:(NSData *)data error:(NSError **)error;
- (void)stop;
/// Dumps connection/endpoint properties, identifiers and connection-level auth state.
/// Read-only evidence: how CoreAccessories classifies our software endpoint.
- (void)dumpConnectionState:(NSString *)tag;
/// Compact heartbeat line for the connection-level authenticated flag.
- (NSString *)authSummary;
/// Experiment: signature-guarded attempt to flip the connection-level authenticated flag.
- (void)attemptSelfAuthentication;
/// Experiment: write one endpoint property, e.g. iAP2_Initialized. Logs the result and
/// the property table before/after so a rejected write is still evidence.
- (BOOL)setEndpointProperty:(NSString *)key value:(id)value;
/// Experiment: same for a connection-level property.
- (BOOL)setConnectionProperty:(NSString *)key value:(id)value;
/// Experiment: register property change handlers for plausible CarPlay keys.
@property(nonatomic) BOOL registerPropertyHandlers;
/// Experiment: call publishConnectionWithUUID: explicitly before the endpoint exists.
@property(nonatomic) BOOL publishExplicitly;
/// Every class CoreAccessories exports, filtered to Car/Air/Session names, with
/// method lists for the interesting ones. Answers "does 15.6 even ship this logic".
+ (NSString *)coreAccessoriesClassSummary;
/// Opens a real XPC connection to a Mach service and reports handshake outcome.
/// Connecting and cancelling is side-effect free; the daemon sees a short-lived client.
+ (void)xpcProbe:(NSString *)service log:(void (^)(NSString *message))log;
/// Kernel process list via libproc. The ps/launchctl binaries are absent on iOS,
/// so this is the only way to see whether iapd/carplay-like processes run at all.
+ (NSString *)processListSummary;
/// Names and paths of processes whose name or path matches the given needles.
+ (NSString *)processDetailFor:(NSArray<NSString *> *)needles;
/// This process's own entitlements via SecTask, to confirm no-sandbox took effect.
+ (NSString *)ownEntitlements;
/// task_for_pid + remote dyld image walk: whether a running process (iapd,
/// backboardd, SpringBoard) actually loads CarPlay-ish code on this iOS build.
+ (NSString *)remoteImageListForProcessNames:(NSArray<NSString *> *)names;
/// _dyld_shared_cache_contains_path for each candidate framework path: is the
/// code even present in the OS image, independent of whether anything runs it.
+ (NSString *)sharedCacheContainment;
/// dlopen CarKit/CarPlay/CarPlayServices/CarPlayUIServices/CarAccessoryFramework and
/// enumerate their classes, dumping selectors of session-request classes, plus each
/// framework's Info.plist version and XPCService/extension entries. Answers "does
/// iOS 15.6 ship the session-request logic carplayd would run".
+ (NSString *)frameworkClassSummary;
/// Raw net.inet.tcp.pcblist snapshot: record count plus leading raw bytes,
/// because socket structs differ per OS version and hex can be decoded offline.
+ (NSString *)tcpSocketTableSummary;
/// Same for net.inet.udp.pcblist: mDNS/AirPlay discovery and AirPlay media are UDP,
/// and a UDP listener is invisible to the TCP table.
+ (NSString *)udpSocketTableSummary;
/// Keychain items in the accessory-related access groups (attributes only).
+ (NSString *)keychainSummary;
/// Create and destroy connections with types 0–5 to map which types this
/// CoreAccessories build accepts; the accepted type decides how sessions see us.
- (void)sweepConnectionTypes;
@end
NS_ASSUME_NONNULL_END

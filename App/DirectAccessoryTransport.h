#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
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
@end
NS_ASSUME_NONNULL_END

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
@end
NS_ASSUME_NONNULL_END

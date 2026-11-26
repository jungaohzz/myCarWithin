#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
/// Direct accessory transport. All methods and callbacks run on the main queue.
@interface DirectAccessoryTransport : NSObject
@property(nonatomic, copy, nullable) void (^onData)(NSData *data);
/// "2" or "1" once the connection exists; nil before start. Which type CoreAccessories
/// actually accepted differs across iOS versions and decides how CarPlay sees the endpoint.
@property(nonatomic, readonly, nullable) NSString *connectionTypeDescription;
/// The CoreAccessories client surface this iOS build offers, with every method name.
+ (NSString *)apiSummary;
- (BOOL)startWithIdentifier:(NSString *)identifier transportType:(NSUInteger)transportType error:(NSError **)error;
- (BOOL)sendData:(NSData *)data error:(NSError **)error;
- (void)stop;
@end
NS_ASSUME_NONNULL_END

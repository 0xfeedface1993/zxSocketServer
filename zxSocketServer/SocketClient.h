//
//  SocketClient.h
//  zxSocketServer
//
//  Created by virus1993 on 2016/11/25.
//  Copyright © 2016年 张玺. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "GCDAsyncSocket.h"

@interface SocketClient : NSObject <GCDAsyncSocketDelegate>
@property (nonatomic, strong) GCDAsyncSocket *socket;
@property (nonatomic, strong) NSString *ipAddress;
@property (nonatomic, strong) NSString *sessionID;
@property (nonatomic, strong) NSData *revData;
@property (nonatomic, strong) NSData *saveData;
@property (nonatomic, assign) uint32_t byteCount;
@property (nonatomic, assign) NSUInteger leftByteCount;
@property (nonatomic, assign) BOOL isNewData;
@property (nonatomic, strong) NSDate *timeStamp;
@property (nonatomic, strong) NSString *tlsKey;
@property (nonatomic, strong) NSString *firstRandomKey;
@property (nonatomic, strong) NSString *secondRandomKey;

- (instancetype)initWithSessionID:(NSString *)sessionID client:(GCDAsyncSocket *)client;
@end

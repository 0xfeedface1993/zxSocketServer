//
//  AppDelegate.m
//  zxSocketServer
//
//  Created by 张 玺 on 12-3-24.
//  Copyright (c) 2012年 张玺. All rights reserved.
//

#import "AppDelegate.h"
#import "SocketClient.h"
#import "DefinedHeader.h"

#define MethodKey @"method"
#define ParasKey @"paras"

@interface AppDelegate ()
@property (nonatomic, strong) NSMutableArray<SocketClient *> *clients;
@property (nonatomic, strong) NSTimer *socketTimer;
@end

@implementation AppDelegate
@synthesize status;
@synthesize port;
@synthesize host;
@synthesize window = _window;
@synthesize socket;

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    port.stringValue = @"54321";
    self.clients = [[NSMutableArray alloc] init];
    
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(closeTrueSocket:) name:CloseSocketNotication object:nil];
    self.socketTimer = [NSTimer scheduledTimerWithTimeInterval:10 repeats:true block:^(NSTimer *timer){
        [self clearTimer];
    }];
    [self.socketTimer fire];
}
-(void)addText:(NSString *)str
{
    status.string = [status.string stringByAppendingFormat:@"%@\n",str];
    NSLog(@"%@", str);
}
- (IBAction)listen:(id)sender {
    NSLog(@"listen");
    
    socket = [[GCDAsyncSocket alloc] initWithDelegate:self delegateQueue:dispatch_get_main_queue()];
    NSError *err = nil; 
    if(![socket acceptOnPort:[port integerValue] error:&err]) 
    { 
        [self addText:err.description];
    }   else    {
        [self addText:[NSString stringWithFormat:@"开始监听%ld端口.",(long)port.integerValue]];
    }
}

- (void)socket:(GCDAsyncSocket *)sender didAcceptNewSocket:(GCDAsyncSocket *)newSocket {
    // The "sender" parameter is the listenSocket we created.
    // The "newSocket" is a new instance of GCDAsyncSocket.
    // It represents the accepted incoming client connection.
    
    // Do server stuff with newSocket...
    [self addText:[NSString stringWithFormat:@"建立与%@的连接",newSocket.connectedHost]];

    //检测是否有session id，没有就重新设为一个新客户端
    NSString *sessionID;
    for (SocketClient *client in self.clients) {
        if ([client.socket.connectedHost isEqualToString:newSocket.connectedHost]) {
            sessionID = client.sessionID;
        }
    }
    
    if (!sessionID) {
        sessionID = [NSString stringWithFormat:@"%d", arc4random()];
    }
    
    [self.clients addObject:[[SocketClient alloc] initWithSessionID:sessionID client:newSocket]];
    
    [s readDataWithTimeout:-1 tag:0];
}

- (void)closeTrueSocket:(SocketClient *)client {
    [self.clients removeObject:client];
}

//定时清除不活动链接
- (void)clearTimer {
    NSDate *now = [NSDate date];
    NSMutableArray *array = [[NSMutableArray alloc] init];
    for (SocketClient *client in self.clients) {
        if (client.socket.isDisconnected) {
            [array addObject:client];
        }   else    {
            if ([now timeIntervalSinceDate:client.timeStamp] > SessionTimeSpace) {
                [array addObject:client];
            }
        }
    }
    
    for (SocketClient *client in array) {
        [client.socket disconnect];
        client.socket.delegate = nil;
        [self.clients removeObject:client];
        NSLog(@"清除 %@ session", client.ipAddress);
    }
    
    array = nil;
}

@end

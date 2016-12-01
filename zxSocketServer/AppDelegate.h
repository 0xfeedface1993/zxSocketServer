//
//  AppDelegate.h
//  zxSocketServer
//
//  Created by 张 玺 on 12-3-24.
//  Copyright (c) 2012年 张玺. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "GCDAsyncSocket.h"

@interface AppDelegate : NSObject <NSApplicationDelegate,GCDAsyncSocketDelegate>
{
    GCDAsyncSocket *socket;
    GCDAsyncSocket *s;
}
@property(strong)  GCDAsyncSocket *socket;


- (IBAction)listen:(id)sender;
@property (unsafe_unretained) IBOutlet NSTextView *status;
@property (unsafe_unretained) IBOutlet NSTextField *port;
@property (unsafe_unretained) IBOutlet NSTextField *host;


@property (assign) IBOutlet NSWindow *window;

@end

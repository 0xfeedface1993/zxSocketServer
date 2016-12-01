//
//  SocketClient.m
//  zxSocketServer
//
//  Created by virus1993 on 2016/11/25.
//  Copyright © 2016年 张玺. All rights reserved.
//

#import "SocketClient.h"
#import "DefinedHeader.h"
#import "RSAEncryptor.h"
#import "CCMBase64.h"
#import "CCMCryptor.h"
#import "CCMPublicKey.h"
#import "CCMKeyLoader.h"
#import "NSData+Encryption.h"
#import <CoreImage/CoreImage.h>
#import <CommonCrypto/CommonCrypto.h>

#define MethodKey @"method"
#define ParasKey @"paras"
#define RandomKey @"RandomKey"
#define MD5Key @"MD5Key"

@interface SocketClient ()
@property (nonatomic, strong) CCMCryptor *cryptor;
@end

@implementation SocketClient
- (instancetype)initWithSessionID:(NSString *)sessionID client:(GCDAsyncSocket *)client {
    self = [super init];
    if (self) {
        self.timeStamp = [NSDate date];
        self.sessionID = sessionID;
        self.socket = client;
        self.socket.delegate = self;
        self.ipAddress = client.connectedHost;
        self.cryptor = [[CCMCryptor alloc] init];
        [self.socket readDataWithTimeout:-1 tag:0];
        [self clearAllState];
    }
    return self;
}

- (void)socket:(GCDAsyncSocket *)sock didReadData:(NSData *)data withTag:(long)tag {
    if (self.isNewData) {
        self.isNewData = false;
        unsigned char fourByteArray[4];
        if (data.length > 4) {
            [data getBytes:&fourByteArray length:4];
            [self postLogPrint:[NSString stringWithFormat:@"---%@--- 4 bytes: %x %x %x %x", self.socket.connectedHost,fourByteArray[0],fourByteArray[1],fourByteArray[2],fourByteArray[3]]];
            self.byteCount = ((fourByteArray[3]<<24)&0xff000000)+((fourByteArray[2]<<16)&0xff0000)+((fourByteArray[1]<<8)&0xff00)+(fourByteArray[0] & 0xff);
            self.leftByteCount = self.byteCount;
            [self postLogPrint:[NSString stringWithFormat:@"---%@--- bytes count: %u", self.socket.connectedHost, self.byteCount]];
            NSUInteger length = data.length - 4;
            unsigned char dataArray[length];
            [data getBytes:&dataArray range:NSMakeRange(4, length)];
            self.revData = [NSData dataWithBytes:dataArray length:length];
            self.leftByteCount = self.leftByteCount - length;
            if (self.leftByteCount == 0) {
                self.isNewData = true;
                [self postLogPrint:[NSString stringWithFormat:@"---%@--- 数据接收完毕！总接受到：%u bytes", self.socket.connectedHost, self.byteCount]];
                [self resovleData:self.revData];
                [self clearRevState];
            }
        }   else    {
            self.isNewData = true;
            [self postLogPrint:[NSString stringWithFormat:@"---%@--- 数据头部不正确！头部应为：4 bytes, 接受到：%ld bytes", self.socket.connectedHost, data.length]];
            [self clearAllState];
        }
    }   else    {
        NSUInteger length = data.length;
        if (self.leftByteCount < length) {
            self.isNewData = true;
            [self postLogPrint:[NSString stringWithFormat:@"---%@--- 数据长度不正确！剩余：%ld bytes, 接受到：%ld bytes", self.socket.connectedHost, self.leftByteCount, length]];
            [self clearAllState];
        }   else    {
            unsigned char dataArray[length];
            [data getBytes:&dataArray length:length];
            NSMutableData *mutableData = [[NSMutableData alloc] initWithData:self.revData];
            [mutableData appendData:[NSData dataWithBytes:&dataArray length:length]];
            self.revData = [mutableData copy];
            self.leftByteCount = self.leftByteCount - length;
            [self postLogPrint:[NSString stringWithFormat:@"---%@--- 接受到数据：%ld bytes", self.socket.connectedHost, self.byteCount - self.leftByteCount]];
            if (self.leftByteCount == 0) {
                self.isNewData = true;
                [self postLogPrint:[NSString stringWithFormat:@"---%@--- 数据接收完毕！总接受到：%u bytes", self.socket.connectedHost, self.byteCount]];
                [self resovleData:self.revData];
                [self clearRevState];
            }
        }
    }
    [self.socket readDataWithTimeout:-1 tag:0];
}

#pragma mark - socket
- (void)clearAllState {
    self.tlsKey = nil;
    self.firstRandomKey = nil;
    self.secondRandomKey = nil;
    self.byteCount = 0;
    self.leftByteCount = 0;
    self.isNewData = true;
    self.revData = nil;
}

- (void)clearRevState {
    self.byteCount = 0;
    self.leftByteCount = 0;
    self.isNewData = true;
    self.revData = nil;
}

#pragma mark - rsa加密解密
- (NSData *)decryptRSADataWithPrivateKey:(NSData *)inputData {
    CCMPrivateKey *privateKey = [self loadPrivateKeyResource:@"private_key"];
    NSError *error;
    NSData *decryptedData = [self.cryptor decryptData:inputData
                                  withPrivateKey:privateKey
                                           error:&error];
    return decryptedData;
}

- (NSData *)encryptRSADataWithPublicKey:(NSData *)inputData {
    CCMPublicKey *publicKey = [self loadPublicKeyResource:@"public_key"];
    NSError *error;
    NSData *encryptedData = [self.cryptor encryptData:inputData withPublicKey:publicKey error:&error];
    return encryptedData;
}

- (NSData *)decryptRSADataWithPublicKey:(NSData *)inputData {
    CCMPublicKey *key = [self loadPublicKeyResource:@"public_key"];
    
    NSError *error;
    NSData *decryptedData = [self.cryptor decryptData:inputData
                                   withPublicKey:key
                                           error:&error];
    return decryptedData;
}

- (NSData *)encryptRSADataWithPrivateKey:(NSData *)inputData {
    CCMPrivateKey *key = [self loadPrivateKeyResource:@"private_key"];
    NSError *error;
    NSData *encryptedData = [self.cryptor encryptData:inputData withPrivateKey:key error:&error];
    return encryptedData;
}

- (CCMPublicKey *)loadPublicKeyResource:(NSString *)name {
    NSString *pem = [self loadPEMResource:name];
    CCMKeyLoader *keyLoader = [[CCMKeyLoader alloc] init];
    return [keyLoader loadX509PEMPublicKey:pem];
}

- (CCMPrivateKey *)loadPrivateKeyResource:(NSString *)name {
    NSString *pem = [self loadPEMResource:name];
    CCMKeyLoader *keyLoader = [[CCMKeyLoader alloc] init];
    return [keyLoader loadRSAPEMPrivateKey:pem];
}

- (NSString *)loadPEMResource:(NSString *)name {
    NSBundle *bundle = [NSBundle mainBundle];
    NSURL *url = [bundle URLForResource:name withExtension:@"pem"];
    NSAssert(url != nil, @"file not found");
    NSString *pem = [NSString stringWithContentsOfURL:url encoding:NSUTF8StringEncoding error:nil];
    return pem;
}

#pragma mark - 解析数据

- (void)resovleData:(NSData *)data {
    self.timeStamp = [NSDate date];
    if (!self.tlsKey) {
        NSData *decryptData = [self decryptRSADataWithPrivateKey:data];
        if (!self.firstRandomKey) {
            [self firstHandleShake:decryptData];
        }   else if (self.secondRandomKey) {
            [self secondHandleShake:decryptData];
        }
    }   else    {
        [self resovleJSON:data];
    }
}

- (void)resovleJSON:(NSData *)data {
    NSError *error;
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:[data AES256ParmDecryptWithKey:self.tlsKey] options:NSJSONReadingMutableLeaves error:&error];
    if (error) {
        NSLog(@"---%@--- %@", self.socket.connectedHost, error);
        NSLog(@"---%@--- 解析失败！非json对象！", self.socket.connectedHost);
    }   else    {
        NSString *method = json[MethodKey];
        NSArray *paras = json[ParasKey];
        NSMutableDictionary *mutableDic = [[NSMutableDictionary alloc] init];
        for (NSDictionary *dic in paras) {
            NSString *key = [[dic allKeys] lastObject];
            NSString *value = dic[key];
            [mutableDic setObject:value forKey:key];
        }
        NSData *encryptData = [[NSData alloc] initWithBase64EncodedString:mutableDic[@"message"] options:NSDataBase64DecodingIgnoreUnknownCharacters];
        NSData *outputData = [self decryptRSADataWithPrivateKey:encryptData];
        NSLog(@"%@", [[NSString alloc] initWithData:outputData encoding:NSUTF8StringEncoding]);
        [self replyResponse:method paras:[mutableDic copy]];
        NSLog(@"---%@--- 方法名：%@，参数：%@", self.socket.connectedHost, method, paras);
    }
}

- (void)replyResponse:(NSString *)method paras:(NSDictionary *)paras {
    method = [method stringByAppendingString:@"Result"];
    NSString *message = paras[@"message"];
    if ([message isEqualToString:@"ok"]) {
//        NSImage *image = [NSImage imageNamed:@"2345"];
//        NSData *imageData = [image TIFFRepresentation];
//        NSBitmapImageRep *imageRep = [NSBitmapImageRep imageRepWithData:imageData];
//        
//        [imageRep setSize:[image size]];
//        // png
//        NSData *imageData1= [imageRep representationUsingType:NSPNGFileType properties:@{}];
        
         [self.socket writeData:[self responseWebservice:method paras:@[@{@"result":@"ok"}]] withTimeout:-1 tag:0];
    }   else    {
         [self.socket writeData:[self responseWebservice:method paras:@[@{@"result":@"接收完成！"}, @{@"error":@"成功哥哥哥哥"}]] withTimeout:-1 tag:0];
    }
}

- (NSData *)responseWebservice:(NSString *)method paras:(NSArray<NSDictionary *> *)paras {
    NSDictionary *package = @{MethodKey:method,ParasKey:paras};
    NSData *jsonData = [[self convertToJSONData:package] AES256ParmEncryptWithKey:self.tlsKey];
    uint32_t lenght = (uint32_t)jsonData.length;
    NSData *headData = [NSData dataWithBytes:&lenght length:sizeof(uint32_t)];
    NSMutableData *fullData = [[NSMutableData alloc] initWithData:headData];
    [fullData appendData:jsonData];
    return [fullData copy];
}

- (NSData *)packageData:(NSData *)data {
    uint32_t lenght = (uint32_t)data.length;
    NSData *headData = [NSData dataWithBytes:&lenght length:sizeof(uint32_t)];
    NSMutableData *fullData = [[NSMutableData alloc] initWithData:headData];
    [fullData appendData:data];
    return [fullData copy];
}

- (NSData *)convertToJSONData:(id)infoDict
{
    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:infoDict
                                                       options:NSJSONWritingPrettyPrinted // Pass 0 if you don't care about the readability of the generated string
                                                         error:&error];
    if (! jsonData) {
        NSLog(@"Got an error: %@", error);
        return nil;
    }   else   {
        return jsonData;
    }
}

- (void)postLogPrint:(NSString *)log {
    NSLog(@"%@", log);
}

- (void)socketDidDisconnect:(GCDAsyncSocket *)sock withError:(nullable NSError *)err {
    NSLog(@"---%@--- 断开链接：%@", self.ipAddress, err);
    sock.delegate = nil;
    [[NSNotificationCenter defaultCenter] postNotificationName:CloseSocketNotication object:self];
}

#pragma mark - 第一次握手
- (void)firstHandleShake:(NSData *)data {
    NSError *error;
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableLeaves error:&error];
    if (error) {
        NSLog(@"---%@--- %@", self.socket.connectedHost, error);
        NSLog(@"---%@--- 解析失败！非json对象！", self.socket.connectedHost);
    }   else    {
        NSString *firstKeyString = json[RandomKey];
        if (firstKeyString && ![firstKeyString isEqualToString:@""]) {
            self.firstRandomKey = firstKeyString;
            uint32_t randomNumer = (uint32_t)fabsf((float)arc4random());
            self.secondRandomKey = [NSString stringWithFormat:@"%u", randomNumer];
            NSDictionary *dic = @{RandomKey:self.secondRandomKey, MD5Key:[self encryptString:[NSString stringWithFormat:@"%@", self.firstRandomKey]]};
            NSData *data = [self convertToJSONData:dic];
            if (data) {
                NSData *encodeData = [self encryptRSADataWithPrivateKey:data];
                [self.socket writeData:[self packageData:encodeData] withTimeout:-1 tag:0];
            }   else    {
                NSLog(@"---转换json失败---");
                [self clearAllState];
            }
        } else {
            NSLog(@"---第一次握手---客户端验证密钥无效---");
            [self clearAllState];
        }
    }
    
}

#pragma mark - 第二次握手
- (void)secondHandleShake:(NSData *)decodeData {
    NSError *error;
    NSDictionary *dic = [NSJSONSerialization JSONObjectWithData:decodeData options:NSJSONReadingMutableLeaves error:&error];
    if (!error) {
        NSString *md5String = dic[MD5Key];
        NSString *str = [NSString stringWithFormat:@"%@%@", self.firstRandomKey, self.secondRandomKey];
        if ([[self encryptString:str] isEqualToString:md5String]) {
            NSDictionary *dicx = @{MD5Key:[self encryptString:[self encryptString:str]]};
            NSData *data = [NSJSONSerialization dataWithJSONObject:dicx options:NSJSONWritingPrettyPrinted error:&error];
            if (!error) {
                self.tlsKey = str;
                NSData *encodeData = [self encryptRSADataWithPrivateKey:data];
                [self.socket writeData:[self packageData:encodeData] withTimeout:-1 tag:0];
            }   else    {
                NSLog(@"%@", error);
                [self clearAllState];
            }
        }   else    {
            NSLog(@"---第二次握手---客户端验证密钥失败---");
            [self clearAllState];
        }
    }   else    {
        NSLog(@"%@", error);
        [self clearAllState];
    }
    
}

#pragma mark - 加密字符串

- (NSString *)encryptString:(NSString *)str {
    return [self sha1:[self md5:str]];
}

- (NSString *)md5:(NSString *)input {
    const char *cStr = [input UTF8String];
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5( cStr, (CC_LONG)strlen(cStr), digest ); // This is the md5 call
    
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x", digest[i]];
    
    NSLog(@"---MD5--- %@", output);
    return  output;
}

- (NSString*)sha1:(NSString *)input {
    const char *cstr = [input cStringUsingEncoding:NSUTF8StringEncoding];
    
    NSData *data = [NSData dataWithBytes:cstr length:input.length];
    //使用对应的CC_SHA1,CC_SHA256,CC_SHA384,CC_SHA512的长度分别是20,32,48,64
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    //使用对应的CC_SHA256,CC_SHA384,CC_SHA512
    CC_SHA1(data.bytes, (unsigned int)data.length, digest);
    
    NSMutableString* output = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x", digest[i]];
    
    return output;
}

@end

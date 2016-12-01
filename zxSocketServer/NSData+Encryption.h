//
//  AES256Encoder.h
//  zxSocket
//
//  Created by virus1993 on 2016/11/26.
//  Copyright © 2016年 张玺. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSData (Encryption)

- (NSData *)AES256ParmEncryptWithKey:(NSString *)key;   //加密
- (NSData *)AES256ParmDecryptWithKey:(NSString *)key;   //解密

@end

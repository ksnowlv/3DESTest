//
//  ViewController.m
//  3DESTest
//
//  Created by lv wei on 13-4-22.
//  Copyright (c) 2013年 lv wei. All rights reserved.
//

#import "ViewController.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonHMAC.h>

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
	// Do any additional setup after loading the view, typically from a nib.
    NSString* key = @"my little pang bao!";
    NSString* content = @"五一回家休息几天啊，好好出去转转玩玩!";
    
    NSData* encryptData = [self AESEncrypt:[content dataUsingEncoding:NSUTF8StringEncoding] withKey:key];
    printf("encryptData = %s\n",[encryptData description].UTF8String);
    
    NSData* decryptData = [self AESDecrypt:encryptData withKey:key];
    NSString* utf8String = [[NSString alloc] initWithData:decryptData encoding:NSUTF8StringEncoding];
    NSLog(@"decryptData = %@",utf8String);
    [utf8String release];
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (NSData *) AESEncrypt:(NSData *)srcData withKey:(NSString*)key{
    
    char keyPtr[kCCKeySize3DES+1]; // room for terminator (unused)
    bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
    
    // fetch key data
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [srcData length];
    
    size_t buffer_size           = dataLength + kCCBlockSize3DES;
    void* buffer                 = malloc(buffer_size);
    size_t num_bytes_encrypted   = 0;

    CCCryptorStatus crypt_status = CCCrypt(kCCEncrypt, kCCAlgorithm3DES, kCCOptionPKCS7Padding,
                                           keyPtr, kCCKeySize3DES,
                                           NULL,
                                           [srcData bytes], dataLength,
                                           buffer, buffer_size,
                                           &num_bytes_encrypted);
    
    if (crypt_status == kCCSuccess){
        NSLog(@"~~ encrypt data successfully...");
        return [NSData dataWithBytesNoCopy:buffer length:num_bytes_encrypted];
    }
    
    free(buffer); //free the buffer;
    return nil;
    
}

- (NSData *) AESDecrypt:(NSData *)srcData withKey:(NSString*)key{
    char keyPtr[kCCKeySize3DES+1]; // room for terminator (unused)
    bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
    
    // fetch key data
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger data_length= [srcData length];
    
    size_t buffer_size           = data_length + kCCBlockSize3DES;
    void* buffer                 = malloc(buffer_size);
    size_t num_bytes_decrypted   = 0;
    
    
    CCCryptorStatus crypt_status = CCCrypt(kCCDecrypt, kCCAlgorithm3DES, kCCOptionPKCS7Padding,
                                           keyPtr, kCCKeySize3DES,
                                           NULL /* initialization vector (optional) */,
                                           [srcData bytes], data_length, /* input */
                                           buffer, buffer_size, /* output */
                                           &num_bytes_decrypted);
    
    if (crypt_status == kCCSuccess){
        NSLog(@"decrypt data successfully...");
        return [NSData dataWithBytesNoCopy:buffer length:num_bytes_decrypted];
    }
    
    free(buffer); //free the buffer;
    return nil;
}

@end

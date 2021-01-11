//
//  FishhookDemo.m
//  foundemo
//
//  Created by 贾晓滨 on 2020/12/24.
//

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import "fishhook.h"

static void (* oNSLog)(NSString *format, ...);
void nNSLog(NSString *format, ...){
    oNSLog(@"%@", [format stringByAppendingString:@"被HOOK了"]);
}

void hookNSLog(){
    struct rebinding nsLog;
    nsLog.name = "NSLog";// 指定要hook的C函数名
    nsLog.replacement = nNSLog; // 指定要hook到的方法
    nsLog.replaced = (void *)&oNSLog; // 指定原方法的替身
    struct rebinding rebinds[1] = { nsLog };
    rebind_symbols(rebinds, 1);
}

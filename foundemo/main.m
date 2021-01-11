//
//  main.m
//  foundemo
//
//  Created by 贾晓滨 on 2020/12/23.
//

#import <Foundation/Foundation.h>
#import "FishhookDemo.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // insert code here...
        NSLog(@"Hello, World!");
        
        hookNSLog();
        
        NSLog(@"Hello, World2!");
    }
    return 0;
}

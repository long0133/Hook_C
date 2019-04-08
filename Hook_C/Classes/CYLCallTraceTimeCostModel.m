//
//  CYLCallTraceTimeCostModel.m
//  Apex
//
//  Created by gary on 2019/4/8.
//  Copyright © 2019 Gary. All rights reserved.
//

#import "CYLCallTraceTimeCostModel.h"
#import "CYLHookCore.h"

@implementation CYLCallTraceTimeCostModel
- (NSString *)des {
    NSMutableString *str = [NSMutableString new];
    [str appendFormat:@"%2d| ",(int)_callDepth];
    [str appendFormat:@"%6.2f|",_timeCost * 1000.0];
    for (NSUInteger i = 0; i < _callDepth; i++) {
        [str appendString:@"  "];
    }
    [str appendFormat:@"%s[%@ %@]", (_isClassMethod ? "+" : "-"), _className, _methodName];
    return str;
}

+ (void)printCallTrace:(NSArray<CYLCallTraceTimeCostModel *>*)arr{
    if (arr) {
        for (CYLCallTraceTimeCostModel *model in arr) {
            NSLog(@"%@",[model des]);
            [self printCallTrace:model.subCosts];
        }
    }
}

+ (NSArray<CYLCallTraceTimeCostModel *>*)loadRecords {
    NSMutableArray<CYLCallTraceTimeCostModel *> *arr = [NSMutableArray new];
    int num = 0;
    smCallRecord *records = smGetCallRecords(&num);
    for (int i = 0; i < num; i++) {
        smCallRecord *rd = &records[i];
        CYLCallTraceTimeCostModel *model = [CYLCallTraceTimeCostModel new];
        model.className = NSStringFromClass(rd->cls);
        model.methodName = NSStringFromSelector(rd->sel);
        model.isClassMethod = class_isMetaClass(rd->cls);
        model.timeCost = (double)rd->time / 1000000.0;
        model.callDepth = rd->depth;
        [arr addObject:model];
    }
    NSUInteger count = arr.count;
    for (NSUInteger i = 0; i < count; i++) {
        CYLCallTraceTimeCostModel *model = arr[i];
        if (model.callDepth > 0) {
            [arr removeObjectAtIndex:i];
            //Todo:不需要循环，直接设置下一个，然后判断好边界就行
            for (NSUInteger j = i; j < count - 1; j++) {
                //下一个深度小的话就开始将后面的递归的往 sub array 里添加
                if (arr[j].callDepth + 1 == model.callDepth) {
                    NSMutableArray *sub = (NSMutableArray *)arr[j].subCosts;
                    if (!sub) {
                        sub = [NSMutableArray new];
                        arr[j].subCosts = sub;
                    }
                    [sub insertObject:model atIndex:0];
                }
            }
            i--;
            count--;
        }
    }
    return arr;
}
@end

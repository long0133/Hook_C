//
//  CYLHookCore.h
//  Hook_C
//
//  Created by gary on 2019/4/2.
//  Copyright © 2019 yulin chi. All rights reserved.
//

#ifndef CYLHookCore_h
#define CYLHookCore_h
#include <stdio.h>

struct rebinding {
    char *name;
    void *replacement;
    void **replaced;
};

typedef struct {
    __unsafe_unretained Class cls;
    SEL sel;
    uint64_t time;
    int depth;
} smCallRecord;


typedef struct rebinding rebinding_t;

void cyl_hook_start(rebinding_t rebindings[], size_t rebinding_nel);
void CallTraceTrackStart(void);
void CallTraceTrackStop(void);

smCallRecord *smGetCallRecords(int *num); //获取调用记录
void set_min_cost_time(uint64_t us);
void set_max_depth(int max_depth);

#endif /* CYLHookCore_h */

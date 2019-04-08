//
//  CYLHookCore.c
//  Hook_C
//
//  Created by gary on 2019/4/2.
//  Copyright © 2019 yulin chi. All rights reserved.
//

#include "CYLHookCore.h"
#ifdef __aarch64__

#include <stddef.h>
#include <stdint.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <dispatch/dispatch.h>

#pragma mark - rebinding
/*结构体*/
struct rebinding_entry{
    rebinding_t *rebindings;
    size_t rebinding_nel;
    struct rebinding_entry *next;
};

static struct rebinding_entry * _rebindings_head;
#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST  "__DATA_CONST"
#endif

typedef struct segment_command_64 segment_command_t;
typedef struct mach_header_64 mach_header_t;
typedef struct nlist_64 nlist_t;
typedef struct section_64 section_t;

/*函数声明*/
static int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel);
static int prepend_rebindings(struct rebinding_entry **head, rebinding_t rebindings[], size_t nel);
static void dyld_rebinding_symbol_for_image(const struct mach_header *mach_header, intptr_t slide);
static void rebinding_symbol_for_image(struct rebinding_entry *rebindings, const struct mach_header *mach_header, intptr_t slide);
static void perform_rebinding_with_section(struct rebinding_entry *rebindings,
                                           section_t *sect,
                                           intptr_t slide,
                                           nlist_t* symtab,
                                           char *strtab,
                                           uint32_t *indirect_symtab);


void cyl_hook_start(rebinding_t rebindings[], size_t rebinding_nel){
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        rebind_symbols(rebindings, rebinding_nel);
    });
}

static int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel){
    int retval = prepend_rebindings(&_rebindings_head, rebindings, rebindings_nel);
    if(retval < 0) return retval;
    
    //首先是遍历 dyld 里的所有的 image，取出 image header 和 slide。注意第一次调用时主要注册 callback
    if (!_rebindings_head->next) {
        _dyld_register_func_for_add_image(dyld_rebinding_symbol_for_image);
    }else{
        uint c = _dyld_image_count();
        for (uint32_t i = 0; i < c; i++) {
            dyld_rebinding_symbol_for_image(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
        }
    }
    return 0;
}

static int prepend_rebindings(struct rebinding_entry **head, rebinding_t rebindings[], size_t nel){
    
    struct rebinding_entry *new_entry = malloc(sizeof(struct rebinding_entry));
    if (!new_entry) {
        return -1;
    }
    
    new_entry->rebindings = malloc(sizeof(rebinding_t)*nel);
    if (!new_entry->rebindings) {
        free(new_entry);
        return -1;
    }
    
    memcpy(new_entry->rebindings, rebindings, sizeof(rebinding_t)*nel);
    new_entry->rebinding_nel = nel;
    new_entry->next = *head;
    *(head) = new_entry;
    return 0;
}

static void dyld_rebinding_symbol_for_image(const struct mach_header *mach_header, intptr_t slide){
    rebinding_symbol_for_image(_rebindings_head, mach_header, slide);
}

static void rebinding_symbol_for_image(struct rebinding_entry *rebindings, const struct mach_header *header, intptr_t slide){
    
    /* 共享库的信息
     typedef struct dl_info {
        const char      *dli_fname;     // Pathname of shared object
        void            *dli_fbase;     // Base address of shared object
        const char      *dli_sname;     // Name of nearest symbol
        void            *dli_saddr;     // Address of nearest symbol
     } Dl_info;
     */
    Dl_info info;
    if (dladdr(header, &info) == 0) {
        return;
    }
    
    /*寻找相关的segment command*/
    segment_command_t *cur_seg_cmd = NULL;
    segment_command_t *link_edit_seg_cmd = NULL;
    struct symtab_command *symtab_cmd = NULL; //符号表cmd(存储了符号表(nlist_64数组)的偏移值,以及str表的偏移值)
    struct dysymtab_command *dysym_cmd = NULL; //动态符号表cmd(存储了indirectsym表的偏移(这个表存储了imp对应的符号在symtab中的索引)))
    
    uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
    for (uint32_t i = 0; i < header->ncmds; i ++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (segment_command_t*)cur;
        if (cur_seg_cmd->cmd == LC_SEGMENT_64) {
            if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) {
                link_edit_seg_cmd = cur_seg_cmd;
            }
        }
        
        if (cur_seg_cmd->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command*)cur_seg_cmd;
        }
        
        if (cur_seg_cmd->cmd == LC_DYSYMTAB) {
            dysym_cmd = (struct dysymtab_command*)cur_seg_cmd;
        }
    }
    
    if (!symtab_cmd || !link_edit_seg_cmd || !dysym_cmd || !dysym_cmd->indirectsymoff) {
        return;
    }
    
    //计算镜像的基址
    uintptr_t image_base = link_edit_seg_cmd->vmaddr - link_edit_seg_cmd->fileoff + (uintptr_t)slide;
    //找到符号表与str表
    nlist_t *symtab = (nlist_t*)(image_base + symtab_cmd->symoff);
    char *strtab = (char*)(image_base + symtab_cmd->stroff);
    
    //获取indirect symbol table(一个32bits的数组,存储着symtab的索引)
    uint32_t *indirect_symtab = (uint32_t*)(image_base + dysym_cmd->indirectsymoff);
    
    /*寻找_la_symbol_ptr, _nl_symbol_ptr, 外部函数的地址放在 __DATA 段的__la_symbol_ptr */
    cur = (uintptr_t)header + sizeof(mach_header_t);
    for (uint32_t j = 0; j < header->ncmds ; j++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (segment_command_t*)cur;
        if (cur_seg_cmd->cmd == LC_SEGMENT_64) {
            if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 &&
                strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) != 0) {
                continue;
            }
            
            for (uint32_t k = 0; k < cur_seg_cmd->nsects; k++) {
                section_t *sect = (section_t*)(cur + sizeof(segment_command_t)) + k;
                
                if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) {
                    perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);
                }
                
                if ((sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
                    perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);
                }
            }
            
            break;
        }
    }
}

static void perform_rebinding_with_section(struct rebinding_entry *rebindings,
                                           section_t *sect,
                                           intptr_t slide,
                                           nlist_t* symtabs,
                                           char *strtab,
                                           uint32_t *indirect_symtab){
    
    uint32_t *indirect_sym_index = indirect_symtab + sect->reserved1; //找到在动态符号表中的index
    void **indirect_symbol_binding = (void**) ((uintptr_t)slide + sect->addr); //绑定符号指针的基址
    
    for (uint i = 0; i < sect->size / sizeof(void*); i ++) { //一条指针一条指针的遍历
        uint32_t symtab_index = indirect_sym_index[i];
        if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
            symtab_index == (INDIRECT_SYMBOL_LOCAL   | INDIRECT_SYMBOL_ABS)) {
            continue;
        }
        
        uint32_t strtab_offset = symtabs[symtab_index].n_un.n_strx;
        char *symbol_name = strtab + strtab_offset;
        if (strcmp(symbol_name, "") == 0 || strnlen(symbol_name,2) < 2) {
            continue;
        }
        
        struct rebinding_entry *cur = rebindings;
        while (cur) {
            for (uint j = 0; j < cur->rebinding_nel; j++) {
                if (strcmp(&symbol_name[1], cur->rebindings[j].name) == 0) {
                    if (cur->rebindings[j].replaced != NULL &&
                        cur->rebindings[j].replacement != indirect_symbol_binding[i]) {
                        *(cur->rebindings[j].replaced) = indirect_symbol_binding[i];
                    }
                    
                    indirect_symbol_binding[i] = cur->rebindings[j].replacement;
                    goto symbol_loop;
                }
            }
            cur = cur->next;
        }
    symbol_loop:;
    }
}

#pragma mark - CallTraceTrack
#include <sys/time.h>
#include <pthread.h>

typedef struct {
    id selfObj;
    Class cls;
    SEL cmd;
    uint64_t time;
    uintptr_t lr;
} thread_call_record; //方法调用记录的结构体

typedef struct {
    thread_call_record *stack;
    int allocated_length;
    int index;
    bool is_main_thread;
} thread_call_stack;

//声明
static bool _call_record_enabled = true; //是否可以进行记录
static pthread_key_t _thread_key;

static uint64_t _min_time_cost = 0; //us
static int _max_call_depth = 20;

static smCallRecord *_smCallRecords;
static int _smRecordNum;
static int _smRecordAlloc;

void pre_objc_msgSend(id self, SEL _cmd, intptr_t lr);
uintptr_t after_objc_msgSend(void);
static inline void push_call_record(id _self, Class _cls, SEL _cmd, uintptr_t lr);
static inline thread_call_stack* get_thread_call_stack(void);
static inline uintptr_t pop_call_record(void);

/* objc_msgSend Hook*/
#define save() \
__asm volatile ( \
"stp q6, q7, [sp, #-32]!\n" \
"stp q4, q5, [sp, #-32]!\n" \
"stp q2, q3, [sp, #-32]!\n" \
"stp q0, q1, [sp, #-32]!\n" \
"stp x8, x9, [sp, #-16]!\n" \
"stp x6, x7, [sp, #-16]!\n" \
"stp x4, x5, [sp, #-16]!\n" \
"stp x2, x3, [sp, #-16]!\n" \
"stp x0, x1, [sp, #-16]!\n" );

#define load() \
__asm volatile (\
"ldp x0, x1, [sp], #16\n" \
"ldp x2, x3, [sp], #16\n" \
"ldp x4, x5, [sp], #16\n" \
"ldp x6, x7, [sp], #16\n" \
"ldp x8, x9, [sp], #16\n" \
"ldp q0, q1, [sp], #32\n" \
"ldp q2, q3, [sp], #32\n" \
"ldp q4, q5, [sp], #32\n" \
"ldp q6, q7, [sp], #32\n" );

#define call(b, value) \
__asm volatile ("mov x12, %0\n" :: "r"(value)); \
__asm volatile (#b " x12\n");

#define ret() __asm volatile ("ret\n");

__unused static id (*orig_objc_msgSend)(id, SEL, ...);

__attribute__((__naked__))
static void hook_Objc_msgSend(){
    save();
    
    //放在x2供pre_objc_msgSend使用
    __asm volatile ("mov x2, lr\n");
    
    call(blr, &pre_objc_msgSend);

    load();
    
    call(blr, orig_objc_msgSend);
    
    save();

    call(blr, &after_objc_msgSend);

    //after_objc_msgSend的返回值在x0
    __asm volatile ("mov lr, x0\n");

    load();

    ret();
}

void pre_objc_msgSend(id self, SEL _cmd, intptr_t lr){
    push_call_record(self, object_getClass(self), _cmd, lr);
}

static inline void push_call_record(id _self, Class _cls, SEL _cmd, uintptr_t lr){
    thread_call_stack *cs = get_thread_call_stack();
    if (cs) {
        int nextIndex = (++cs->index);
        if (nextIndex >= cs->allocated_length) {
            cs->allocated_length += 64;
            cs->stack = (thread_call_record*)realloc(cs->stack, cs->allocated_length*sizeof(thread_call_record));
        }
        thread_call_record *newRecord = &cs->stack[nextIndex];
        newRecord->selfObj = _self;
        newRecord->cls = _cls;
        newRecord->cmd = _cmd;
        newRecord->lr = lr;
        if (cs->is_main_thread && _call_record_enabled) {
            struct timeval now;
            gettimeofday(&now, NULL);
            newRecord->time = (now.tv_sec % 100) * 1000000 + now.tv_usec;
        }
    }
}

static inline thread_call_stack* get_thread_call_stack(){
    thread_call_stack *cs = pthread_getspecific(_thread_key);
    if (cs == NULL || cs->allocated_length == 0) {
        cs = (thread_call_stack*)malloc(sizeof(thread_call_stack));
        cs->stack = (thread_call_record*)calloc(128, sizeof(thread_call_record));
        cs->allocated_length = 64;
        cs->index = -1;
        cs->is_main_thread = pthread_main_np();
        pthread_setspecific(_thread_key, cs);
    }
    return cs;
}

uintptr_t after_objc_msgSend() {
    return pop_call_record();
}

static inline uintptr_t pop_call_record() {
    thread_call_stack *cs = get_thread_call_stack();
    int curIndex = cs->index;
    int nextIndex = cs->index--;
    thread_call_record *pRecord = &cs->stack[nextIndex];
    
    if (cs->is_main_thread && _call_record_enabled) {
        struct timeval now;
        gettimeofday(&now, NULL);
        uint64_t time = (now.tv_sec % 100) * 1000000 + now.tv_usec;
        if (time < pRecord->time) {
            time += 100 * 1000000;
        }
        uint64_t cost = time - pRecord->time;
        if (cost > _min_time_cost && cs->index < _max_call_depth) {
            if (!_smCallRecords) {
                _smRecordAlloc = 1024;
                _smCallRecords = malloc(sizeof(smCallRecord)*_smRecordAlloc);
            }
            _smRecordNum++;
            if (_smRecordNum >= _smRecordAlloc) {
                _smRecordAlloc += 1024;
                _smCallRecords = realloc(_smCallRecords, sizeof(smCallRecord)*_smRecordAlloc);
            }
            
            smCallRecord *log = &_smCallRecords[_smRecordNum-1];
            log->cls = pRecord->cls;
            log->depth = curIndex;
            log->sel = pRecord->cmd;
            log->time = cost;
        }
    }
    return pRecord->lr;
}

static void release_thread_call_stack(void *ptr) {
    thread_call_stack *cs = (thread_call_stack *)ptr;
    if (!cs) return;
    if (cs->stack) free(cs->stack);
    free(cs);
}

void CallTraceTrackStart(){
    _call_record_enabled = true;
    pthread_key_create(&_thread_key, &release_thread_call_stack);
    cyl_hook_start((struct rebinding[1]){
        {"objc_msgSend", (void *)hook_Objc_msgSend, (void **)&orig_objc_msgSend},
    }, 1);
}

void CallTraceTrackStop() {
    _call_record_enabled = false;
}


#pragma mark - public
void set_min_cost_time(uint64_t us){
    _min_time_cost = us;
}

void set_max_depth(int max_depth){
    _max_call_depth = max_depth;
}

smCallRecord *smGetCallRecords(int *num) {
    if (num) {
        *num = _smRecordNum;
    }
    return _smCallRecords;
}
#endif

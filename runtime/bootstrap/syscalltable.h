#ifndef SYSCALLTABLE_H
#define SYSCALLTABLE_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    ULONGLONG hash;
    DWORD syscall_number;
} SyscallEntry;

#define SYSCALL_TABLE_MAX 128
extern SyscallEntry g_SyscallTable[SYSCALL_TABLE_MAX];
extern int g_SyscallCount;

#ifdef __cplusplus
}
#endif

#endif // SYSCALLTABLE_H

#ifndef CORE_H
#define CORE_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

void *MemoryAllocate(size_t size);
void MemoryFree(void *ptr);
void *MemoryReallocate(void *ptr, size_t size);

unsigned long long fnv1aHash(const char *s);
unsigned long long fnv1aWideHash(const __WCHAR_TYPE__ *s);

PLDR_DATA_TABLE_ENTRY FindInMemoryModuleByHash(unsigned long long target_hash);
PVOID FindExportByHash(PLDR_DATA_TABLE_ENTRY module, unsigned long long target_hash);
int ExtractSyscallFromNativeStub(PVOID function);

int ResolveSyscallTable(PLDR_DATA_TABLE_ENTRY ntdll);

#ifdef __cplusplus
}
#endif

#endif // CORE_H

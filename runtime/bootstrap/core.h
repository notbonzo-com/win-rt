#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

void *__bootstrap_malloc(size_t size);
void __bootstrap_free(void *ptr);
void *__bootstrap_realloc(void *ptr, size_t size);

unsigned long long __bootstrap_fnv1a_hash(const char *s);
unsigned long long __bootstrap_fnv1a_whash(const __WCHAR_TYPE__ *s);

PLDR_DATA_TABLE_ENTRY __bootstrap_find_module(unsigned long long target_hash);
PVOID __bootstrap_get_export(PLDR_DATA_TABLE_ENTRY module, unsigned long long target_hash);

void __bootstrap_print(const char* msg);
bool __bootstrap_init();

#ifdef __cplusplus
}
#endif

#endif // __BOOTSTRAP_H

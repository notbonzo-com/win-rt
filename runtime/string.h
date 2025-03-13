#ifndef STRING_H
#define STRING_H

typedef unsigned long long size_t;

void *memcpy(void *dest, const void *src, size_t n);
void *memmove(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);

size_t strlen(const char *s);
char *strcpy(char *dest, const char *src);
char *strncpy(char *dest, const char *src, size_t n);
char *strcat(char *dest, const char *src);
char *strncat(char *dest, const char *src, size_t n);
int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t n);
char *strchr(const char *s, int c);
char *strrchr(const char *s, int c);
size_t strspn(const char *s, const char *accept);
size_t strcspn(const char *s, const char *reject);
char *strstr(const char *haystack, const char *needle);

size_t wcslen(const __WCHAR_TYPE__ *s);
__WCHAR_TYPE__ *wcscpy(__WCHAR_TYPE__ *dest, const __WCHAR_TYPE__ *src);
__WCHAR_TYPE__ *wcsncpy(__WCHAR_TYPE__ *dest, const __WCHAR_TYPE__ *src, size_t n);
__WCHAR_TYPE__ *wcscat(__WCHAR_TYPE__ *dest, const __WCHAR_TYPE__ *src);
__WCHAR_TYPE__ *wcsncat(__WCHAR_TYPE__ *dest, const __WCHAR_TYPE__ *src, size_t n);
int wcscmp(const __WCHAR_TYPE__ *s1, const __WCHAR_TYPE__ *s2);
int wcsncmp(const __WCHAR_TYPE__ *s1, const __WCHAR_TYPE__ *s2, size_t n);
__WCHAR_TYPE__ *wcschr(const __WCHAR_TYPE__ *s, __WCHAR_TYPE__ c);
__WCHAR_TYPE__ *wcsrchr(const __WCHAR_TYPE__ *s, __WCHAR_TYPE__ c);
size_t wcscspn(const __WCHAR_TYPE__ *s, const __WCHAR_TYPE__ *reject);
__WCHAR_TYPE__ *wcsstr(const __WCHAR_TYPE__ *haystack, const __WCHAR_TYPE__ *needle);

int stricmp(const char *s1, const char *s2);
int strnicmp(const char *s1, const char *s2, size_t n);
int wcsicmp(const __WCHAR_TYPE__ *s1, const __WCHAR_TYPE__ *s2);
int wcsnicmp(const __WCHAR_TYPE__ *s1, const __WCHAR_TYPE__ *s2, size_t n);

int tolower(int c);
int toupper(int c);
__WCHAR_TYPE__ towlower(__WCHAR_TYPE__ c);
__WCHAR_TYPE__ towupper(__WCHAR_TYPE__ c);

#endif

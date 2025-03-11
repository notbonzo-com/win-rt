#include <string.h>

void *memcpy(void *dest, const void *src, size_t n) {
    unsigned char *d = dest;
    const unsigned char *s = src;
    while(n--) *d++ = *s++;
    return dest;
}

void *memmove(void *dest, const void *src, size_t n) {
    unsigned char *d = dest;
    const unsigned char *s = src;
    if(d < s) {
        while(n--) *d++ = *s++;
    } else if(d > s) {
        d += n;
        s += n;
        while(n--) *--d = *--s;
    }
    return dest;
}

void *memset(void *s, int c, size_t n) {
    unsigned char *p = s;
    while(n--) *p++ = (unsigned char)c;
    return s;
}

int memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *p1 = s1, *p2 = s2;
    while(n--) {
        if(*p1 != *p2) return *p1 - *p2;
        p1++;
        p2++;
    }
    return 0;
}

size_t strlen(const char *s) {
    const char *p = s;
    while(*p) p++;
    return p - s;
}

char *strcpy(char *dest, const char *src) {
    char *d = dest;
    while((*d++ = *src++));
    return dest;
}

char *strncpy(char *dest, const char *src, size_t n) {
    size_t i;
    for(i = 0; i < n; i++) {
        if(src[i] == '\0') break;
        dest[i] = src[i];
    }
    for(; i < n; i++) dest[i] = '\0';
    return dest;
}

char *strcat(char *dest, const char *src) {
    char *d = dest;
    while(*d) d++;
    while((*d++ = *src++));
    return dest;
}

char *strncat(char *dest, const char *src, size_t n) {
    char *d = dest;
    while(*d) d++;
    while(n && *src) {
        *d++ = *src++;
        n--;
    }
    *d = '\0';
    return dest;
}

int strcmp(const char *s1, const char *s2) {
    while(*s1 && *s1 == *s2) {
        s1++;
        s2++;
    }
    return (unsigned char)*s1 - (unsigned char)*s2;
}

int strncmp(const char *s1, const char *s2, size_t n) {
    while(n && *s1 && *s1 == *s2) {
        s1++;
        s2++;
        n--;
    }
    if(n == 0) return 0;
    return (unsigned char)*s1 - (unsigned char)*s2;
}

char *strchr(const char *s, int c) {
    while(*s) {
        if(*s == (char)c) return (char *)s;
        s++;
    }
    return c == '\0' ? (char *)s : 0;
}

char *strrchr(const char *s, int c) {
    const char *r = 0;
    while(*s) {
        if(*s == (char)c) r = s;
        s++;
    }
    return c == '\0' ? (char *)s : (char *)r;
}

size_t strspn(const char *s, const char *accept) {
    const char *p = s;
    while(*p) {
        const char *a = accept;
        int found = 0;
        while(*a) {
            if(*p == *a) {found = 1; break;}
            a++;
        }
        if(!found) break;
        p++;
    }
    return p - s;
}

size_t strcspn(const char *s, const char *reject) {
    const char *p = s;
    while(*p) {
        const char *r = reject;
        while(*r) {
            if(*p == *r) return p - s;
            r++;
        }
        p++;
    }
    return p - s;
}

char *strstr(const char *haystack, const char *needle) {
    if(!*needle) return (char *)haystack;
    for(; *haystack; haystack++) {
        if(*haystack == *needle) {
            const char *h = haystack, *n = needle;
            while(*h && *n && *h == *n) {h++; n++;}
            if(!*n) return (char *)haystack;
        }
    }
    return 0;
}

size_t wcslen(const __WCHAR_TYPE__ *s) {
    const __WCHAR_TYPE__ *p = s;
    while(*p) p++;
    return p - s;
}

__WCHAR_TYPE__ *wcscpy(__WCHAR_TYPE__ *dest, const __WCHAR_TYPE__ *src) {
    __WCHAR_TYPE__ *d = dest;
    while((*d++ = *src++));
    return dest;
}

__WCHAR_TYPE__ *wcsncpy(__WCHAR_TYPE__ *dest, const __WCHAR_TYPE__ *src, size_t n) {
    size_t i;
    for(i = 0; i < n; i++) {
        if(src[i] == L'\0') break;
        dest[i] = src[i];
    }
    for(; i < n; i++) dest[i] = L'\0';
    return dest;
}

__WCHAR_TYPE__ *wcscat(__WCHAR_TYPE__ *dest, const __WCHAR_TYPE__ *src) {
    __WCHAR_TYPE__ *d = dest;
    while(*d) d++;
    while((*d++ = *src++));
    return dest;
}

__WCHAR_TYPE__ *wcsncat(__WCHAR_TYPE__ *dest, const __WCHAR_TYPE__ *src, size_t n) {
    __WCHAR_TYPE__ *d = dest;
    while(*d) d++;
    while(n && *src) {
        *d++ = *src++;
        n--;
    }
    *d = L'\0';
    return dest;
}

int wcscmp(const __WCHAR_TYPE__ *s1, const __WCHAR_TYPE__ *s2) {
    while(*s1 && *s1 == *s2) {
        s1++;
        s2++;
    }
    return *s1 - *s2;
}

int wcsncmp(const __WCHAR_TYPE__ *s1, const __WCHAR_TYPE__ *s2, size_t n) {
    while(n && *s1 && *s1 == *s2) {
        s1++;
        s2++;
        n--;
    }
    if(n == 0) return 0;
    return *s1 - *s2;
}

__WCHAR_TYPE__ *wcschr(const __WCHAR_TYPE__ *s, __WCHAR_TYPE__ c) {
    while(*s) {
        if(*s == c) return (__WCHAR_TYPE__ *)s;
        s++;
    }
    return c == L'\0' ? (__WCHAR_TYPE__ *)s : 0;
}

__WCHAR_TYPE__ *wcsrchr(const __WCHAR_TYPE__ *s, __WCHAR_TYPE__ c) {
    const __WCHAR_TYPE__ *r = 0;
    while(*s) {
        if(*s == c) r = s;
        s++;
    }
    return c == L'\0' ? (__WCHAR_TYPE__ *)s : (__WCHAR_TYPE__ *)r;
}

size_t wcscspn(const __WCHAR_TYPE__ *s, const __WCHAR_TYPE__ *reject) {
    const __WCHAR_TYPE__ *p = s;
    while(*p) {
        const __WCHAR_TYPE__ *r = reject;
        while(*r) {
            if(*p == *r) return p - s;
            r++;
        }
        p++;
    }
    return p - s;
}

__WCHAR_TYPE__ *wcsstr(const __WCHAR_TYPE__ *haystack, const __WCHAR_TYPE__ *needle) {
    if(!*needle) return (__WCHAR_TYPE__ *)haystack;
    for(; *haystack; haystack++) {
        if(*haystack == *needle) {
            const __WCHAR_TYPE__ *h = haystack, *n = needle;
            while(*h && *n && *h == *n) {h++; n++;}
            if(!*n) return (__WCHAR_TYPE__ *)haystack;
        }
    }
    return 0;
}

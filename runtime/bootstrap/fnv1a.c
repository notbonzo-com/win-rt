
#define FNV_OFFSET_BASIS_64 0xcbf29ce484222325ULL
#define FNV_PRIME_64 0x100000001b3ULL

unsigned long long __bootstrap_fnv1a_hash(const char *s) {
    unsigned long long hash = FNV_OFFSET_BASIS_64;

    while (*s) {
        hash ^= (unsigned char)(*s);
        hash *= FNV_PRIME_64;
        hash &= 0xFFFFFFFFFFFFFFFF;
        s++;
    }

    return hash;
}

unsigned long long __bootstrap_fnv1a_whash(const __WCHAR_TYPE__ *s) {
    unsigned long long hash = FNV_OFFSET_BASIS_64;

    while (*s) {
        unsigned short wide_char = (unsigned short)(*s);
        unsigned char low_byte = wide_char & 0xFF;
        unsigned char high_byte = (wide_char >> 8) & 0xFF;

        hash ^= low_byte;
        hash *= FNV_PRIME_64;
        hash &= 0xFFFFFFFFFFFFFFFF;

        hash ^= high_byte;
        hash *= FNV_PRIME_64;
        hash &= 0xFFFFFFFFFFFFFFFF;

        s++;
    }

    return hash;
}

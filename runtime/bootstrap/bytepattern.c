#include <bootstrap/bytepattern.h>
#include <stdarg.h>
#include <windows.h>

BOOL bytepattern_match(const BYTE* data, size_t pattern_count, ...) {
    if (data == nullptr) return false;

    va_list args;
    va_start(args, pattern_count);

    for (size_t i = 0; i < pattern_count; i++) {
        int byte_val = va_arg(args, int);
        if (byte_val == 0x100) continue;
        if (data[i] != (BYTE) byte_val) {
            va_end(args);
            return false;
        }
    }

    va_end(args);
    return true;
}
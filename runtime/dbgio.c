#include "windows.h"
#include <dbgio.h>
#include <stdarg.h>
#include <windows.h>
#include <stddef.h>
#include <hash/ntdll.h>
#include <stdint.h>

#define DBGIO_BUF_SIZE 1024

static int itoa_base(unsigned long long value, char *out, int base, int uppercase)
{
    char digits[17] = "0123456789abcdef";
    if (uppercase) {
        char tmp[] = "0123456789ABCDEF";
        for (int i = 0; i < 16; i++) {
            digits[i] = tmp[i];
        }
        digits[16] = '\0';
    }
    char buffer[65];
    int i = 0;
    if (value == 0) {
        buffer[i++] = '0';
    } else {
        while (value) {
            buffer[i++] = digits[value % base];
            value /= base;
        }
    }
    int len = i;
    for (int j = 0; j < len; j++) {
        out[j] = buffer[len - j - 1];
    }
    out[len] = '\0';
    return len;
}

static int mini_vsnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
    int pos = 0;
    for (const char *p = fmt; *p; p++) {
        if (*p != '%') {
            if (pos < (int)(size - 1)) {
                buf[pos] = *p;
            }
            pos++;
            continue;
        }
        
        p++;
        if (!*p) break;
        if (*p == '%') {
            if (pos < (int)(size - 1)) {
                buf[pos] = '%';
            }
            pos++;
            continue;
        }

        int length_mod = 0;
        if (*p == 'l') {
            length_mod = 1;
            p++;
            if (*p == 'l') {
                length_mod = 2;
                p++;
            }
        }

        char spec = *p;
        if (spec == 'c') {
            int c = va_arg(args, int);
            if (pos < (int)(size - 1))
                buf[pos] = (char)c;
            pos++;
        } else if (spec == 's') {
            const char *str = va_arg(args, const char*);
            if (!str)
                str = "(null)";
            while (*str) {
                if (pos < (int)(size - 1))
                    buf[pos] = *str;
                pos++;
                str++;
            }
        } else if (spec == 'd') {
            char numbuf[65];
            int len_conv = 0;
            if (length_mod == 2) {
                long long num = va_arg(args, long long);
                if (num < 0) {
                    if (pos < (int)(size - 1))
                        buf[pos] = '-';
                    pos++;
                    unsigned long long unum = (unsigned long long)(-num);
                    len_conv = itoa_base(unum, numbuf, 10, 0);
                } else {
                    unsigned long long unum = (unsigned long long)num;
                    len_conv = itoa_base(unum, numbuf, 10, 0);
                }
            } else if (length_mod == 1) {
                long num = va_arg(args, long);
                if (num < 0) {
                    if (pos < (int)(size - 1))
                        buf[pos] = '-';
                    pos++;
                    unsigned long long unum = (unsigned long long)(-num);
                    len_conv = itoa_base(unum, numbuf, 10, 0);
                } else {
                    unsigned long long unum = (unsigned long long)num;
                    len_conv = itoa_base(unum, numbuf, 10, 0);
                }
            } else {
                int num = va_arg(args, int);
                if (num < 0) {
                    if (pos < (int)(size - 1))
                        buf[pos] = '-';
                    pos++;
                    unsigned long long unum = (unsigned long long)(-num);
                    len_conv = itoa_base(unum, numbuf, 10, 0);
                } else {
                    unsigned long long unum = (unsigned long long)num;
                    len_conv = itoa_base(unum, numbuf, 10, 0);
                }
            }
            for (int j = 0; j < len_conv; j++) {
                if (pos < (int)(size - 1))
                    buf[pos] = numbuf[j];
                pos++;
            }
        } else if (spec == 'u') {
            char numbuf[65];
            int len_conv = 0;
            if (length_mod == 2) {
                unsigned long long num = va_arg(args, unsigned long long);
                len_conv = itoa_base(num, numbuf, 10, 0);
            } else if (length_mod == 1) {
                unsigned long num = va_arg(args, unsigned long);
                len_conv = itoa_base(num, numbuf, 10, 0);
            } else {
                unsigned int num = va_arg(args, unsigned int);
                len_conv = itoa_base(num, numbuf, 10, 0);
            }
            for (int j = 0; j < len_conv; j++) {
                if (pos < (int)(size - 1))
                    buf[pos] = numbuf[j];
                pos++;
            }
        } else if (spec == 'x' || spec == 'X') {
            int uppercase = (spec == 'X');
            char numbuf[65];
            int len_conv = 0;
            if (length_mod == 2) {
                unsigned long long num = va_arg(args, unsigned long long);
                len_conv = itoa_base(num, numbuf, 16, uppercase);
            } else if (length_mod == 1) {
                unsigned long num = va_arg(args, unsigned long);
                len_conv = itoa_base(num, numbuf, 16, uppercase);
            } else {
                unsigned int num = va_arg(args, unsigned int);
                len_conv = itoa_base(num, numbuf, 16, uppercase);
            }
            for (int j = 0; j < len_conv; j++) {
                if (pos < (int)(size - 1))
                    buf[pos] = numbuf[j];
                pos++;
            }
        } else if (spec == 'p') {
            void *ptr = va_arg(args, void*);
            unsigned long long num = (unsigned long long)(uintptr_t)ptr;
            char numbuf[65];
            if (pos < (int)(size - 1))
                buf[pos] = '0';
            pos++;
            if (pos < (int)(size - 1))
                buf[pos] = 'x';
            pos++;
            int len_conv = itoa_base(num, numbuf, 16, 0);
            for (int j = 0; j < len_conv; j++) {
                if (pos < (int)(size - 1))
                    buf[pos] = numbuf[j];
                pos++;
            }
        } else {
            if (pos < (int)(size - 1))
                buf[pos] = '%';
            pos++;
            if (pos < (int)(size - 1))
                buf[pos] = spec;
            pos++;
        }
    }
    if (size > 0)
        buf[(pos < (int)(size - 1)) ? pos : (size - 1)] = '\0';
    return pos;
}

static void internal_write(DBGIO_STREAM stream, const char *buffer, size_t length)
{
    IO_STATUS_BLOCK iosb = {0};
    void *fileHandle = NULL;
    if (stream == DBGIO_STREAM_STDOUT)
        fileHandle = NtCurrentPeb()->ProcessParameters->StandardOutput;
    else if (stream == DBGIO_STREAM_STDERR)
        fileHandle = NtCurrentPeb()->ProcessParameters->StandardError;
    unsigned long long args[9] = {
        (unsigned long long)fileHandle,
        0ULL, 0ULL, 0ULL,
        (unsigned long long)&iosb,
        (unsigned long long)buffer,
        (unsigned long long)length,
        0ULL,
        0ULL
    };
    NTSTATUS status = CallSyscall(NtWriteFile_HASH, args);
    if (!NT_SUCCESS(status)) {
        
    }
}

void dbgio_write(DBGIO_STREAM stream, const char *buffer, size_t len)
{
    if (buffer && len)
        internal_write(stream, buffer, len);
}

int dbgio_printf(const char *fmt, ...)
{
    char buf[DBGIO_BUF_SIZE];
    va_list args;
    int n;
    va_start(args, fmt);
    n = mini_vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (n > 0) {
        size_t toWrite = (n < DBGIO_BUF_SIZE) ? n : DBGIO_BUF_SIZE - 1;
        internal_write(DBGIO_STREAM_STDOUT, buf, toWrite);
    }
    return n;
}

int dbgio_fprintf(DBGIO_STREAM stream, const char *fmt, ...)
{
    char buf[DBGIO_BUF_SIZE];
    va_list args;
    int n;
    va_start(args, fmt);
    n = mini_vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (n > 0) {
        size_t toWrite = (n < DBGIO_BUF_SIZE) ? n : DBGIO_BUF_SIZE - 1;
        internal_write(stream, buf, toWrite);
    }
    return n;
}

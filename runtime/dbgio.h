#ifndef DBGIO_H
#define DBGIO_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

typedef enum _DBGIO_STREAM {
    DBGIO_STREAM_STDOUT,
    DBGIO_STREAM_STDERR
} DBGIO_STREAM;

void dbgio_write(DBGIO_STREAM stream, const char *buffer, size_t len);
int dbgio_printf(const char *fmt, ...);
int dbgio_fprintf(DBGIO_STREAM stream, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif // DBGIO_H

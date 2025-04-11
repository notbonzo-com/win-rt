#ifndef BYTEPATTERN_H
#define BYTEPATTERN_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL bytepattern_match(const BYTE* data, size_t pattern_count, ...);

#define BYTEPATTERN_PP_NARG(...) \
         BYTEPATTERN_PP_NARG_(__VA_ARGS__, BYTEPATTERN_RSEQ_N())
#define BYTEPATTERN_PP_NARG_(...) \
         BYTEPATTERN_ARG_N(__VA_ARGS__)
#define BYTEPATTERN_ARG_N( \
          _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, \
          _11, _12, _13, _14, _15, _16, _17, _18, _19, _20, \
          _21, _22, _23, _24, _25, _26, _27, _28, _29, _30, \
          _31, _32, N, ...) N
#define BYTEPATTERN_RSEQ_N() \
         32,31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0

#define BYTEPATTERN_MATCH(data, ...) \
         bytepattern_match((data), BYTEPATTERN_PP_NARG(__VA_ARGS__), __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif // BYTEPATTERN_H

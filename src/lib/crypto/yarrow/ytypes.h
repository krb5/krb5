/* -*- Mode: C; c-file-style: "bsd" -*- */

#ifndef YTYPES_H
#define YTYPES_H

#include <limits.h>
#include <stddef.h>
#include <sys/types.h>

#ifdef WIN32
# include <winsock2.h>
#endif

#define byte unsigned char 

#define uint8 unsigned char
#define int8 signed char

#define int16 signed short
#define uint16 unsigned short

#if (ULONG_MAX > 0xFFFFFFFFUL)
#   define int32 signed int
#   define uint32 unsigned int
#   define int64 signed long
#   define uint64 unsigned long
#else
#   define int32 signed long
#   define uint32 unsigned long
#   if defined(__GNUC__)
#       define int64 signed long long
#       define uint64 unsigned long long
#   elif defined(__sgi)
#       define int64 __int64_t
#       define uint64 __uint64_t
#   elif defined(__MWERKS__)
#       define int64 signed long long
#       define uint64 unsigned long long
#   elif defined(WIN32)
#       define uint64 unsigned __int64
#   endif
#endif

#if defined(uint64)
#   define COUNTER uint64
#else
#   define COUNTER uint32
#endif

#define COUNTER_MAX ((COUNTER)0 - 1)

#endif /* YTYPES_H */

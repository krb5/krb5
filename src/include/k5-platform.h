/* Copyright 2003 Massachusetts Institute of Technology.  All rights reserved.  */
/* Platform-dependent junk.  */

#ifndef K5_PLATFORM_H
#define K5_PLATFORM_H

#if !defined(inline)
# if __STDC_VERSION__ >= 199901L
/* C99 supports inline, don't do anything.  */
# elif defined(__GNUC__)
#  define inline __inline__ /* this form silences -pedantic warnings */
# elif defined(__mips) && defined(__sgi)
#  define inline __inline /* IRIX used at MIT does inline but not c99 yet */
# elif defined(__sun) && __SUNPRO_C >= 0x540
/* The Forte Developer 7 C compiler supports "inline".  */
# elif defined(_WIN32)
#  define inline __inline
# else
#  define inline /* nothing, just static */
# endif
#endif

#include "autoconf.h"

/* 64-bit support: krb5_ui_8 and krb5_int64.

   This should move to krb5.h eventually, but without the namespace
   pollution from the autoconf macros.  */
#if defined(HAVE_STDINT_H) || defined(HAVE_INTTYPES_H)
# ifdef HAVE_STDINT_H
#  include <stdint.h>
# endif
# ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
# endif
# define INT64_TYPE int64_t
# define UINT64_TYPE uint64_t
#elif defined(_WIN32)
# define INT64_TYPE signed __int64
# define UINT64_TYPE unsigned __int64
#else /* not Windows, and neither stdint.h nor inttypes.h */
# define INT64_TYPE signed long long
# define UINT64_TYPE unsigned long long
#endif

/* Read and write integer values as (unaligned) octet strings in
   specific byte orders.

   Add per-platform optimizations later if needed.  (E.g., maybe x86
   unaligned word stores and gcc/asm instructions for byte swaps,
   etc.)  */

static inline void
store_16_be (unsigned int val, unsigned char *p)
{
    p[0] = (val >>  8) & 0xff;
    p[1] = (val      ) & 0xff;
}
static inline void
store_16_le (unsigned int val, unsigned char *p)
{
    p[1] = (val >>  8) & 0xff;
    p[0] = (val      ) & 0xff;
}
static inline void
store_32_be (unsigned int val, unsigned char *p)
{
    p[0] = (val >> 24) & 0xff;
    p[1] = (val >> 16) & 0xff;
    p[2] = (val >>  8) & 0xff;
    p[3] = (val      ) & 0xff;
}
static inline void
store_32_le (unsigned int val, unsigned char *p)
{
    p[3] = (val >> 24) & 0xff;
    p[2] = (val >> 16) & 0xff;
    p[1] = (val >>  8) & 0xff;
    p[0] = (val      ) & 0xff;
}
static inline void
store_64_be (UINT64_TYPE val, unsigned char *p)
{
    p[0] = (val >> 56) & 0xff;
    p[1] = (val >> 48) & 0xff;
    p[2] = (val >> 40) & 0xff;
    p[3] = (val >> 32) & 0xff;
    p[4] = (val >> 24) & 0xff;
    p[5] = (val >> 16) & 0xff;
    p[6] = (val >>  8) & 0xff;
    p[7] = (val      ) & 0xff;
}
static inline void
store_64_le (UINT64_TYPE val, unsigned char *p)
{
    p[7] = (val >> 56) & 0xff;
    p[6] = (val >> 48) & 0xff;
    p[5] = (val >> 40) & 0xff;
    p[4] = (val >> 32) & 0xff;
    p[3] = (val >> 24) & 0xff;
    p[2] = (val >> 16) & 0xff;
    p[1] = (val >>  8) & 0xff;
    p[0] = (val      ) & 0xff;
}
static inline unsigned short
load_16_be (unsigned char *p)
{
    return (p[1] | (p[0] << 8));
}
static inline unsigned short
load_16_le (unsigned char *p)
{
    return (p[0] | (p[1] << 8));
}
static inline unsigned int
load_32_be (unsigned char *p)
{
    return (p[3] | (p[2] << 8) | (p[1] << 16) | (p[0] << 24));
}
static inline unsigned int
load_32_le (unsigned char *p)
{
    return (p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}
static inline UINT64_TYPE
load_64_be (unsigned char *p)
{
    return ((UINT64_TYPE)load_32_be(p) << 32) | load_32_be(p+4);
}
static inline UINT64_TYPE
load_64_le (unsigned char *p)
{
    return ((UINT64_TYPE)load_32_le(p+4) << 32) | load_32_le(p);
}

#endif /* K5_PLATFORM_H */

/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#ifndef YTYPES_H
#define YTYPES_H

#include <limits.h>
#include <stddef.h>
#include "autoconf.h"
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#define byte unsigned char

#define uint8 unsigned char
#define int8 signed char


#if defined(uint64)
#   define COUNTER uint64
#else
#   define COUNTER krb5_ui_4
#endif

#define COUNTER_MAX ((COUNTER)0 - 1)

#endif /* YTYPES_H */

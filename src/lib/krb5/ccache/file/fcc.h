/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This file contains constant and function declarations used in the
 * file-based credential cache routines.
 */

#include <krb5/copyright.h>

#ifndef __KRB5_FILE_CCACHE__
#define __KRB5_FILE_CCACHE__

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include "fcc-proto.h"
#include <krb5/sysincl.h>
#include <stdio.h>

#define KRB5_OK 0

#define KRB5_FCC_MAXLEN 100

#ifndef TKT_ROOT
#define TKT_ROOT "/tmp/tkt"
#endif

/* macros to make checking flags easier */
#define OPENCLOSE(id) (((krb5_fcc_data *)id->data)->flags & KRB5_TC_OPENCLOSE)

typedef struct _krb5_fcc_data {
     char *filename;
     int fd;
     krb5_flags flags;
} krb5_fcc_data;

/* An off_t can be arbitrarily complex */
typedef struct _krb5_fcc_cursor {
     off_t pos;
} krb5_fcc_cursor;

/* DO NOT ADD ANYTHING AFTER THIS #endif */
#endif /* __KRB5_FILE_CCACHE__ */

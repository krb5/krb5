/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * This file contains constant and function declarations used in the
 * file-based credential cache routines.
 */

#include <krb5/copyright.h>

#ifndef __KRB5_FILE_CCACHE__
#define __KRB5_FILE_CCACHE__

#include <krb5/krb5.h>
#include "fcc-os.h"

/* XXX Until I find out the right #define for this.. XXX */
#define KRB5_OK 0
#define KRB5_NOMEM 1
#define KRB5_NOTFOUND 2
#define KRB5_FCC_MAXLEN 100

#ifndef TKT_ROOT
#define TKT_ROOT "/tmp/tkt"
#endif

typedef struct _krb5_fcc_data {
     char *filename;
     int fd;
} krb5_fcc_data;

/* An off_t can be arbitrarily complex */
typedef struct _krb5_fcc_cursor {
     off_t pos;
} krb5_fcc_cursor;

/* DO NOT ADD ANYTHING AFTER THIS #endif */
#endif /* __KRB5_FILE_CCACHE__ */

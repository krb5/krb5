/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * This file contains constant and function declarations used in the
 * file-based credential cache routines.
 */


#ifndef __KRB5_FILE_CCACHE__
#define __KRB5_FILE_CCACHE__

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include "scc-proto.h"
#include <krb5/sysincl.h>
#include <stdio.h>

#define KRB5_OK 0

#define KRB5_SCC_MAXLEN 100

#define KRB5_SCC_FVNO 0x0501		/* krb v5, scc v1 */

#define	SCC_OPEN_AND_ERASE	1
#define	SCC_OPEN_RDWR		2
#define	SCC_OPEN_RDONLY		3

#ifndef TKT_ROOT
#define TKT_ROOT "/tmp/tkt"
#endif

/* macros to make checking flags easier */
#define OPENCLOSE(id) (((krb5_scc_data *)id->data)->flags & KRB5_TC_OPENCLOSE)

typedef struct _krb5_scc_data {
     char *filename;
     FILE *file;
     krb5_flags flags;
     char stdio_buffer[BUFSIZ];
} krb5_scc_data;

/* An off_t can be arbitrarily complex */
typedef struct _krb5_scc_cursor {
    long pos;
} krb5_scc_cursor;

#define MAYBE_OPEN(ID, MODE) \
{									\
    if (OPENCLOSE (ID)) {						\
	krb5_error_code maybe_open_ret = krb5_scc_open_file (ID,MODE);	\
	if (maybe_open_ret) return maybe_open_ret; } }

#define MAYBE_CLOSE(ID, RET) \
{									\
    if (OPENCLOSE (ID)) {						\
	krb5_error_code maybe_close_ret = krb5_scc_close_file (ID);	\
	if (!(RET)) RET = maybe_close_ret; } }

/* DO NOT ADD ANYTHING AFTER THIS #endif */
#endif /* __KRB5_FILE_CCACHE__ */

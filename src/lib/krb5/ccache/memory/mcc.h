/*
 * lib/krb5/ccache/memory/mcc.h
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
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
 * memory-based credential cache routines.
 */

#ifndef __KRB5_MEMORY_CCACHE__
#define __KRB5_MEMORY_CCACHE__

#include "k5-int.h"
#include "mcc-proto.h"

#define KRB5_OK 0

typedef struct _krb5_mcc_link {
     struct _krb5_mcc_link *next;
     krb5_creds *creds;
} krb5_mcc_link, FAR *krb5_mcc_cursor;

typedef struct _krb5_mcc_data {
     struct _krb5_mcc_data *next;
     char *name;
     krb5_principal prin;
     krb5_mcc_cursor link;
} krb5_mcc_data;


extern krb5_mcc_data FAR *mcc_head;
#if 0
extern int krb5_cache_sessions;
#endif

#endif /* __KRB5_MEMORY_CCACHE__ */

/*
 * lib/krb5/keytab/srvtab/kts_ops.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * krb5_kts_ops
 */

#include "k5-int.h"
#include "ktsrvtab.h"

struct _krb5_kt_ops krb5_kts_ops = {
    0,
    "SRVTAB", 	/* Prefix -- this string should not appear anywhere else! */
    krb5_ktsrvtab_resolve,
    krb5_ktsrvtab_get_name, 
    krb5_ktsrvtab_close,
    krb5_ktsrvtab_get_entry,
    krb5_ktsrvtab_start_seq_get,
    krb5_ktsrvtab_get_next,
    krb5_ktsrvtab_end_get,
    0,
    0,
    0
};

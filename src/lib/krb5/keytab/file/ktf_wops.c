/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_ktf_writable_ops
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_ktf_wops_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

#include "ktfile.h"

struct _krb5_kt_ops krb5_ktf_writable_ops = {
    "WRFILE", 	/* Prefix -- this string should not appear anywhere else! */
    krb5_ktfile_wresolve,
    krb5_ktfile_get_name, 
    krb5_ktfile_close,
    krb5_ktfile_get_entry,
    krb5_ktfile_start_seq_get,
    krb5_ktfile_get_next,
    krb5_ktfile_end_get,
    krb5_ktfile_add,
    krb5_ktfile_remove,
};

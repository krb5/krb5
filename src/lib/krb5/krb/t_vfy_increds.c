/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/krb/t_vfy_increds.c - test program for krb5_verify_init_creds */
/*
 * Copyright 2011 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

/*
 * This program is intended to be run from t_vfy_increds.py.  It retrieves the
 * first credential from the default ccache and verifies it against the default
 * keytab, exiting with status 0 on successful verification and 1 on
 * unsuccessful verification.
 */

#include "k5-int.h"

int
main(int argc, char **argv)
{
    krb5_context context;
    krb5_ccache ccache;
    krb5_cc_cursor cursor;
    krb5_creds creds;

    assert(krb5_init_context(&context) == 0);

    /* Fetch the first credential from the default ccache. */
    assert(krb5_cc_default(context, &ccache) == 0);
    assert(krb5_cc_start_seq_get(context, ccache, &cursor) == 0);
    assert(krb5_cc_next_cred(context, ccache, &cursor, &creds) == 0);
    assert(krb5_cc_end_seq_get(context, ccache, &cursor) == 0);
    assert(krb5_cc_close(context, ccache) == 0);

    if (krb5_verify_init_creds(context, &creds, NULL, NULL, NULL, NULL) != 0)
        return 1;
    return 0;
}

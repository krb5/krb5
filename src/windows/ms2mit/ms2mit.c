/*
 * ms2mit.c
 *
 */
/*
 * Copyright (C) 2003 by the Massachusetts Institute of Technology.
 * All rights reserved.
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
 *
 */

#include "krb5.h"

void
main(
    int argc,
    char *argv[]
    )
{
    krb5_context kcontext;
    krb5_error_code code;
    krb5_ccache ccache=NULL;
    krb5_ccache mslsa_ccache=NULL;
    krb5_get_init_creds_opt opts;
    krb5_principal princ;

    if (code = krb5_init_context(&kcontext)) {
        com_err(argv[0], code, "while initializing kerberos library");
        exit(1);
    }
    krb5_get_init_creds_opt_init(&opts);
  
    if (code = krb5_cc_resolve(kcontext, "MSLSA:", &mslsa_ccache)) {
        com_err(argv[0], code, "while opening MS LSA ccache");
        exit(1);
    }

    if (code = krb5_cc_get_principal(kcontext, mslsa_ccache, &princ)) {
        com_err(argv[0], code, "while obtaining MS LSA principal");
        exit(1);
    }

    if (code = krb5_cc_default(kcontext, &ccache)) {
        com_err(argv[0], code, "while getting default ccache");
        exit(1);
    }
    if (code = krb5_cc_initialize(kcontext, ccache, princ)) {
        com_err (argv[0], code, "when initializing ccache");
        exit(1);
    }

    if (code = krb5_cc_copy_creds(kcontext, mslsa_ccache, ccache)) {
        com_err (argv[0], code, "while copying MS LSA ccache to default ccache");
        exit(1);
    }

    krb5_free_principal(kcontext, princ);
    krb5_cc_close(kcontext, ccache);
    krb5_cc_close(kcontext, mslsa_ccache);
    krb5_free_context(kcontext);
    return(0);
}

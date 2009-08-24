/* -*- mode: c; indent-tabs-mode: nil -*- */
/*
 * lib/gssapi/krb5/naming_exts.c
 *
 * Copyright 2009 by the Massachusetts Institute of Technology.
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
 *
 *
 */

#include <assert.h>
#include "k5-platform.h"        /* for 64-bit support */
#include "k5-int.h"          /* for zap() */
#include "gssapiP_krb5.h"
#include <stdarg.h>

krb5_error_code
kg_init_name(krb5_context context,
             krb5_principal principal,
             krb5_authdata_context ad_context,
             krb5_flags flags,
             krb5_gss_name_t *name)
{
    krb5_error_code code;

    if (principal == NULL)
        return EINVAL;

    *name = (krb5_gss_name_t)xmalloc(sizeof(krb5_gss_name_rec));
    if (*name == NULL) {
        return ENOMEM;
    }
    (*name)->princ = NULL;
    (*name)->ad_context = NULL;

    if ((flags & KG_INIT_NAME_NO_COPY) == 0) {
        code = krb5_copy_principal(context, principal, &(*name)->princ);
        if (code != 0)
            goto cleanup;

        if (ad_context != NULL) {
            code = krb5_authdata_context_copy(context,
                                              ad_context,
                                              &(*name)->ad_context);
            if (code != 0)
                goto cleanup;
        }
    } else {
        (*name)->princ = principal;
        (*name)->ad_context = ad_context;
    }

    if ((flags & KG_INIT_NAME_INTERN) &&
        !kg_save_name((gss_name_t)*name)) {
        code = G_VALIDATE_FAILED;
        goto cleanup;
    }

    code = 0;

cleanup:
    if (code != 0) {
        if (*name != NULL) {
            krb5_free_principal(context, (*name)->princ);
            krb5_authdata_context_free(context, (*name)->ad_context);
            free(*name);
            *name = NULL;
        }
    }

    return code;
}

krb5_error_code
kg_release_name(krb5_context context,
                krb5_gss_name_t *name)
{
    if (*name != NULL) {
        if ((*name)->princ != NULL)
            krb5_free_principal(context, (*name)->princ);
        if ((*name)->ad_context != NULL)
            krb5_authdata_context_free(context, (*name)->ad_context);
        free(*name);
        *name = NULL;
    }

    return 0;
}

krb5_error_code
kg_duplicate_name(krb5_context context,
                  const krb5_gss_name_t src,
                  krb5_flags flags,
                  krb5_gss_name_t *dst)
{
    return kg_init_name(context, src->princ,
                        src->ad_context, flags, dst);
}


krb5_boolean
kg_compare_name(krb5_context context,
                krb5_gss_name_t name1,
                krb5_gss_name_t name2)
{
    return krb5_principal_compare(context, name1->princ, name2->princ);
}


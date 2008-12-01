/* -*- mode: c; indent-tabs-mode: nil -*- */
/*
 * lib/gssapi/krb5/duplicate_name.c
 *
 * Copyright 1997,2007 by the Massachusetts Institute of Technology.
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
 */

#include "gssapiP_krb5.h"

OM_uint32 krb5_gss_duplicate_name(OM_uint32  *minor_status,
                                  const gss_name_t input_name,
                                  gss_name_t *dest_name)
{
    krb5_context context;
    krb5_error_code code;
    krb5_principal princ, outprinc;

    if (minor_status)
        *minor_status = 0;

    code = krb5_gss_init_context(&context);
    if (code) {
        if (minor_status)
            *minor_status = code;
        return GSS_S_FAILURE;
    }

    if (! kg_validate_name(input_name)) {
        if (minor_status)
            *minor_status = (OM_uint32) G_VALIDATE_FAILED;
        krb5_free_context(context);
        return(GSS_S_CALL_BAD_STRUCTURE|GSS_S_BAD_NAME);
    }

    princ = (krb5_principal)input_name;
    if ((code = krb5_copy_principal(context, princ, &outprinc))) {
        *minor_status = code;
        save_error_info(*minor_status, context);
        krb5_free_context(context);
        return(GSS_S_FAILURE);
    }

    if (! kg_save_name((gss_name_t) outprinc)) {
        krb5_free_principal(context, outprinc);
        krb5_free_context(context);
        *minor_status = (OM_uint32) G_VALIDATE_FAILED;
        return(GSS_S_FAILURE);
    }

    krb5_free_context(context);
    *dest_name = (gss_name_t) outprinc;
    return(GSS_S_COMPLETE);

}

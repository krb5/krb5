/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include "gssapiP_krb5.h"

krb5_error_code
kg_release_cred(krb5_context context, krb5_gss_cred_id_t cred)
{
    krb5_error_code ret = 0;

    if (cred == NULL)
        return 0;
    k5_mutex_destroy(&cred->lock);
    if (cred->ccache != NULL) {
        if (cred->destroy_ccache)
            ret = krb5_cc_destroy(context, cred->ccache);
        else
            ret = krb5_cc_close(context, cred->ccache);
    }
    if (cred->client_keytab != NULL)
        krb5_kt_close(context, cred->client_keytab);
#ifndef LEAN_CLIENT
    if (cred->keytab != NULL)
        krb5_kt_close(context, cred->keytab);
#endif /* LEAN_CLIENT */
    if (cred->rcache != NULL)
        k5_rc_close(context, cred->rcache);
    kg_release_name(context, &cred->name);
    krb5_free_principal(context, cred->acceptor_mprinc);
    krb5_free_principal(context, cred->impersonator);
    free(cred->req_enctypes);
    zapfreestr(cred->password);
    free(cred);
    return ret;
}

OM_uint32 KRB5_CALLCONV
krb5_gss_release_cred(OM_uint32 *minor_status, gss_cred_id_t *cred_handle)
{
    krb5_context context;

    *minor_status = 0;
    if (*cred_handle == GSS_C_NO_CREDENTIAL)
        return GSS_S_COMPLETE;
    *minor_status = krb5_gss_init_context(&context);
    if (*minor_status)
        return GSS_S_FAILURE;
    *minor_status = kg_release_cred(context, (krb5_gss_cred_id_t)*cred_handle);
    if (*minor_status)
        save_error_info(*minor_status, context);
    krb5_free_context(context);
    return *minor_status ? GSS_S_FAILURE : GSS_S_COMPLETE;
}

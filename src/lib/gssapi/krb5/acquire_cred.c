/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 2000, 2007-2010 by the Massachusetts Institute of Technology.
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

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "k5-int.h"
#include "gssapiP_krb5.h"
#ifdef HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#if defined(USE_KIM)
#include <kim/kim.h>
#include "kim_library_private.h"
#elif defined(USE_LEASH)
#ifdef _WIN64
#define LEASH_DLL "leashw64.dll"
#else
#define LEASH_DLL "leashw32.dll"
#endif
static void (*pLeash_AcquireInitialTicketsIfNeeded)(krb5_context,krb5_principal,char*,int) = NULL;
static HANDLE hLeashDLL = INVALID_HANDLE_VALUE;
#endif

#ifndef LEAN_CLIENT
k5_mutex_t gssint_krb5_keytab_lock = K5_MUTEX_PARTIAL_INITIALIZER;
static char *krb5_gss_keytab = NULL;

/* Heimdal calls this gsskrb5_register_acceptor_identity. */
OM_uint32
gss_krb5int_register_acceptor_identity(OM_uint32 *minor_status,
                                       const gss_OID desired_mech,
                                       const gss_OID desired_object,
                                       gss_buffer_t value)
{
    char *new = NULL, *old;
    int err;

    err = gss_krb5int_initialize_library();
    if (err != 0)
        return GSS_S_FAILURE;

    if (value->value != NULL) {
        new = strdup((char *)value->value);
        if (new == NULL)
            return GSS_S_FAILURE;
    }

    err = k5_mutex_lock(&gssint_krb5_keytab_lock);
    if (err) {
        free(new);
        return GSS_S_FAILURE;
    }
    old = krb5_gss_keytab;
    krb5_gss_keytab = new;
    k5_mutex_unlock(&gssint_krb5_keytab_lock);
    free(old);
    return GSS_S_COMPLETE;
}

/* get credentials corresponding to a key in the krb5 keytab.
   If successful, set the keytab-specific fields in cred
*/

static OM_uint32
acquire_accept_cred(krb5_context context,
                    OM_uint32 *minor_status,
                    krb5_principal desired_princ,
                    krb5_keytab req_keytab,
                    krb5_gss_cred_id_rec *cred)
{
    krb5_error_code code;
    krb5_keytab kt;
    krb5_keytab_entry entry;

    assert(cred->keytab == NULL);

    if (req_keytab != NULL) {
        char ktname[BUFSIZ];

        /* Duplicate keytab handle */
        code = krb5_kt_get_name(context, req_keytab, ktname, sizeof(ktname));
        if (code) {
            *minor_status = code;
            return GSS_S_CRED_UNAVAIL;
        }
        code = krb5_kt_resolve(context, ktname, &kt);
    } else {
        code = k5_mutex_lock(&gssint_krb5_keytab_lock);
        if (code) {
            *minor_status = code;
            return GSS_S_FAILURE;
        }
        if (krb5_gss_keytab != NULL) {
            code = krb5_kt_resolve(context, krb5_gss_keytab, &kt);
            k5_mutex_unlock(&gssint_krb5_keytab_lock);
        } else {
            k5_mutex_unlock(&gssint_krb5_keytab_lock);
            code = krb5_kt_default(context, &kt);
        }
    }
    if (code) {
        *minor_status = code;
        return GSS_S_CRED_UNAVAIL;
    }

    if (desired_princ != NULL) {
        code = krb5_kt_get_entry(context, kt, desired_princ, 0, 0, &entry);
        if (code) {
            krb5_kt_close(context, kt);
            if (code == KRB5_KT_NOTFOUND) {
                char *errstr = (char *)krb5_get_error_message(context, code);
                krb5_set_error_message(context, KG_KEYTAB_NOMATCH, "%s", errstr);
                krb5_free_error_message(context, errstr);
                *minor_status = KG_KEYTAB_NOMATCH;
            } else
                *minor_status = code;
            return GSS_S_CRED_UNAVAIL;
        }
        krb5_kt_free_entry(context, &entry);

        assert(cred->name == NULL);
        code = kg_init_name(context, desired_princ, NULL, 0, &cred->name);
        if (code) {
            *minor_status = code;
            return GSS_S_FAILURE;
        }

        /* Open the replay cache for this principal. */
        code = krb5_get_server_rcache(context,
                                      krb5_princ_component(context, desired_princ, 0),
                                      &cred->rcache);
        if (code) {
            *minor_status = code;
            return GSS_S_FAILURE;
        }
    }

    cred->keytab = kt;

    return GSS_S_COMPLETE;
}
#endif /* LEAN_CLIENT */

/* get credentials corresponding to the default credential cache.
   If successful, set the ccache-specific fields in cred.
*/

static OM_uint32
acquire_init_cred(krb5_context context,
                  OM_uint32 *minor_status,
                  krb5_ccache req_ccache,
                  krb5_principal desired_princ,
                  gss_buffer_t password,
                  krb5_gss_cred_id_rec *cred)
{
    krb5_error_code code;
    krb5_ccache ccache;
    krb5_principal ccache_princ = NULL, tmp_princ;
    krb5_cc_cursor cur;
    krb5_creds creds;
    int got_endtime;
    int caller_provided_ccache_name = 0;
    krb5_data password_data, *cred_princ_realm;

    cred->ccache = NULL;

    /* load the GSS ccache name into the kg_context */

    if (GSS_ERROR(kg_sync_ccache_name(context, minor_status)))
        return GSS_S_FAILURE;

    /* check to see if the caller provided a ccache name if so
     * we will just use that and not search the cache collection */
    if (GSS_ERROR(kg_caller_provided_ccache_name (minor_status, &caller_provided_ccache_name))) {
        return GSS_S_FAILURE;
    }

#if defined(USE_KIM) || defined(USE_LEASH)
    if (desired_princ && !caller_provided_ccache_name && !req_ccache) {
#if defined(USE_KIM)
        kim_error err = KIM_NO_ERROR;
        kim_ccache kimccache = NULL;
        kim_identity identity = NULL;
        kim_credential_state state;

        err = kim_identity_create_from_krb5_principal (&identity,
                                                       context,
                                                       desired_princ);

        if (!err) {
            err = kim_ccache_create_from_client_identity (&kimccache, identity);
        }

        if (!err) {
            err = kim_ccache_get_state (kimccache, &state);
        }

        if (!err && state != kim_credentials_state_valid) {
            if (state == kim_credentials_state_needs_validation) {
                err = kim_ccache_validate (kimccache, KIM_OPTIONS_DEFAULT);
            } else {
                kim_ccache_free (&kimccache);
                ccache = NULL;
            }
        }

        if (!kimccache && kim_library_allow_automatic_prompting ()) {
            /* ccache does not already exist, create a new one */
            err = kim_ccache_create_new (&kimccache, identity,
                                         KIM_OPTIONS_DEFAULT);
        }

        if (!err) {
            err = kim_ccache_get_krb5_ccache (kimccache, context, &ccache);
        }

        kim_ccache_free (&kimccache);
        kim_identity_free (&identity);

        if (err) {
            *minor_status = err;
            return GSS_S_CRED_UNAVAIL;
        }

#elif defined(USE_LEASH)
        if ( hLeashDLL == INVALID_HANDLE_VALUE ) {
            hLeashDLL = LoadLibrary(LEASH_DLL);
            if ( hLeashDLL != INVALID_HANDLE_VALUE ) {
                (FARPROC) pLeash_AcquireInitialTicketsIfNeeded =
                    GetProcAddress(hLeashDLL, "not_an_API_Leash_AcquireInitialTicketsIfNeeded");
            }
        }

        if ( pLeash_AcquireInitialTicketsIfNeeded ) {
            char ccname[256]="";
            pLeash_AcquireInitialTicketsIfNeeded(context, desired_princ, ccname, sizeof(ccname));
            if (!ccname[0]) {
                *minor_status = KRB5_CC_NOTFOUND;
                return GSS_S_CRED_UNAVAIL;
            }

            if ((code = krb5_cc_resolve (context, ccname, &ccache))) {
                *minor_status = code;
                return GSS_S_CRED_UNAVAIL;
            }
        } else {
            /* leash dll not available, open the default credential cache */

            if ((code = krb5int_cc_default(context, &ccache))) {
                *minor_status = code;
                return GSS_S_CRED_UNAVAIL;
            }
        }
#endif /* USE_LEASH */
    } else
#endif /* USE_KIM || USE_LEASH */
    {
        if (req_ccache != NULL) {
            /* Duplicate ccache handle */
            code = krb5_cc_dup(context, req_ccache, &ccache);
        } else {
            /* Open the default credential cache */
            code = krb5int_cc_default(context, &ccache);
        }
        if (code != 0) {
            *minor_status = code;
            return GSS_S_CRED_UNAVAIL;
        }
    }

    /* turn off OPENCLOSE mode while extensive frobbing is going on */
    code = krb5_cc_set_flags(context, ccache, 0);
    if (code == KRB5_FCC_NOFILE &&
        password != GSS_C_NO_BUFFER && desired_princ != NULL) {
        /* We will get initial creds later. */
        code = krb5_cc_initialize(context, ccache, desired_princ);
        if (code == 0)
            code = krb5_cc_set_flags(context, ccache, 0);
    }
    if (code != 0) {
        krb5_cc_close(context, ccache);
        *minor_status = code;
        return GSS_S_CRED_UNAVAIL;
    }

    /*
     * Credentials cache principal must match either the acceptor principal
     * name or the desired_princ argument (they may be the same).
     */
    if (cred->name != NULL && desired_princ == NULL)
        desired_princ = cred->name->princ;

    code = krb5_cc_get_principal(context, ccache, &ccache_princ);
    if (code != 0) {
        krb5_cc_close(context, ccache);
        *minor_status = code;
        return GSS_S_FAILURE;
    }

    if (desired_princ != NULL) {
        if (!krb5_principal_compare(context, ccache_princ, desired_princ)) {
            krb5_free_principal(context, ccache_princ);
            krb5_cc_close(context, ccache);
            *minor_status = KG_CCACHE_NOMATCH;
            return GSS_S_CRED_UNAVAIL;
        }
    }

    /*
     * If we are acquiring initiator-only default credentials, then set
     * cred->name to the credentials cache principal name.
     */
    if (cred->name == NULL) {
        if ((code = kg_init_name(context, ccache_princ, NULL,
                                 KG_INIT_NAME_NO_COPY, &cred->name))) {
            krb5_free_principal(context, ccache_princ);
            krb5_cc_close(context, ccache);
            *minor_status = code;
            return GSS_S_FAILURE;
        }
    } else {
        krb5_free_principal(context, ccache_princ);
    }

    assert(cred->name->princ != NULL);
    cred_princ_realm = krb5_princ_realm(context, cred->name->princ);

    if (password != GSS_C_NO_BUFFER) {
        /* stash the password for later */
        password_data.length = password->length;
        password_data.data = (char *)password->value;

        code = krb5int_copy_data_contents_add0(context, &password_data,
                                               &cred->password);
        if (code != 0) {
            krb5_cc_close(context, ccache);
            *minor_status = code;
            return GSS_S_FAILURE;
        }

        /* restore the OPENCLOSE flag */
        code = krb5_cc_set_flags(context, ccache, KRB5_TC_OPENCLOSE);
        if (code != 0) {
            krb5_cc_close(context, ccache);
            *minor_status = code;
            return GSS_S_FAILURE;
        }

        cred->ccache = ccache;
        return GSS_S_COMPLETE;
    }

    /* iterate over the ccache, find the tgt */

    if ((code = krb5_cc_start_seq_get(context, ccache, &cur))) {
        krb5_cc_close(context, ccache);
        *minor_status = code;
        return GSS_S_FAILURE;
    }

    /* this is hairy.  If there's a tgt for the principal's local realm
       in here, that's what we want for the expire time.  But if
       there's not, then we want to use the first key.  */

    got_endtime = 0;

    code = krb5_build_principal_ext(context, &tmp_princ,
                                    cred_princ_realm->length,
                                    cred_princ_realm->data,
                                    KRB5_TGS_NAME_SIZE, KRB5_TGS_NAME,
                                    cred_princ_realm->length,
                                    cred_princ_realm->data,
                                    0);
    if (code) {
        krb5_cc_close(context, ccache);
        *minor_status = code;
        return GSS_S_FAILURE;
    }
    while (!(code = krb5_cc_next_cred(context, ccache, &cur, &creds))) {
        if (krb5_principal_compare(context, tmp_princ, creds.server)) {
            cred->tgt_expire = creds.times.endtime;
            got_endtime = 1;
            *minor_status = 0;
            code = 0;
            krb5_free_cred_contents(context, &creds);
            break;
        }
        if (got_endtime == 0) {
            cred->tgt_expire = creds.times.endtime;
            got_endtime = 1;
        }
        krb5_free_cred_contents(context, &creds);
    }
    krb5_free_principal(context, tmp_princ);

    if (code && code != KRB5_CC_END) {
        /* this means some error occurred reading the ccache */
        krb5_cc_end_seq_get(context, ccache, &cur);
        krb5_cc_close(context, ccache);
        *minor_status = code;
        return GSS_S_FAILURE;
    } else if (! got_endtime) {
        /* this means the ccache was entirely empty */
        krb5_cc_end_seq_get(context, ccache, &cur);
        krb5_cc_close(context, ccache);
        *minor_status = KG_EMPTY_CCACHE;
        return GSS_S_FAILURE;
    } else {
        /* this means that we found an endtime to use. */
        if ((code = krb5_cc_end_seq_get(context, ccache, &cur))) {
            krb5_cc_close(context, ccache);
            *minor_status = code;
            return GSS_S_FAILURE;
        }
        if ((code = krb5_cc_set_flags(context, ccache, KRB5_TC_OPENCLOSE))) {
            krb5_cc_close(context, ccache);
            *minor_status = code;
            return GSS_S_FAILURE;
        }
    }

    /* the credentials match and are valid */

    cred->ccache = ccache;
    /* minor_status is set while we are iterating over the ccache */
    return GSS_S_COMPLETE;
}

struct acquire_cred_args {
    gss_name_t desired_name;
    gss_buffer_t password;
    OM_uint32 time_req;
    gss_OID_set desired_mechs;
    gss_cred_usage_t cred_usage;
    krb5_keytab keytab;
    krb5_ccache ccache;
    int iakerb;
};

/*ARGSUSED*/
static OM_uint32
acquire_cred(OM_uint32 *minor_status,
             const struct acquire_cred_args *args,
             gss_cred_id_t *output_cred_handle,
             OM_uint32 *time_rec)
{
    krb5_context context = NULL;
    krb5_gss_cred_id_t cred = NULL;
    OM_uint32 ret;
    krb5_error_code code = 0;
    krb5_principal desired_princ = NULL;

    /* make sure all outputs are valid */
    *output_cred_handle = GSS_C_NO_CREDENTIAL;
    if (time_rec)
        *time_rec = 0;

    code = gss_krb5int_initialize_library();
    if (code)
        goto krb_error_out;

    code = krb5_gss_init_context(&context);
    if (code)
        goto krb_error_out;

    /* create the gss cred structure */
    cred = k5alloc(sizeof(krb5_gss_cred_id_rec), &code);
    if (cred == NULL)
        goto krb_error_out;

    cred->usage = args->cred_usage;
    cred->name = NULL;
    cred->iakerb_mech = args->iakerb;
    cred->default_identity = (args->desired_name == GSS_C_NO_NAME);
#ifndef LEAN_CLIENT
    cred->keytab = NULL;
#endif /* LEAN_CLIENT */
    cred->destroy_ccache = 0;
    cred->ccache = NULL;

    code = k5_mutex_init(&cred->lock);
    if (code)
        goto krb_error_out;

    switch (args->cred_usage) {
    case GSS_C_INITIATE:
    case GSS_C_ACCEPT:
    case GSS_C_BOTH:
        break;
    default:
        ret = GSS_S_FAILURE;
        *minor_status = (OM_uint32) G_BAD_USAGE;
        goto error_out;
    }

    if (args->desired_name != GSS_C_NO_NAME)
        desired_princ = ((krb5_gss_name_t)args->desired_name)->princ;

#ifndef LEAN_CLIENT
    /*
     * If requested, acquire credentials for accepting. This will fill
     * in cred->name if desired_princ is specified.
     */
    if (args->cred_usage == GSS_C_ACCEPT || args->cred_usage == GSS_C_BOTH) {
        ret = acquire_accept_cred(context, minor_status,
                                  desired_princ,
                                  args->keytab, cred);
        if (ret != GSS_S_COMPLETE)
            goto error_out;
    }
#endif /* LEAN_CLIENT */

    /*
     * If requested, acquire credentials for initiation. This will fill
     * in cred->name if it wasn't set above.
     */
    if (args->cred_usage == GSS_C_INITIATE || args->cred_usage == GSS_C_BOTH) {
        ret = acquire_init_cred(context, minor_status, args->ccache,
                                desired_princ, args->password, cred);
        if (ret != GSS_S_COMPLETE)
            goto error_out;
    }

    assert(cred->default_identity || cred->name != NULL);

    /*** at this point, the cred structure has been completely created */

    if (args->cred_usage == GSS_C_ACCEPT) {
        if (time_rec)
            *time_rec = GSS_C_INDEFINITE;
    } else {
        krb5_timestamp now;

        code = krb5_timeofday(context, &now);
        if (code != 0)
            goto krb_error_out;

        if (time_rec)
            *time_rec = (cred->tgt_expire > now) ? (cred->tgt_expire - now) : 0;
    }

    if (!kg_save_cred_id((gss_cred_id_t)cred)) {
        ret = GSS_S_FAILURE;
        goto error_out;
    }

    *minor_status = 0;
    *output_cred_handle = (gss_cred_id_t) cred;

    krb5_free_context(context);
    return GSS_S_COMPLETE;

krb_error_out:
    *minor_status = code;
    ret = GSS_S_FAILURE;

error_out:
    if (cred != NULL) {
        if (cred->ccache)
            krb5_cc_close(context, cred->ccache);
#ifndef LEAN_CLIENT
        if (cred->keytab)
            krb5_kt_close(context, cred->keytab);
#endif /* LEAN_CLIENT */
        if (cred->name)
            kg_release_name(context, 0, &cred->name);
        k5_mutex_destroy(&cred->lock);
        xfree(cred);
    }
    save_error_info(*minor_status, context);
    krb5_free_context(context);
    return ret;
}

OM_uint32
gss_krb5int_set_cred_rcache(OM_uint32 *minor_status,
                            gss_cred_id_t *cred_handle,
                            const gss_OID desired_oid,
                            const gss_buffer_t value)
{
    krb5_gss_cred_id_t cred;
    krb5_error_code code;
    krb5_context context;
    krb5_rcache rcache;

    assert(value->length == sizeof(rcache));

    if (value->length != sizeof(rcache))
        return GSS_S_FAILURE;

    rcache = (krb5_rcache)value->value;

    cred = (krb5_gss_cred_id_t)*cred_handle;

    code = krb5_gss_init_context(&context);
    if (code) {
        *minor_status = code;
        return GSS_S_FAILURE;
    }
    if (cred->rcache != NULL) {
        code = krb5_rc_close(context, cred->rcache);
        if (code) {
            *minor_status = code;
            krb5_free_context(context);
            return GSS_S_FAILURE;
        }
    }

    cred->rcache = rcache;

    krb5_free_context(context);

    *minor_status = 0;
    return GSS_S_COMPLETE;
}

/*
 * krb5 and IAKERB mech API functions follow.  The mechglue always passes null
 * desired_mechs and actual_mechs, so we ignore those parameters.
 */

OM_uint32
krb5_gss_acquire_cred(minor_status, desired_name, time_req,
                      desired_mechs, cred_usage, output_cred_handle,
                      actual_mechs, time_rec)
    OM_uint32 *minor_status;
    gss_name_t desired_name;
    OM_uint32 time_req;
    gss_OID_set desired_mechs;
    gss_cred_usage_t cred_usage;
    gss_cred_id_t *output_cred_handle;
    gss_OID_set *actual_mechs;
    OM_uint32 *time_rec;
{
    struct acquire_cred_args args;

    if (desired_name && !kg_validate_name(desired_name)) {
        *minor_status = G_VALIDATE_FAILED;
        return GSS_S_FAILURE;
    }

    memset(&args, 0, sizeof(args));
    args.desired_name = desired_name;
    args.time_req = time_req;
    args.desired_mechs = desired_mechs;
    args.cred_usage = cred_usage;
    args.iakerb = 0;

    return acquire_cred(minor_status, &args, output_cred_handle, time_rec);
}

OM_uint32
iakerb_gss_acquire_cred(minor_status, desired_name, time_req,
                        desired_mechs, cred_usage, output_cred_handle,
                        actual_mechs, time_rec)
    OM_uint32 *minor_status;
    gss_name_t desired_name;
    OM_uint32 time_req;
    gss_OID_set desired_mechs;
    gss_cred_usage_t cred_usage;
    gss_cred_id_t *output_cred_handle;
    gss_OID_set *actual_mechs;
    OM_uint32 *time_rec;
{
    struct acquire_cred_args args;

    if (desired_name && !kg_validate_name(desired_name)) {
        *minor_status = G_VALIDATE_FAILED;
        return GSS_S_FAILURE;
    }

    memset(&args, 0, sizeof(args));
    args.desired_name = desired_name;
    args.time_req = time_req;
    args.desired_mechs = desired_mechs;
    args.cred_usage = cred_usage;
    args.iakerb = 1;

    return acquire_cred(minor_status, &args, output_cred_handle, time_rec);
}

OM_uint32
krb5_gss_acquire_cred_with_password(OM_uint32 *minor_status,
                                    const gss_name_t desired_name,
                                    const gss_buffer_t password,
                                    OM_uint32 time_req,
                                    const gss_OID_set desired_mechs,
                                    int cred_usage,
                                    gss_cred_id_t *output_cred_handle,
                                    gss_OID_set *actual_mechs,
                                    OM_uint32 *time_rec)
{
    struct acquire_cred_args args;

    if (desired_name && !kg_validate_name(desired_name)) {
        *minor_status = G_VALIDATE_FAILED;
        return GSS_S_FAILURE;
    }

    memset(&args, 0, sizeof(args));
    args.desired_name = desired_name;
    args.password = password;
    args.time_req = time_req;
    args.desired_mechs = desired_mechs;
    args.cred_usage = cred_usage;
    args.iakerb = 0;

    return acquire_cred(minor_status, &args, output_cred_handle, time_rec);
}

OM_uint32
iakerb_gss_acquire_cred_with_password(OM_uint32 *minor_status,
                                      const gss_name_t desired_name,
                                      const gss_buffer_t password,
                                      OM_uint32 time_req,
                                      const gss_OID_set desired_mechs,
                                      int cred_usage,
                                      gss_cred_id_t *output_cred_handle,
                                      gss_OID_set *actual_mechs,
                                      OM_uint32 *time_rec)
{
    struct acquire_cred_args args;

    if (desired_name && !kg_validate_name(desired_name)) {
        *minor_status = G_VALIDATE_FAILED;
        return GSS_S_FAILURE;
    }

    memset(&args, 0, sizeof(args));
    args.desired_name = desired_name;
    args.password = password;
    args.time_req = time_req;
    args.desired_mechs = desired_mechs;
    args.cred_usage = cred_usage;
    args.iakerb = 1;

    return acquire_cred(minor_status, &args, output_cred_handle, time_rec);
}

OM_uint32
gss_krb5int_import_cred(OM_uint32 *minor_status,
                        gss_cred_id_t *cred_handle,
                        const gss_OID desired_oid,
                        const gss_buffer_t value)
{
    struct krb5_gss_import_cred_req *req;
    struct acquire_cred_args args;
    krb5_gss_name_rec name;
    OM_uint32 time_rec;

    assert(value->length == sizeof(*req));

    if (value->length != sizeof(*req))
        return GSS_S_FAILURE;

    req = (struct krb5_gss_import_cred_req *)value->value;

    memset(&args, 0, sizeof(args));

    if (req->keytab_principal) {
        memset(&name, 0, sizeof(name));
        name.princ = req->keytab_principal;
        args.desired_name = (gss_name_t)&name;
    }

    args.ccache = req->id;
    args.keytab = req->keytab;

    if (req->id && req->keytab)
        args.cred_usage = GSS_C_BOTH;
    else if (req->id)
        args.cred_usage = GSS_C_INITIATE;
    else if (req->keytab)
        args.cred_usage = GSS_C_ACCEPT;
    else {
        *minor_status = EINVAL;
        return GSS_S_FAILURE;
    }

    return acquire_cred(minor_status, &args, cred_handle, &time_rec);
}


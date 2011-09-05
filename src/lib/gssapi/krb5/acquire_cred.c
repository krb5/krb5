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

/* Try to verify that keytab contains at least one entry for name.  Return 0 if
 * it does, KRB5_KT_NOTFOUND if it doesn't, or another error as appropriate. */
static krb5_error_code
check_keytab(krb5_context context, krb5_keytab kt, krb5_gss_name_t name)
{
    krb5_error_code code;
    krb5_keytab_entry ent;
    krb5_kt_cursor cursor;
    krb5_principal accprinc = NULL;
    krb5_boolean match;
    char *princname;

    if (name->service == NULL) {
        code = krb5_kt_get_entry(context, kt, name->princ, 0, 0, &ent);
        if (code == 0)
            krb5_kt_free_entry(context, &ent);
        return code;
    }

    /* If we can't iterate through the keytab, skip this check. */
    if (kt->ops->start_seq_get == NULL)
        return 0;

    /* Get the partial principal for the acceptor name. */
    code = kg_acceptor_princ(context, name, &accprinc);
    if (code)
        return code;

    /* Scan the keytab for host-based entries matching accprinc. */
    code = krb5_kt_start_seq_get(context, kt, &cursor);
    if (code)
        goto cleanup;
    while ((code = krb5_kt_next_entry(context, kt, &ent, &cursor)) == 0) {
        match = krb5_sname_match(context, accprinc, ent.principal);
        (void)krb5_free_keytab_entry_contents(context, &ent);
        if (match)
            break;
    }
    (void)krb5_kt_end_seq_get(context, kt, &cursor);
    if (code == KRB5_KT_END) {
        code = KRB5_KT_NOTFOUND;
        if (krb5_unparse_name(context, accprinc, &princname) == 0) {
            krb5_set_error_message(context, code,
                                   _("No key table entry found matching %s"),
                                   princname);
            free(princname);
        }
    }

cleanup:
    krb5_free_principal(context, accprinc);
    return code;
}

/* get credentials corresponding to a key in the krb5 keytab.
   If successful, set the keytab-specific fields in cred
*/

static OM_uint32
acquire_accept_cred(krb5_context context,
                    OM_uint32 *minor_status,
                    krb5_gss_name_t desired_name,
                    krb5_keytab req_keytab,
                    krb5_gss_cred_id_rec *cred)
{
    krb5_error_code code;
    krb5_keytab kt;

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

    if (desired_name != NULL) {
        code = check_keytab(context, kt, desired_name);
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

        assert(cred->name == NULL);
        code = kg_duplicate_name(context, desired_name, &cred->name);
        if (code) {
            *minor_status = code;
            return GSS_S_FAILURE;
        }

        /* Open the replay cache for this principal. */
        code = krb5_get_server_rcache(context, &desired_name->princ->data[0],
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

#ifdef USE_KIM
krb5_error_code
get_ccache_kim(krb5_context context, krb5_principal desired_princ,
               krb5_ccache *ccache_out)
{
    kim_error err;
    kim_ccache kimccache = NULL;
    kim_identity identity = NULL;
    kim_credential_state state;
    krb5_ccache ccache;

    *ccache_out = NULL;

    err = kim_identity_create_from_krb5_principal(&identity, context,
                                                  desired_princ);
    if (err)
        goto cleanup;

    err = kim_ccache_create_from_client_identity(&kimccache, identity);
    if (err)
        goto cleanup;

    err = kim_ccache_get_state(kimccache, &state);
    if (err)
        goto cleanup;

    if (state != kim_credentials_state_valid) {
        if (state == kim_credentials_state_needs_validation) {
            err = kim_ccache_validate(kimccache, KIM_OPTIONS_DEFAULT);
            if (err)
                goto cleanup;
        } else {
            kim_ccache_free(&kimccache);
        }
    }

    if (!kimccache && kim_library_allow_automatic_prompting()) {
        /* ccache does not already exist, create a new one. */
        err = kim_ccache_create_new(&kimccache, identity, KIM_OPTIONS_DEFAULT);
        if (err)
            goto cleanup;
    }

    err = kim_ccache_get_krb5_ccache(kimccache, context, &ccache);
    if (err)
        goto cleanup;

    *ccache_out = ccache;

cleanup:
    kim_ccache_free(&kimccache);
    kim_identity_free(&identity);
    return err;
}
#endif /* USE_KIM */

#ifdef USE_LEASH
static krb5_error_code
get_ccache_leash(krb5_context context, krb5_principal desired_princ,
                 krb5_ccache *ccache_out)
{
    krb5_error_code code;
    krb5_ccache ccache;
    char ccname[256] = "";

    *ccache_out = NULL;

    if (hLeashDLL == INVALID_HANDLE_VALUE) {
        hLeashDLL = LoadLibrary(LEASH_DLL);
        if (hLeashDLL != INVALID_HANDLE_VALUE) {
            (FARPROC) pLeash_AcquireInitialTicketsIfNeeded =
                GetProcAddress(hLeashDLL, "not_an_API_Leash_AcquireInitialTicketsIfNeeded");
        }
    }

    if (pLeash_AcquireInitialTicketsIfNeeded) {
        pLeash_AcquireInitialTicketsIfNeeded(context, desired_princ, ccname,
                                             sizeof(ccname));
        if (!ccname[0])
            return KRB5_CC_NOTFOUND;

        code = krb5_cc_resolve(context, ccname, &ccache);
        if (code)
            return code;
    } else {
        /* leash dll not available, open the default credential cache. */
        code = krb5int_cc_default(context, &ccache);
        if (code)
            return code;
    }

    *ccache_out = ccache;
    return 0;
}
#endif /* USE_LEASH */

/* Prepare to acquire credentials into ccache using password at
 * init_sec_context time.  On success, cred takes ownership of ccache. */
static krb5_error_code
prep_ccache(krb5_context context, krb5_gss_cred_id_rec *cred,
            krb5_ccache ccache, krb5_principal desired_princ,
            gss_buffer_t password)
{
    krb5_error_code code;
    krb5_principal ccache_princ;
    krb5_data password_data = make_data(password->value, password->length);
    krb5_boolean eq;
    const char *cctype;
    krb5_ccache newcache = NULL;

    /* Check the ccache principal or initialize a new cache. */
    code = krb5_cc_get_principal(context, ccache, &ccache_princ);
    if (code == 0) {
        eq = krb5_principal_compare(context, ccache_princ, desired_princ);
        krb5_free_principal(context, ccache_princ);
        if (!eq) {
            cctype = krb5_cc_get_type(context, ccache);
            if (krb5_cc_support_switch(context, cctype)) {
                /* Make a new ccache within the collection. */
                code = krb5_cc_new_unique(context, cctype, NULL, &newcache);
                if (code)
                    return code;
            } else
                return KG_CCACHE_NOMATCH;
        }
    } else if (code == KRB5_FCC_NOFILE) {
        /* Cache file does not exist; create and initialize one. */
        code = krb5_cc_initialize(context, ccache, desired_princ);
        if (code)
            return code;
    } else
        return code;

    /* Save the desired principal as the credential name if not already set. */
    if (!cred->name) {
        code = kg_init_name(context, desired_princ, NULL, NULL, NULL, 0,
                            &cred->name);
        if (code)
            return code;
    }

    /* Stash the password for later. */
    code = krb5int_copy_data_contents_add0(context, &password_data,
                                           &cred->password);
    if (code)
        return code;

    if (newcache) {
        krb5_cc_close(context, ccache);
        cred->ccache = newcache;
    } else
        cred->ccache = ccache;
    return 0;
}

/* Check ccache and scan it for its expiry time.  On success, cred takes
 * ownership of ccache. */
static krb5_error_code
scan_ccache(krb5_context context, krb5_gss_cred_id_rec *cred,
            krb5_ccache ccache, krb5_principal desired_princ)
{
    krb5_error_code code;
    krb5_principal ccache_princ = NULL, tgt_princ = NULL;
    krb5_data *realm;
    krb5_cc_cursor cursor;
    krb5_creds creds;
    krb5_timestamp endtime;
    int got_endtime = 0, is_tgt;

    /* Turn off OPENCLOSE mode while extensive frobbing is going on. */
    code = krb5_cc_set_flags(context, ccache, 0);
    if (code)
        return code;

    code = krb5_cc_get_principal(context, ccache, &ccache_princ);
    if (code != 0)
        return code;

    /* Credentials cache principal must match the initiator name. */
    if (desired_princ != NULL &&
        !krb5_principal_compare(context, ccache_princ, desired_princ)) {
        code = KG_CCACHE_NOMATCH;
        goto cleanup;
    }

    /* Save the ccache principal as the credential name if not already set. */
    if (!cred->name) {
        code = kg_init_name(context, ccache_princ, NULL, NULL, NULL,
                            KG_INIT_NAME_NO_COPY, &cred->name);
        if (code)
            goto cleanup;
        ccache_princ = NULL;
    }

    assert(cred->name->princ != NULL);
    realm = krb5_princ_realm(context, cred->name->princ);
    code = krb5_build_principal_ext(context, &tgt_princ,
                                    realm->length, realm->data,
                                    KRB5_TGS_NAME_SIZE, KRB5_TGS_NAME,
                                    realm->length, realm->data,
                                    0);
    if (code)
        return code;

    /* If there's a tgt for the principal's local realm in here, use its expiry
     * time.  Otherwise use the first key. */
    code = krb5_cc_start_seq_get(context, ccache, &cursor);
    if (code) {
        krb5_free_principal(context, tgt_princ);
        return code;
    }
    while (!(code = krb5_cc_next_cred(context, ccache, &cursor, &creds))) {
        is_tgt = krb5_principal_compare(context, tgt_princ, creds.server);
        endtime = creds.times.endtime;
        krb5_free_cred_contents(context, &creds);
        if (is_tgt || !got_endtime)
            cred->tgt_expire = creds.times.endtime;
        got_endtime = 1;
        if (is_tgt)
            break;
    }
    krb5_cc_end_seq_get(context, ccache, &cursor);
    if (code && code != KRB5_CC_END)
        goto cleanup;
    code = 0;

    if (!got_endtime) {         /* ccache is empty. */
        code = KG_EMPTY_CCACHE;
        goto cleanup;
    }

    (void)krb5_cc_set_flags(context, ccache, KRB5_TC_OPENCLOSE);
    cred->ccache = ccache;

cleanup:
    krb5_free_principal(context, ccache_princ);
    krb5_free_principal(context, tgt_princ);
    return code;
}

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
    krb5_ccache ccache = NULL;
    int caller_ccname = 0;

    cred->ccache = NULL;

    /* Load the GSS ccache name, if specified, into the context. */
    if (GSS_ERROR(kg_sync_ccache_name(context, minor_status)))
        return GSS_S_FAILURE;
    if (GSS_ERROR(kg_caller_provided_ccache_name(minor_status,
                                                 &caller_ccname)))
        return GSS_S_FAILURE;

    /* Pick a credential cache. */
    if (req_ccache != NULL) {
        code = krb5_cc_dup(context, req_ccache, &ccache);
    } else if (caller_ccname) {
        /* Caller's ccache name has been set as the context default. */
        code = krb5int_cc_default(context, &ccache);
    } else if (desired_princ) {
        /* Try to find an appropriate ccache for the desired name. */
#if defined(USE_KIM)
        code = get_ccache_kim(context, desired_princ, &ccache);
#elif defined(USE_LEASH)
        code = get_ccache_leash(context, desired_princ, &ccache);
#else
        code = krb5_cc_cache_match(context, desired_princ, &ccache);
        if (code == KRB5_CC_NOTFOUND && password != GSS_C_NO_BUFFER) {
            /* Grab the default ccache for now; if it's not empty, prep_ccache
             * will create a new one of the default type or error out. */
            krb5_clear_error_message(context);
            code = krb5_cc_default(context, &ccache);
        }
#endif
    } else
        code = 0;
    if (code != 0) {
        *minor_status = code;
        return GSS_S_CRED_UNAVAIL;
    }

    if (ccache != NULL) {
        if (password != GSS_C_NO_BUFFER && desired_princ != NULL)
            code = prep_ccache(context, cred, ccache, desired_princ, password);
        else
            code = scan_ccache(context, cred, ccache, desired_princ);
        if (code != 0) {
            krb5_cc_close(context, ccache);
            *minor_status = code;
            return GSS_S_CRED_UNAVAIL;
        }
        cred->ccache = ccache;
    }

    /*
     * If the caller specified no ccache and no desired principal, leave
     * cred->ccache and cred->name NULL.  They will be resolved later by
     * kg_cred_resolve(), possibly using the target principal name.
     */

    *minor_status = 0;
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
    krb5_gss_name_t name = (krb5_gss_name_t)args->desired_name;
    OM_uint32 ret;
    krb5_error_code code = 0;

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
    cred->default_identity = (name == NULL);
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

#ifndef LEAN_CLIENT
    /*
     * If requested, acquire credentials for accepting. This will fill
     * in cred->name if desired_princ is specified.
     */
    if (args->cred_usage == GSS_C_ACCEPT || args->cred_usage == GSS_C_BOTH) {
        ret = acquire_accept_cred(context, minor_status, name, args->keytab,
                                  cred);
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
                                name ? name->princ : NULL, args->password,
                                cred);
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
            kg_release_name(context, &cred->name);
        k5_mutex_destroy(&cred->lock);
        xfree(cred);
    }
    save_error_info(*minor_status, context);
    krb5_free_context(context);
    return ret;
}

/*
 * Resolve the name and ccache for an initiator credential if it has not yet
 * been done.  If specified, use the target name to pick an appropriate ccache
 * within the collection.  Validates cred_handle and leaves it locked on
 * success.
 */
OM_uint32
kg_cred_resolve(OM_uint32 *minor_status, krb5_context context,
                gss_cred_id_t cred_handle, gss_name_t target_name)
{
    OM_uint32 maj;
    krb5_error_code code;
    krb5_gss_cred_id_t cred = (krb5_gss_cred_id_t)cred_handle;
    krb5_gss_name_t tname = (krb5_gss_name_t)target_name;
    krb5_ccache ccache = NULL;
    krb5_principal client_princ = NULL;

    *minor_status = 0;

    maj = krb5_gss_validate_cred_1(minor_status, cred_handle, context);
    if (maj != 0)
        return maj;
    k5_mutex_assert_locked(&cred->lock);

    if (cred->ccache != NULL || cred->usage == GSS_C_ACCEPT)
        return GSS_S_COMPLETE;

    /* Pick a credential cache. */
    if (tname != NULL) {
        code = krb5_cc_select(context, tname->princ, &ccache, &client_princ);
        if (code && code != KRB5_CC_NOTFOUND)
            goto kerr;
    }
    if (ccache == NULL) {
        /*
         * Ideally we would get credentials for client_princ if it is set.  At
         * the moment, we just get the default ccache (obtaining credentials if
         * the platform supports it) and check it against client_princ below.
         */
        code = krb5int_cc_default(context, &ccache);
        if (code)
            goto kerr;
    }

    code = scan_ccache(context, cred, ccache, client_princ);
    if (code) {
        krb5_cc_close(context, ccache);
        goto kerr;
    }

    krb5_free_principal(context, client_princ);
    return GSS_S_COMPLETE;

kerr:
    krb5_free_principal(context, client_princ);
    k5_mutex_unlock(&cred->lock);
    save_error_info(code, context);
    *minor_status = code;
    return GSS_S_CRED_UNAVAIL;
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

OM_uint32 KRB5_CALLCONV
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

    memset(&args, 0, sizeof(args));
    args.desired_name = desired_name;
    args.time_req = time_req;
    args.desired_mechs = desired_mechs;
    args.cred_usage = cred_usage;
    args.iakerb = 0;

    return acquire_cred(minor_status, &args, output_cred_handle, time_rec);
}

OM_uint32 KRB5_CALLCONV
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

    memset(&args, 0, sizeof(args));
    args.desired_name = desired_name;
    args.time_req = time_req;
    args.desired_mechs = desired_mechs;
    args.cred_usage = cred_usage;
    args.iakerb = 1;

    return acquire_cred(minor_status, &args, output_cred_handle, time_rec);
}

OM_uint32 KRB5_CALLCONV
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

    memset(&args, 0, sizeof(args));
    args.desired_name = desired_name;
    args.password = password;
    args.time_req = time_req;
    args.desired_mechs = desired_mechs;
    args.cred_usage = cred_usage;
    args.iakerb = 0;

    return acquire_cred(minor_status, &args, output_cred_handle, time_rec);
}

OM_uint32 KRB5_CALLCONV
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
    krb5_error_code code;

    assert(value->length == sizeof(*req));

    if (value->length != sizeof(*req))
        return GSS_S_FAILURE;

    req = (struct krb5_gss_import_cred_req *)value->value;

    memset(&args, 0, sizeof(args));

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

    if (req->keytab_principal) {
        memset(&name, 0, sizeof(name));
        code = k5_mutex_init(&name.lock);
        if (code != 0) {
            *minor_status = code;
            return GSS_S_FAILURE;
        }
        name.princ = req->keytab_principal;
        args.desired_name = (gss_name_t)&name;
    }

    args.ccache = req->id;
    args.keytab = req->keytab;

    code = acquire_cred(minor_status, &args, cred_handle, &time_rec);
    if (req->keytab_principal)
        k5_mutex_destroy(&name.lock);
    return code;
}

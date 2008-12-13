/* -*- mode: c; indent-tabs-mode: nil -*- */
/*
 * Portions Copyright (C) 2008 Novell Inc.
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

/*
 * $Id$
 */


/* For declaration of krb5_ser_context_init */
#include "k5-int.h"
#include "gssapiP_krb5.h"

/** exported constants defined in gssapi_krb5{,_nx}.h **/

/* these are bogus, but will compile */

/*
 * The OID of the draft krb5 mechanism, assigned by IETF, is:
 *      iso(1) org(3) dod(5) internet(1) security(5)
 *      kerberosv5(2) = 1.3.5.1.5.2
 * The OID of the krb5_name type is:
 *      iso(1) member-body(2) US(840) mit(113554) infosys(1) gssapi(2)
 *      krb5(2) krb5_name(1) = 1.2.840.113554.1.2.2.1
 * The OID of the krb5_principal type is:
 *      iso(1) member-body(2) US(840) mit(113554) infosys(1) gssapi(2)
 *      krb5(2) krb5_principal(2) = 1.2.840.113554.1.2.2.2
 * The OID of the proposed standard krb5 mechanism is:
 *      iso(1) member-body(2) US(840) mit(113554) infosys(1) gssapi(2)
 *      krb5(2) = 1.2.840.113554.1.2.2
 * The OID of the proposed standard krb5 v2 mechanism is:
 *      iso(1) member-body(2) US(840) mit(113554) infosys(1) gssapi(2)
 *      krb5v2(3) = 1.2.840.113554.1.2.3
 *
 */

/*
 * Encoding rules: The first two values are encoded in one byte as 40
 * * value1 + value2.  Subsequent values are encoded base 128, most
 * significant digit first, with the high bit (\200) set on all octets
 * except the last in each value's encoding.
 */

const gss_OID_desc krb5_gss_oid_array[] = {
    /* this is the official, rfc-specified OID */
    {GSS_MECH_KRB5_OID_LENGTH, GSS_MECH_KRB5_OID},
    /* this pre-RFC mech OID */
    {GSS_MECH_KRB5_OLD_OID_LENGTH, GSS_MECH_KRB5_OLD_OID},
    /* this is the unofficial, incorrect mech OID emitted by MS */
    {GSS_MECH_KRB5_WRONG_OID_LENGTH, GSS_MECH_KRB5_WRONG_OID},
    /* this is the v2 assigned OID */
    {9, "\052\206\110\206\367\022\001\002\003"},
    /* these two are name type OID's */

    /* 2.1.1. Kerberos Principal Name Form:  (rfc 1964)
     * This name form shall be represented by the Object Identifier {iso(1)
     * member-body(2) United States(840) mit(113554) infosys(1) gssapi(2)
     * krb5(2) krb5_name(1)}.  The recommended symbolic name for this type
     * is "GSS_KRB5_NT_PRINCIPAL_NAME". */
    {10, "\052\206\110\206\367\022\001\002\002\001"},

    /* gss_nt_krb5_principal.  Object identifier for a krb5_principal. Do not use. */
    {10, "\052\206\110\206\367\022\001\002\002\002"},
    { 0, 0 }
};

const gss_OID_desc * const gss_mech_krb5              = krb5_gss_oid_array+0;
const gss_OID_desc * const gss_mech_krb5_old          = krb5_gss_oid_array+1;
const gss_OID_desc * const gss_mech_krb5_wrong        = krb5_gss_oid_array+2;
const gss_OID_desc * const gss_nt_krb5_name           = krb5_gss_oid_array+4;
const gss_OID_desc * const gss_nt_krb5_principal      = krb5_gss_oid_array+5;
const gss_OID_desc * const GSS_KRB5_NT_PRINCIPAL_NAME = krb5_gss_oid_array+4;

static const gss_OID_set_desc oidsets[] = {
    {1, (gss_OID) krb5_gss_oid_array+0},
    {1, (gss_OID) krb5_gss_oid_array+1},
    {3, (gss_OID) krb5_gss_oid_array+0},
    {1, (gss_OID) krb5_gss_oid_array+2},
    {3, (gss_OID) krb5_gss_oid_array+0},
};

const gss_OID_set_desc * const gss_mech_set_krb5 = oidsets+0;
const gss_OID_set_desc * const gss_mech_set_krb5_old = oidsets+1;
const gss_OID_set_desc * const gss_mech_set_krb5_both = oidsets+2;

g_set kg_vdb = G_SET_INIT;

/** default credential support */

/*
 * init_sec_context() will explicitly re-acquire default credentials,
 * so handling the expiration/invalidation condition here isn't needed.
 */
OM_uint32
kg_get_defcred(minor_status, cred)
    OM_uint32 *minor_status;
    gss_cred_id_t *cred;
{
    OM_uint32 major;

    if ((major = krb5_gss_acquire_cred(minor_status,
                                       (gss_name_t) NULL, GSS_C_INDEFINITE,
                                       GSS_C_NULL_OID_SET, GSS_C_INITIATE,
                                       cred, NULL, NULL)) && GSS_ERROR(major)) {
        return(major);
    }
    *minor_status = 0;
    return(GSS_S_COMPLETE);
}

OM_uint32
kg_sync_ccache_name (krb5_context context, OM_uint32 *minor_status)
{
    OM_uint32 err = 0;

    /*
     * Sync up the context ccache name with the GSSAPI ccache name.
     * If kg_ccache_name is NULL -- normal unless someone has called
     * gss_krb5_ccache_name() -- then the system default ccache will
     * be picked up and used by resetting the context default ccache.
     * This is needed for platforms which support multiple ccaches.
     */

    if (!err) {
        /* if NULL, resets the context default ccache */
        err = krb5_cc_set_default_name(context,
                                       (char *) k5_getspecific(K5_KEY_GSS_KRB5_CCACHE_NAME));
    }

    *minor_status = err;
    return (*minor_status == 0) ? GSS_S_COMPLETE : GSS_S_FAILURE;
}

/* This function returns whether or not the caller set a cccache name.  Used by
 * gss_acquire_cred to figure out if the caller wants to only look at this
 * ccache or search the cache collection for the desired name */
OM_uint32
kg_caller_provided_ccache_name (OM_uint32 *minor_status,
                                int *out_caller_provided_name)
{
    if (out_caller_provided_name) {
        *out_caller_provided_name =
            (k5_getspecific(K5_KEY_GSS_KRB5_CCACHE_NAME) != NULL);
    }

    *minor_status = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
kg_get_ccache_name (OM_uint32 *minor_status, const char **out_name)
{
    const char *name = NULL;
    OM_uint32 err = 0;
    char *kg_ccache_name;

    kg_ccache_name = k5_getspecific(K5_KEY_GSS_KRB5_CCACHE_NAME);

    if (kg_ccache_name != NULL) {
        name = strdup(kg_ccache_name);
        if (name == NULL)
            err = ENOMEM;
    } else {
        krb5_context context = NULL;

        /* Reset the context default ccache (see text above), and then
           retrieve it.  */
        err = krb5_gss_init_context(&context);
        if (!err)
            err = krb5_cc_set_default_name (context, NULL);
        if (!err) {
            name = krb5_cc_default_name(context);
            if (name) {
                name = strdup(name);
                if (name == NULL)
                    err = ENOMEM;
            }
        }
        if (err && context)
            save_error_info(err, context);
        if (context)
            krb5_free_context(context);
    }

    if (!err) {
        if (out_name) {
            *out_name = name;
        }
    }

    *minor_status = err;
    return (*minor_status == 0) ? GSS_S_COMPLETE : GSS_S_FAILURE;
}

OM_uint32
kg_set_ccache_name (OM_uint32 *minor_status, const char *name)
{
    char *new_name = NULL;
    char *swap = NULL;
    char *kg_ccache_name;
    krb5_error_code kerr;

    if (name) {
        new_name = strdup(name);
        if (new_name == NULL) {
            *minor_status = ENOMEM;
            return GSS_S_FAILURE;
        }
    }

    kg_ccache_name = k5_getspecific(K5_KEY_GSS_KRB5_CCACHE_NAME);
    swap = kg_ccache_name;
    kg_ccache_name = new_name;
    new_name = swap;
    kerr = k5_setspecific(K5_KEY_GSS_KRB5_CCACHE_NAME, kg_ccache_name);
    if (kerr != 0) {
        /* Can't store, so free up the storage.  */
        free(kg_ccache_name);
        /* ??? free(new_name); */
        *minor_status = kerr;
        return GSS_S_FAILURE;
    }

    free (new_name);
    *minor_status = 0;
    return GSS_S_COMPLETE;
}

/*
 * Mechanism specific API shims below
 */

OM_uint32 KRB5_CALLCONV
gss_krb5_get_tkt_flags(
    OM_uint32 *minor_status,
    gss_ctx_id_t context_handle,
    krb5_flags *ticket_flags)
{
    static const gss_OID_desc const req_oid = {
	GSS_KRB5_GET_TKT_FLAGS_OID_LENGTH,
	GSS_KRB5_GET_TKT_FLAGS_OID };
    OM_uint32 major_status;
    gss_buffer_set_t data_set = GSS_C_NO_BUFFER_SET;

    if (ticket_flags == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    major_status = gss_inquire_sec_context_by_oid(minor_status,
						  context_handle,
						  (const gss_OID)&req_oid,
						  &data_set);
    if (major_status != GSS_S_COMPLETE)
	return major_status;

    if (data_set == GSS_C_NO_BUFFER_SET ||
        data_set->count != 1 ||
	data_set->elements[0].length != sizeof(*ticket_flags)) {
	*minor_status = EINVAL;
	return GSS_S_FAILURE;
    }

    *ticket_flags = *((krb5_flags *)data_set->elements[0].value);

    gss_release_buffer_set(minor_status, &data_set);

    *minor_status = 0;

    return GSS_S_COMPLETE;
}

OM_uint32 KRB5_CALLCONV
gss_krb5_copy_ccache(
    OM_uint32 *minor_status,
    gss_cred_id_t cred_handle,
    krb5_ccache out_ccache)
{
    static const gss_OID_desc const req_oid = {
	GSS_KRB5_COPY_CCACHE_OID_LENGTH,
	GSS_KRB5_COPY_CCACHE_OID };
    OM_uint32 major_status;
    gss_buffer_desc req_buffer;

    if (out_ccache == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    req_buffer.value = out_ccache;
    req_buffer.length = sizeof(out_ccache);

    major_status = gssspi_set_cred_option(minor_status,
					  cred_handle,
					  (const gss_OID)&req_oid,
					  &req_buffer);

    return major_status;
}

OM_uint32 KRB5_CALLCONV
gss_krb5_export_lucid_sec_context(
    OM_uint32 *minor_status,
    gss_ctx_id_t *context_handle,
    OM_uint32 version,
    void **kctx)
{
    static const gss_OID_desc const req_oid = {
	GSS_KRB5_EXPORT_LUCID_SEC_CONTEXT_OID_LENGTH,
	GSS_KRB5_EXPORT_LUCID_SEC_CONTEXT_OID };
    OM_uint32 major_status;
    struct krb5_gss_export_lucid_sec_context_req req;
    gss_buffer_desc req_buffer;

    if (kctx == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    *kctx = NULL;

    req.version = version;
    req.kctx = NULL;

    req_buffer.length = sizeof(req);
    req_buffer.value = &req;

    /*
     * While it may seem we should call
     * gss_inquire_context_by_oid() that would not let
     * the underlying mechanism delete the context.
     */
    major_status = gss_set_sec_context_option(minor_status,
					      context_handle,
					      (const gss_OID)&req_oid,
					      &req_buffer);

    *kctx = req.kctx;

    return major_status;
}

OM_uint32 KRB5_CALLCONV
gss_krb5_set_allowable_enctypes(
    OM_uint32 *minor_status,
    gss_cred_id_t cred,
    OM_uint32 num_ktypes,
    krb5_enctype *ktypes)
{
    static const gss_OID_desc const req_oid = {
	GSS_KRB5_SET_ALLOWABLE_ENCTYPES_OID_LENGTH,
	GSS_KRB5_SET_ALLOWABLE_ENCTYPES_OID };
    OM_uint32 major_status;
    struct krb5_gss_set_allowable_enctypes_req req;
    gss_buffer_desc req_buffer;
    
    req.num_ktypes = num_ktypes;
    req.ktypes = ktypes;

    req_buffer.length = sizeof(req);
    req_buffer.value = &req;

    major_status = gssspi_set_cred_option(minor_status,
					  cred,
					  (const gss_OID)&req_oid,
					  &req_buffer);

    return major_status;
}

OM_uint32 KRB5_CALLCONV
gss_krb5_ccache_name(
    OM_uint32 *minor_status,
    const char *name,
    const char **out_name)
{
    static const gss_OID_desc const req_oid = {
	GSS_KRB5_CCACHE_NAME_OID_LENGTH,
	GSS_KRB5_CCACHE_NAME_OID };
    OM_uint32 major_status;
    struct krb5_gss_ccache_name_req req;
    gss_buffer_desc req_buffer;

    if (out_name == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    *out_name = NULL;

    req.name = name;
    req.out_name = NULL;

    req_buffer.length = sizeof(req);
    req_buffer.value = &req;

    major_status = gssspi_mech_invoke(minor_status,
				      (const gss_OID)gss_mech_krb5,
				      (const gss_OID)&req_oid,
				      &req_buffer);

    *out_name = req.out_name;

    return major_status;    
}

OM_uint32 KRB5_CALLCONV
gss_krb5_free_lucid_sec_context(
    OM_uint32 *minor_status,
    void *kctx)
{
    static const gss_OID_desc const req_oid = {
	GSS_KRB5_FREE_LUCID_SEC_CONTEXT_OID_LENGTH,
	GSS_KRB5_FREE_LUCID_SEC_CONTEXT_OID };
    OM_uint32 major_status;
    gss_buffer_desc req_buffer;

    req_buffer.length = sizeof(kctx);
    req_buffer.value = kctx;

    major_status = gssspi_mech_invoke(minor_status,
				      (const gss_OID)gss_mech_krb5,
				      (const gss_OID)&req_oid,
				      &req_buffer);

    return major_status;    
}

OM_uint32 KRB5_CALLCONV
krb5_gss_register_acceptor_identity(const char *keytab)
{
    static const gss_OID_desc const req_oid = {
	GSS_KRB5_REGISTER_ACCEPTOR_IDENTITY_OID_LENGTH,
	GSS_KRB5_REGISTER_ACCEPTOR_IDENTITY_OID };
    OM_uint32 major_status;
    OM_uint32 minor_status;
    gss_buffer_desc req_buffer;

    req_buffer.length = sizeof(keytab);
    req_buffer.value = (char *)keytab;

    major_status = gssspi_mech_invoke(&minor_status,
				      (const gss_OID)gss_mech_krb5,
				      (const gss_OID)&req_oid,
				      &req_buffer);

    return major_status;    
}

krb5_error_code
krb5_gss_use_kdc_context(void)
{
    static const gss_OID_desc const req_oid = {
	GSS_KRB5_USE_KDC_CONTEXT_OID_LENGTH,
	GSS_KRB5_USE_KDC_CONTEXT_OID };
    OM_uint32 major_status;
    OM_uint32 minor_status;
    gss_buffer_desc req_buffer;

    req_buffer.length = 0;
    req_buffer.value = NULL;

    major_status = gssspi_mech_invoke(&minor_status,
				      (const gss_OID)gss_mech_krb5,
				      (const gss_OID)&req_oid,
				      &req_buffer);

    return major_status;    
}

OM_uint32
gsskrb5_get_subkey(
    OM_uint32  *minor_status,
    const gss_ctx_id_t context_handle,
    krb5_keyblock **key)
{
    static const gss_OID_desc const req_oid = {
	GSS_KRB5_GET_SUBKEY_OID_LENGTH,
	GSS_KRB5_GET_SUBKEY_OID };
    OM_uint32 major_status;
    gss_buffer_set_t data_set = GSS_C_NO_BUFFER_SET;

    if (minor_status == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    if (key == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    major_status = gss_inquire_sec_context_by_oid(minor_status,
						  context_handle,
						  (const gss_OID)&req_oid,
						  &data_set);
    if (major_status != GSS_S_COMPLETE)
	return major_status;

    if (data_set == GSS_C_NO_BUFFER_SET ||
        data_set->count != 1 ||
	data_set->elements[0].length != sizeof(*key)) {
	return GSS_S_FAILURE;
    }

    *key = *((krb5_keyblock **)data_set->elements[0].value);

    gss_release_buffer_set(minor_status, &data_set);

    *minor_status = 0;

    return GSS_S_COMPLETE;
}

/*
 * This API should go away and be replaced with an accessor
 * into a gss_name_t.
 */
OM_uint32 KRB5_CALLCONV
gsskrb5_extract_authz_data_from_sec_context(
    OM_uint32 *minor_status,
    const gss_ctx_id_t context_handle,
    int ad_type,
    gss_buffer_t ad_data)
{
    gss_OID_desc req_oid;
    unsigned char oid_buf[GSS_KRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT_OID_LENGTH + 6];
    OM_uint32 major_status;
    gss_buffer_set_t data_set = GSS_C_NO_BUFFER_SET;
    int oad_type, i;
    unsigned char *op;
    OM_uint32 nbytes;

    if (ad_data == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    /*
     * This absolutely horrible code is used to DER encode the
     * requested authorization data type into the last element
     * of the request OID. Oh for an ASN.1 library...
     */

    memcpy(oid_buf, GSS_KRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT_OID,
	   GSS_KRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT_OID_LENGTH);

    nbytes = 0;
    oad_type = ad_type;
    while (ad_type) {
	nbytes++;
	ad_type >>= 7;
    }
    ad_type = oad_type;
    op = oid_buf + GSS_KRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT_OID_LENGTH + nbytes;
    i = -1;
    while (ad_type) {
	op[i] = (unsigned char)ad_type & 0x7f;
	if (i != -1)
	    op[i] |= 0x80;
	i--;
	ad_type >>= 7;
    }

    req_oid.elements = oid_buf;
    req_oid.length = GSS_KRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT_OID_LENGTH + nbytes;
    assert(req_oid.length <= sizeof(oid_buf));

    major_status = gss_inquire_sec_context_by_oid(minor_status,
						  context_handle,
						  (const gss_OID)&req_oid,
						  &data_set);
    if (major_status != GSS_S_COMPLETE) {
	return major_status;
    }

    if (data_set == GSS_C_NO_BUFFER_SET ||
	data_set->count != 1) {
	return GSS_S_FAILURE;
    }

    ad_data->length = data_set->elements[0].length;
    ad_data->value = data_set->elements[0].value;

    data_set->elements[0].length = 0;
    data_set->elements[0].value = NULL;

    data_set->count = 0;

    gss_release_buffer_set(minor_status, &data_set);

    return GSS_S_COMPLETE;
}

OM_uint32 KRB5_CALLCONV
gss_krb5_set_cred_rcache(
    OM_uint32 *minor_status,
    gss_cred_id_t cred,
    krb5_rcache rcache)
{
    static const gss_OID_desc const req_oid = {
	GSS_KRB5_SET_CRED_RCACHE_OID_LENGTH,
	GSS_KRB5_SET_CRED_RCACHE_OID };
    OM_uint32 major_status;
    gss_buffer_desc req_buffer;
    
    req_buffer.length = sizeof(rcache);
    req_buffer.value = rcache;

    major_status = gssspi_set_cred_option(minor_status,
					  cred,
					  (const gss_OID)&req_oid,
					  &req_buffer);

    return major_status;
}

OM_uint32 KRB5_CALLCONV
gss_krb5_set_cred_alias(
    OM_uint32 *minor_status,
    gss_cred_id_t cred,
    krb5_principal *aliases)
{
    static const gss_OID_desc const req_oid = {
	GSS_KRB5_SET_ACCEPTOR_ALIAS_OID_LENGTH,
	GSS_KRB5_SET_ACCEPTOR_ALIAS_OID };
    OM_uint32 major_status;
    gss_buffer_desc req_buffer;

    req_buffer.length = sizeof(aliases);
    req_buffer.value = aliases;

    major_status = gssspi_set_cred_option(minor_status,
					  cred,
					  (const gss_OID)&req_oid,
					  &req_buffer);

    return major_status;
}

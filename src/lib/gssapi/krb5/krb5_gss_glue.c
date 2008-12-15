/* -*- mode: c; indent-tabs-mode: nil -*- */
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
 * Copyright (c) 2006-2008, Novell, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *   * The copyright holder's name is not used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * $Id$
 */

#include "gssapiP_krb5.h"
#include "mglueP.h"

#define g_OID_prefix_equal(o1, o2) \
	(((o1)->length >= (o2)->length) && \
	(memcmp((o1)->elements, (o2)->elements, (o2)->length) == 0))

/*
 * gss_inquire_sec_context_by_oid() methods
 */
static struct {
    gss_OID_desc oid;
    OM_uint32 (*func)(OM_uint32 *, const gss_ctx_id_t, const gss_OID, gss_buffer_set_t *);
} krb5_gss_inquire_sec_context_by_oid_ops[] = {
    {
	{GSS_KRB5_GET_TKT_FLAGS_OID_LENGTH, GSS_KRB5_GET_TKT_FLAGS_OID},
	gss_krb5int_get_tkt_flags
    },
    {
	{GSS_KRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT_OID_LENGTH, GSS_KRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT_OID},
	gss_krb5int_extract_authz_data_from_sec_context
    },
    {
	{GSS_KRB5_INQ_SESSION_KEY_OID_LENGTH, GSS_KRB5_INQ_SESSION_KEY_OID},
	gss_krb5int_inq_session_key
    },
#if 0
    {
	{GSS_KRB5_GET_SUBKEY_OID_LENGTH, GSS_KRB5_GET_SUBKEY_OID},
	gss_krb5int_get_subkey
    },
#endif
    {
	{GSS_KRB5_EXPORT_LUCID_SEC_CONTEXT_OID_LENGTH, GSS_KRB5_EXPORT_LUCID_SEC_CONTEXT_OID},
	gss_krb5int_export_lucid_sec_context
    },
    {
	{GSS_KRB5_EXTRACT_AUTHTIME_FROM_SEC_CONTEXT_OID_LENGTH, GSS_KRB5_EXTRACT_AUTHTIME_FROM_SEC_CONTEXT_OID},
	gss_krb5int_extract_authtime_from_sec_context
    }
};

OM_uint32
krb5_gss_inquire_sec_context_by_oid (OM_uint32 *minor_status,
				     const gss_ctx_id_t context_handle,
				     const gss_OID desired_object,
				     gss_buffer_set_t *data_set)
{
    krb5_gss_ctx_id_rec *ctx;
    int i;

    if (minor_status == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    *minor_status = 0;

    if (desired_object == GSS_C_NO_OID)
	return GSS_S_CALL_INACCESSIBLE_READ;

    if (data_set == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    *data_set = GSS_C_NO_BUFFER_SET;

    if (!kg_validate_ctx_id(context_handle))
	return GSS_S_NO_CONTEXT;

    ctx = (krb5_gss_ctx_id_rec *) context_handle;

    if (!ctx->established)
	return GSS_S_NO_CONTEXT;

    for (i = 0; i < sizeof(krb5_gss_inquire_sec_context_by_oid_ops)/
		    sizeof(krb5_gss_inquire_sec_context_by_oid_ops[0]); i++) {
	if (g_OID_prefix_equal(desired_object, &krb5_gss_inquire_sec_context_by_oid_ops[i].oid)) {
	    return (*krb5_gss_inquire_sec_context_by_oid_ops[i].func)(minor_status,
								      context_handle,
								      desired_object,
								      data_set);
	}
    }

    *minor_status = EINVAL;

    return GSS_S_BAD_MECH; 
}

/*
 * gss_inquire_cred_by_oid() methods
 */
static struct {
    gss_OID_desc oid;
    OM_uint32 (*func)(OM_uint32 *, const gss_cred_id_t, const gss_OID, gss_buffer_set_t *);
} krb5_gss_inquire_cred_by_oid_ops[] = {
};

OM_uint32
krb5_gss_inquire_cred_by_oid(OM_uint32 *minor_status,
			     const gss_cred_id_t cred_handle,
			     const gss_OID desired_object,
			     gss_buffer_set_t *data_set)
{
    OM_uint32 major_status = GSS_S_FAILURE;
    krb5_gss_cred_id_t cred;
    int i;

    if (minor_status == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    *minor_status = 0;

    if (desired_object == GSS_C_NO_OID)
	return GSS_S_CALL_INACCESSIBLE_READ;

    if (data_set == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    *data_set = GSS_C_NO_BUFFER_SET;
    if (cred_handle == GSS_C_NO_CREDENTIAL) {
	*minor_status = KRB5_NOCREDS_SUPPLIED;
	return GSS_S_NO_CRED;
    }

    major_status = krb5_gss_validate_cred(minor_status, cred_handle);
    if (GSS_ERROR(major_status))
	return major_status;

    cred = (krb5_gss_cred_id_t) cred_handle;

    for (i = 0; i < sizeof(krb5_gss_inquire_cred_by_oid_ops)/
		    sizeof(krb5_gss_inquire_cred_by_oid_ops[0]); i++) {
	if (g_OID_prefix_equal(desired_object, &krb5_gss_inquire_cred_by_oid_ops[i].oid)) {
	    return (*krb5_gss_inquire_cred_by_oid_ops[i].func)(minor_status,
							       cred_handle,
							       desired_object,
							       data_set);
	}
    }

    *minor_status = EINVAL;

    return GSS_S_BAD_MECH;
}

/*
 * gss_set_sec_context_option() methods
 */
static struct {
    gss_OID_desc oid;
    OM_uint32 (*func)(OM_uint32 *, gss_ctx_id_t *, const gss_OID, const gss_buffer_t);
} krb5_gss_set_sec_context_option_ops[] = {
};

OM_uint32
krb5_gss_set_sec_context_option (OM_uint32 *minor_status,
				 gss_ctx_id_t *context_handle,
				 const gss_OID desired_object,
				 const gss_buffer_t value)
{
    int i;

    if (minor_status == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    *minor_status = 0;

    if (context_handle == NULL)
	return GSS_S_CALL_INACCESSIBLE_READ;

    if (desired_object == GSS_C_NO_OID)
	return GSS_S_CALL_INACCESSIBLE_READ;

    if (*context_handle != GSS_C_NO_CONTEXT) {
	krb5_gss_ctx_id_rec *ctx;

	if (!kg_validate_ctx_id(*context_handle))
	    return GSS_S_NO_CONTEXT;

	ctx = (krb5_gss_ctx_id_rec *) context_handle;

	if (!ctx->established)
	    return GSS_S_NO_CONTEXT;
    }

    for (i = 0; i < sizeof(krb5_gss_set_sec_context_option_ops)/
		    sizeof(krb5_gss_set_sec_context_option_ops[0]); i++) {
	if (g_OID_prefix_equal(desired_object, &krb5_gss_set_sec_context_option_ops[i].oid)) {
	    return (*krb5_gss_set_sec_context_option_ops[i].func)(minor_status,
								  context_handle,
								  desired_object,
								  value);
	}
    }

    *minor_status = EINVAL;

    return GSS_S_BAD_MECH; 
}

/*
 * gssspi_set_cred_option() methods
 */
static struct {
    gss_OID_desc oid;
    OM_uint32 (*func)(OM_uint32 *, gss_cred_id_t, const gss_OID, const gss_buffer_t);
} krb5_gssspi_set_cred_option_ops[] = {
    {
	{GSS_KRB5_COPY_CCACHE_OID_LENGTH, GSS_KRB5_COPY_CCACHE_OID},
	gss_krb5int_copy_ccache
    },
    {
	{GSS_KRB5_SET_ALLOWABLE_ENCTYPES_OID_LENGTH, GSS_KRB5_SET_ALLOWABLE_ENCTYPES_OID},
	gss_krb5int_set_allowable_enctypes
    },
    {
	{GSS_KRB5_SET_CRED_RCACHE_OID_LENGTH, GSS_KRB5_SET_CRED_RCACHE_OID},
	gss_krb5int_set_cred_rcache
    }
};

OM_uint32
krb5_gssspi_set_cred_option(OM_uint32 *minor_status,
			    gss_cred_id_t cred_handle,
			    const gss_OID desired_object,
			    const gss_buffer_t value)
{
    OM_uint32 major_status = GSS_S_FAILURE;
    int i;

    if (minor_status == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    *minor_status = 0;

    if (cred_handle == GSS_C_NO_CREDENTIAL) {
	*minor_status = KRB5_NOCREDS_SUPPLIED;
	return GSS_S_NO_CRED;
    }

    if (desired_object == GSS_C_NO_OID)
	return GSS_S_CALL_INACCESSIBLE_READ;

    major_status = krb5_gss_validate_cred(minor_status, cred_handle);
    if (GSS_ERROR(major_status))
	return major_status;

    for (i = 0; i < sizeof(krb5_gssspi_set_cred_option_ops)/
		    sizeof(krb5_gssspi_set_cred_option_ops[0]); i++) {
	if (g_OID_prefix_equal(desired_object, &krb5_gssspi_set_cred_option_ops[i].oid)) {
	    return (*krb5_gssspi_set_cred_option_ops[i].func)(minor_status,
							      cred_handle,
							      desired_object,
							      value);
	}
    }

    *minor_status = EINVAL;

    return GSS_S_BAD_MECH;
}

/*
 * gssspi_mech_invoke() methods
 */
static struct {
    gss_OID_desc oid;
    OM_uint32 (*func)(OM_uint32 *, const gss_OID, const gss_OID, gss_buffer_t);
} krb5_gssspi_mech_invoke_ops[] = {
    {
	{GSS_KRB5_REGISTER_ACCEPTOR_IDENTITY_OID_LENGTH, GSS_KRB5_REGISTER_ACCEPTOR_IDENTITY_OID},
	gss_krb5int_register_acceptor_identity
    },
    {
	{GSS_KRB5_CCACHE_NAME_OID_LENGTH, GSS_KRB5_CCACHE_NAME_OID},
	gss_krb5int_ccache_name
    },
    {
	{GSS_KRB5_FREE_LUCID_SEC_CONTEXT_OID_LENGTH, GSS_KRB5_FREE_LUCID_SEC_CONTEXT_OID},
	gss_krb5int_free_lucid_sec_context
    },
    {
	{GSS_KRB5_USE_KDC_CONTEXT_OID_LENGTH, GSS_KRB5_USE_KDC_CONTEXT_OID},
	krb5int_gss_use_kdc_context
    }
};

OM_uint32
krb5_gssspi_mech_invoke (OM_uint32 *minor_status,
			 const gss_OID desired_mech,
			 const gss_OID desired_object,
			 gss_buffer_t value)
{
    int i;

    if (minor_status == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    *minor_status = 0;

    if (desired_mech == GSS_C_NO_OID)
	return GSS_S_BAD_MECH;

    if (desired_object == GSS_C_NO_OID)
	return GSS_S_CALL_INACCESSIBLE_READ;

    for (i = 0; i < sizeof(krb5_gssspi_mech_invoke_ops)/
		    sizeof(krb5_gssspi_mech_invoke_ops[0]); i++) {
	if (g_OID_prefix_equal(desired_object, &krb5_gssspi_mech_invoke_ops[i].oid)) {
	    return (*krb5_gssspi_mech_invoke_ops[i].func)(minor_status,
							  desired_mech,
							  desired_object,
							  value);
	}
    }

    *minor_status = EINVAL;

    return GSS_S_BAD_MECH;
}

static struct gss_config krb5_mechanism = {
    { GSS_MECH_KRB5_OID_LENGTH, GSS_MECH_KRB5_OID },
    NULL,                                               
    krb5_gss_acquire_cred,
    krb5_gss_release_cred,
    krb5_gss_init_sec_context,
#ifdef LEAN_CLIENT
    NULL,
#else
    krb5_gss_accept_sec_context,
#endif
    krb5_gss_process_context_token,
    krb5_gss_delete_sec_context,
    krb5_gss_context_time,
    krb5_gss_sign,
    krb5_gss_verify,
    krb5_gss_seal,
    krb5_gss_unseal,
    krb5_gss_display_status,
    krb5_gss_indicate_mechs,
    krb5_gss_compare_name,
    krb5_gss_display_name,
    krb5_gss_import_name,
    krb5_gss_release_name,
    krb5_gss_inquire_cred,
    krb5_gss_add_cred,
#ifdef LEAN_CLIENT
    NULL,
    NULL,
#else
    krb5_gss_export_sec_context,
    krb5_gss_import_sec_context,
#endif
    krb5_gss_inquire_cred_by_mech,
    krb5_gss_inquire_names_for_mech,
    krb5_gss_inquire_context,
    krb5_gss_internal_release_oid,
    krb5_gss_wrap_size_limit,
    krb5_gss_export_name,
    NULL,                        /* store_cred */
    NULL,                        /* import_name_object */
    NULL,                        /* export_name_object */
    krb5_gss_inquire_sec_context_by_oid,
    krb5_gss_inquire_cred_by_oid,
    krb5_gss_set_sec_context_option,
    krb5_gssspi_set_cred_option,
    krb5_gssspi_mech_invoke,
    NULL,		 /* wrap_aead */	
    NULL,		 /* unwrap_aead */	
    krb5_gss_wrap_iov,
    krb5_gss_unwrap_iov,
    krb5_gss_wrap_iov_length,
    NULL,		/* complete_auth_token */
};

gss_mechanism KRB5_CALLCONV
gss_mech_initialize(void)
{
    return &krb5_mechanism;
}

#ifdef _GSS_STATIC_LINK
#include "mglueP.h"

static int gss_krb5mechglue_init(void)
{
    struct gss_mech_config mech_krb5;

    memset(&mech_krb5, 0, sizeof(mech_krb5));
    mech_krb5.mech = gss_mech_initialize();
    if (mech_krb5.mech == NULL) {
	return GSS_S_FAILURE;
    }

    mech_krb5.mechNameStr = "kerberos_v5";
    mech_krb5.mech_type = (gss_OID)gss_mech_krb5;

    gssint_register_mechinfo(&mech_krb5);

    mech_krb5.mechNameStr = "kerberos_v5_old";
    mech_krb5.mech_type = (gss_OID)gss_mech_krb5_old;
    gssint_register_mechinfo(&mech_krb5);

    mech_krb5.mechNameStr = "mskrb";
    mech_krb5.mech_type = (gss_OID)gss_mech_krb5_wrong;
    gssint_register_mechinfo(&mech_krb5);

    return 0;
}
#else
MAKE_INIT_FUNCTION(gss_krb5int_lib_init);
MAKE_FINI_FUNCTION(gss_krb5int_lib_fini);
#endif /* _GSS_STATIC_LINK */

int gss_krb5int_lib_init(void)
{
    int err;

#ifdef SHOW_INITFINI_FUNCS
    printf("gss_krb5int_lib_init\n");
#endif

    add_error_table(&et_ggss_error_table);

#ifndef LEAN_CLIENT
    err = k5_mutex_finish_init(&gssint_krb5_keytab_lock);
    if (err)
        return err;
#endif /* LEAN_CLIENT */
    err = k5_key_register(K5_KEY_GSS_KRB5_SET_CCACHE_OLD_NAME, free);
    if (err)
        return err;
    err = k5_key_register(K5_KEY_GSS_KRB5_CCACHE_NAME, free);
    if (err)
        return err;
    err = k5_key_register(K5_KEY_GSS_KRB5_ERROR_MESSAGE,
                          krb5_gss_delete_error_info);
    if (err)
        return err;
#ifndef _WIN32
    err = k5_mutex_finish_init(&kg_kdc_flag_mutex);
    if (err)
        return err;
    err = k5_mutex_finish_init(&kg_vdb.mutex);
    if (err)
	return err;
#endif
#ifdef _GSS_STATIC_LINK
    err = gss_krb5mechglue_init();
    if (err)
	return err;
#endif

    return 0;
}

void gss_krb5int_lib_fini(void)
{
#ifndef _GSS_STATIC_LINK
    if (!INITIALIZER_RAN(gss_krb5int_lib_init) || PROGRAM_EXITING()) {
# ifdef SHOW_INITFINI_FUNCS
        printf("gss_krb5int_lib_fini: skipping\n");
# endif
        return;
    }
#endif
#ifdef SHOW_INITFINI_FUNCS
    printf("gss_krb5int_lib_fini\n");
#endif
    remove_error_table(&et_k5g_error_table);

    k5_key_delete(K5_KEY_GSS_KRB5_SET_CCACHE_OLD_NAME);
    k5_key_delete(K5_KEY_GSS_KRB5_CCACHE_NAME);
    k5_mutex_destroy(&kg_vdb.mutex);
#ifndef _WIN32
    k5_mutex_destroy(&kg_kdc_flag_mutex);
#endif
#ifndef LEAN_CLIENT
    k5_mutex_destroy(&gssint_krb5_keytab_lock);
#endif /* LEAN_CLIENT */
}

#ifdef _GSS_STATIC_LINK
extern OM_uint32 gssint_lib_init(void);
#endif

OM_uint32 gss_krb5int_initialize_library (void)
{
#ifdef _GSS_STATIC_LINK
    return gssint_mechglue_initialize_library();
#else
    return CALL_INIT_FUNCTION(gss_krb5int_lib_init);
#endif
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
    unsigned char oid_buf[GSS_KRB5_EXPORT_LUCID_SEC_CONTEXT_OID_LENGTH + 6];
    gss_OID_desc req_oid;
    OM_uint32 major_status;
    gss_buffer_set_t data_set = GSS_C_NO_BUFFER_SET;
    int oversion, i;
    unsigned char *op;
    OM_uint32 nbytes;

    if (kctx == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    *kctx = NULL;

    /*
     * This absolutely horrible code is used to DER encode the
     * requested authorization data type into the last element
     * of the request OID. Oh for an ASN.1 library...
     */

    memcpy(oid_buf, GSS_KRB5_EXPORT_LUCID_SEC_CONTEXT_OID,
	   GSS_KRB5_EXPORT_LUCID_SEC_CONTEXT_OID_LENGTH);

    nbytes = 0;
    oversion = version;
    while (version) {
	nbytes++;
	version >>= 7;
    }
    version = oversion;
    op = oid_buf + GSS_KRB5_EXPORT_LUCID_SEC_CONTEXT_OID_LENGTH + nbytes;
    i = -1;
    while (version) {
	op[i] = (unsigned char)version & 0x7f;
	if (i != -1)
	    op[i] |= 0x80;
	i--;
	version >>= 7;
    }

    req_oid.elements = oid_buf;
    req_oid.length = GSS_KRB5_EXPORT_LUCID_SEC_CONTEXT_OID_LENGTH + nbytes;
    assert(req_oid.length <= sizeof(oid_buf));

    major_status = gss_inquire_sec_context_by_oid(minor_status,
						  *context_handle,
						  &req_oid,
						  &data_set);
    if (GSS_ERROR(major_status))
	return major_status;

    if (data_set == GSS_C_NO_BUFFER_SET ||
        data_set->count != 1 ||
	data_set->elements[0].length != sizeof(void *)) {
	*minor_status = EINVAL;
	return GSS_S_FAILURE;
    }

    *kctx = *((void **)data_set->elements[0].value);

    /* Clean up the context state (it is an error for
     * someone to attempt to use this context again)
     */
    (void)krb5_gss_delete_sec_context(minor_status, context_handle, NULL);
    *context_handle = GSS_C_NO_CONTEXT;

    generic_gss_release_buffer_set(&nbytes, &data_set);

    return GSS_S_COMPLETE;
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

    req_buffer.length = strlen(keytab);
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

#if 0
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
#endif

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

#if 0
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
#endif

OM_uint32 KRB5_CALLCONV
gsskrb5_extract_authtime_from_sec_context(OM_uint32 *minor_status,
					  gss_ctx_id_t context_handle,
					  krb5_timestamp *authtime)
{
    static const gss_OID_desc const req_oid = {
	GSS_KRB5_EXTRACT_AUTHTIME_FROM_SEC_CONTEXT_OID_LENGTH,
	GSS_KRB5_EXTRACT_AUTHTIME_FROM_SEC_CONTEXT_OID };
    OM_uint32 major_status;
    gss_buffer_set_t data_set = GSS_C_NO_BUFFER_SET;

    if (authtime == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    major_status = gss_inquire_sec_context_by_oid(minor_status,
						  context_handle,
						  (const gss_OID)&req_oid,
						  &data_set);
    if (major_status != GSS_S_COMPLETE)
	return major_status;

    if (data_set == GSS_C_NO_BUFFER_SET ||
        data_set->count != 1 ||
	data_set->elements[0].length != sizeof(*authtime)) {
	*minor_status = EINVAL;
	return GSS_S_FAILURE;
    }

    *authtime = *((krb5_timestamp *)data_set->elements[0].value);

    gss_release_buffer_set(minor_status, &data_set);

    *minor_status = 0;

    return GSS_S_COMPLETE;
}


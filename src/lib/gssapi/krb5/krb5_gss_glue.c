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
 * $Id$
 */

#include "gssapiP_krb5.h"
#include "mglueP.h"

gss_mechanism KRB5_CALLCONV gss_mech_initialize(void);

/*
 * The krb5 mechanism provides two mech OIDs; use this initializer to
 * ensure that both dispatch tables contain identical function
 * pointers.
 */
#ifndef LEAN_CLIENT
#define KRB5_GSS_CONFIG_INIT                            \
    NULL,                                               \
    krb5_gss_acquire_cred,                              \
    krb5_gss_release_cred,                              \
    krb5_gss_init_sec_context,                          \
    krb5_gss_accept_sec_context,                        \
    krb5_gss_process_context_token,                     \
    krb5_gss_delete_sec_context,                        \
    krb5_gss_context_time,                              \
    krb5_gss_sign,                                      \
    krb5_gss_verify,                                    \
    krb5_gss_seal,                                      \
    krb5_gss_unseal,                                    \
    krb5_gss_display_status,                            \
    krb5_gss_indicate_mechs,                            \
    krb5_gss_compare_name,                              \
    krb5_gss_display_name,                              \
    krb5_gss_import_name,                               \
    krb5_gss_release_name,                              \
    krb5_gss_inquire_cred,                              \
    krb5_gss_add_cred,                                  \
    krb5_gss_export_sec_context,                        \
    krb5_gss_import_sec_context,                        \
    krb5_gss_inquire_cred_by_mech,                      \
    krb5_gss_inquire_names_for_mech,                    \
    krb5_gss_inquire_context,                           \
    krb5_gss_internal_release_oid,                      \
    krb5_gss_wrap_size_limit,                           \
    krb5_gss_export_name,                               \
    NULL,                        /* store_cred */\
    NULL,                        /* import_name_object */\
    NULL,                        /* export_name_object */\
    krb5_gss_inquire_sec_context_by_oid,	\
    krb5_gss_inquire_cred_by_oid,		\
    krb5_gss_set_sec_context_option,		\
    krb5_gssspi_set_cred_option,		\
    krb5_gssspi_mech_invoke,			\
    NULL,		 /* wrap_aead */	\
    NULL,		 /* unwrap_aead */	\
    krb5_gss_wrap_iov,				\
    krb5_gss_unwrap_iov,			\
    krb5_gss_wrap_iov_length,			\
    NULL,					

#else   /* LEAN_CLIENT */

#define KRB5_GSS_CONFIG_INIT                            \
    NULL,                                               \
    krb5_gss_acquire_cred,                              \
    krb5_gss_release_cred,                              \
    krb5_gss_init_sec_context,                          \
    NULL,                                               \
    krb5_gss_process_context_token,                     \
    krb5_gss_delete_sec_context,                        \
    krb5_gss_context_time,                              \
    krb5_gss_sign,                                      \
    krb5_gss_verify,                                    \
    krb5_gss_seal,                                      \
    krb5_gss_unseal,                                    \
    krb5_gss_display_status,                            \
    krb5_gss_indicate_mechs,                            \
    krb5_gss_compare_name,                              \
    krb5_gss_display_name,                              \
    krb5_gss_import_name,                               \
    krb5_gss_release_name,                              \
    krb5_gss_inquire_cred,                              \
    krb5_gss_add_cred,                                  \
    NULL,                                               \
    NULL,                                               \
    krb5_gss_inquire_cred_by_mech,                      \
    krb5_gss_inquire_names_for_mech,                    \
    krb5_gss_inquire_context,                           \
    krb5_gss_internal_release_oid,                      \
    krb5_gss_wrap_size_limit,                           \
    krb5_gss_export_name,                               \
    NULL,                        /* store_cred */\
    NULL,                        /* import_name_object */\
    NULL,                        /* export_name_object */\
    krb5_gss_inquire_sec_context_by_oid,	\
    krb5_gss_inquire_cred_by_oid,		\
    krb5_gss_set_sec_context_option,		\
    krb5_gssspi_set_cred_option,		\
    krb5_gssspi_mech_invoke,			\
    NULL,		 /* wrap_aead */	\
    NULL,		 /* unwrap_aead */	\
    krb5_gss_wrap_iov,				\
    krb5_gss_unwrap_iov,			\
    krb5_gss_wrap_iov_length,			\
    NULL,					

#endif /* LEAN_CLIENT */

static const gss_OID_desc krb5_gss_options_oid_array[] = {
    {GSS_KRB5_COPY_CCACHE_OID_LENGTH, GSS_KRB5_COPY_CCACHE_OID},
#define krb5_gss_copy_ccache_oid (&krb5_gss_options_oid_array[0])
    {GSS_KRB5_GET_TKT_FLAGS_OID_LENGTH, GSS_KRB5_GET_TKT_FLAGS_OID},
#define krb5_gss_get_tkt_flags_oid (&krb5_gss_options_oid_array[1])
    {GSS_KRB5_EXPORT_LUCID_SEC_CONTEXT_OID_LENGTH, GSS_KRB5_EXPORT_LUCID_SEC_CONTEXT_OID},
#define krb5_gss_export_lucid_sec_context_oid (&krb5_gss_options_oid_array[2])
    {GSS_KRB5_SET_ALLOWABLE_ENCTYPES_OID_LENGTH, GSS_KRB5_SET_ALLOWABLE_ENCTYPES_OID},
#define krb5_gss_set_allowable_enctypes_oid (&krb5_gss_options_oid_array[3])
    {GSS_KRB5_REGISTER_ACCEPTOR_IDENTITY_OID_LENGTH, GSS_KRB5_REGISTER_ACCEPTOR_IDENTITY_OID},
#define krb5_gss_register_acceptor_identity_oid (&krb5_gss_options_oid_array[4])
    {GSS_KRB5_CCACHE_NAME_OID_LENGTH, GSS_KRB5_CCACHE_NAME_OID},
#define krb5_gss_ccache_name_oid (&krb5_gss_options_oid_array[5])
    {GSS_KRB5_FREE_LUCID_SEC_CONTEXT_OID_LENGTH, GSS_KRB5_FREE_LUCID_SEC_CONTEXT_OID},
#define krb5_gss_free_lucid_sec_context_oid (&krb5_gss_options_oid_array[6])
    {GSS_KRB5_USE_KDC_CONTEXT_OID_LENGTH, GSS_KRB5_USE_KDC_CONTEXT_OID},
#define krb5_gss_use_kdc_context_oid (&krb5_gss_options_oid_array[7])
    {GSS_KRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT_OID_LENGTH, GSS_KRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT_OID},
#define krb5_gss_extract_authz_data_from_sec_context_oid (&krb5_gss_options_oid_array[8])
    {GSS_KRB5_GET_SUBKEY_OID_LENGTH, GSS_KRB5_GET_SUBKEY_OID}, /* DEPRECATED */
#define krb5_gss_get_subkey_oid (&krb5_gss_options_oid_array[9])
    {9, "\x2b\x06\x01\x04\x01\xa9\x4a\x13\x05"}, /* GSS_C_INQ_SESSION_KEY */
#define krb5_gss_inq_session_key_oid (&krb5_gss_options_oid_array[10])
    {GSS_KRB5_SET_CRED_RCACHE_OID_LENGTH, GSS_KRB5_SET_CRED_RCACHE_OID},
#define krb5_gss_set_cred_rcache_oid (&krb5_gss_options_oid_array[11])
    {GSS_KRB5_SET_ACCEPTOR_ALIAS_OID_LENGTH, GSS_KRB5_SET_ACCEPTOR_ALIAS_OID},
#define krb5_gss_set_acceptor_alias_oid (&krb5_gss_options_oid_array[12])
};

OM_uint32
krb5_gss_inquire_sec_context_by_oid (OM_uint32 *minor_status,
			     const gss_ctx_id_t context_handle,
			     const gss_OID desired_object,
			     gss_buffer_set_t *data_set)
{
    gss_buffer_set_desc rep_set = {0, NULL};
    gss_buffer_desc rep;
    OM_uint32 major_status = GSS_S_FAILURE;
    union {
	krb5_flags ticket_flags;
	krb5_keyblock *key;
    } u;

    if (g_OID_equal(desired_object, krb5_gss_get_tkt_flags_oid)) {
	/* gss_krb5_get_tkt_flags() */
	major_status = gss_krb5int_get_tkt_flags(minor_status,
						 context_handle,
						 &u.ticket_flags);

	rep.value = &u.ticket_flags;
	rep.length = sizeof(u.ticket_flags);
    } else if (desired_object->length >= krb5_gss_extract_authz_data_from_sec_context_oid->length &&
       memcmp(desired_object->elements, krb5_gss_extract_authz_data_from_sec_context_oid->elements,
	krb5_gss_extract_authz_data_from_sec_context_oid->length) == 0) {
	int ad_type = 0, i;
	unsigned char *cp;

	*minor_status = 0;

	/* Determine authorization data type from DER encoded OID suffix */
	cp = desired_object->elements;
	cp += krb5_gss_extract_authz_data_from_sec_context_oid->length;

	for (i = 0;
	     i < desired_object->length -
		krb5_gss_extract_authz_data_from_sec_context_oid->length;
	     i++)
	{
	    ad_type = (ad_type << 7) | (cp[i] & 0x7f);
	    if ((cp[i] & 0x80) == 0)
		break;
	    /* XXX should we return an error if there is another arc */
	}

	if (ad_type == 0)
	    return GSS_S_FAILURE;

	major_status = gss_krb5int_extract_authz_data_from_sec_context(
		minor_status,
		context_handle,
		ad_type,
		&rep_set);

	for (i = 0; i < rep_set.count; i++) {
	    major_status = generic_gss_add_buffer_set_member(minor_status, &rep_set.elements[i],
						     data_set);
	    if (major_status != GSS_S_COMPLETE) {
		free(rep_set.elements);
		return major_status;
	    }
	}

	free(rep_set.elements);

	return GSS_S_COMPLETE;
    } else if (g_OID_equal(desired_object, krb5_gss_get_subkey_oid)) {
	/* DEPRECATED */
	major_status = gss_krb5int_get_subkey(context_handle, &u.key);
	if (major_status != GSS_S_COMPLETE) {
	    return major_status;
	}

	*minor_status = 0;

	rep.value = &u.key;
	rep.length = sizeof(u.key);
    } else if (g_OID_equal(desired_object, krb5_gss_inq_session_key_oid)) {
	major_status = gss_krb5int_get_subkey(context_handle, &u.key);
	*minor_status = 0;

	if (major_status == GSS_S_COMPLETE) {
	    assert(u.key->contents != NULL);

	    rep.value = u.key->contents;
	    rep.length = u.key->length;

	    free(u.key);
	}
    } else {
	*minor_status = EINVAL;
	return GSS_S_BAD_MECH;
    }
    if (major_status != GSS_S_COMPLETE) {
	return major_status;
    }
    return generic_gss_add_buffer_set_member(minor_status, &rep, data_set);
}

OM_uint32 KRB5_CALLCONV
krb5_gss_inquire_cred_by_oid(OM_uint32 *minor_status,
		     const gss_cred_id_t cred_handle,
		     const gss_OID desired_object,
		     gss_buffer_set_t *data_set)
{
    *minor_status = EINVAL;
    return GSS_S_BAD_MECH;
}

OM_uint32 KRB5_CALLCONV
krb5_gss_set_sec_context_option (OM_uint32 *minor_status,
			 gss_ctx_id_t *context_handle,
			 const gss_OID desired_object,
			 const gss_buffer_t value)
{
    OM_uint32 major_status;

    if (g_OID_equal(desired_object, krb5_gss_export_lucid_sec_context_oid)) {
	struct krb5_gss_export_lucid_sec_context_req *req;

	assert(value->length == sizeof(*req));
	req = (struct krb5_gss_export_lucid_sec_context_req *)value->value;

	major_status = gss_krb5int_export_lucid_sec_context(minor_status,
							    context_handle,
							    req->version,
							    &req->kctx);
    } else {
	*minor_status = EINVAL;
	return GSS_S_BAD_MECH;
    }

    return major_status;
}

OM_uint32 KRB5_CALLCONV
krb5_gssspi_set_cred_option(OM_uint32 *minor_status,
		    gss_cred_id_t cred_handle,
		    const gss_OID desired_object,
		    const gss_buffer_t value)
{
    OM_uint32 major_status;

    if (g_OID_equal(desired_object, krb5_gss_copy_ccache_oid)) {
	krb5_ccache out_ccache;

	assert(value->length == sizeof(out_ccache));
	out_ccache = (krb5_ccache)value->value;

	major_status = gss_krb5int_copy_ccache(minor_status,
					       cred_handle,
					       out_ccache);
    } else if (g_OID_equal(desired_object, krb5_gss_set_allowable_enctypes_oid)) {
	struct krb5_gss_set_allowable_enctypes_req *req;

	assert(value->length == sizeof(*req));
	req = (struct krb5_gss_set_allowable_enctypes_req *)value->value;

	major_status = gss_krb5int_set_allowable_enctypes(minor_status,
							  cred_handle,
							  req->num_ktypes,
							  req->ktypes);
    } else if (g_OID_equal(desired_object, krb5_gss_set_cred_rcache_oid)) {
	krb5_rcache rcache;

	assert(value->length == sizeof(rcache));
	rcache = (krb5_rcache)value->value;

	major_status = gss_krb5int_set_cred_rcache(minor_status,
						   cred_handle, 
						   rcache);
    } else {
	*minor_status = EINVAL;
	return GSS_S_BAD_MECH;
    }

    return major_status;
}

OM_uint32 KRB5_CALLCONV
krb5_gssspi_mech_invoke (OM_uint32 *minor_status,
		 const gss_OID desired_mech,
		 const gss_OID desired_object,
		 gss_buffer_t value)
{
    OM_uint32 major_status;

    if (g_OID_equal(desired_object, krb5_gss_register_acceptor_identity_oid)) {
	assert(value->length == sizeof(void *));
	major_status = gss_krb5int_register_acceptor_identity(
			(const char *)value->value);
    } else if (g_OID_equal(desired_object, krb5_gss_ccache_name_oid)) {
	struct krb5_gss_ccache_name_req *req;

	assert(value->length == sizeof(*req));
	req = (struct krb5_gss_ccache_name_req *)value->value;

	major_status = gss_krb5int_ccache_name(minor_status,
					       req->name,
					       &req->out_name);
    } else if (g_OID_equal(desired_object, krb5_gss_free_lucid_sec_context_oid)) {
	assert(value->length == sizeof(void *));
	major_status = gss_krb5int_free_lucid_sec_context(minor_status, value->value);
    } else if (g_OID_equal(desired_object, krb5_gss_use_kdc_context_oid)) {
	assert(value->length == 0);
	major_status = (OM_uint32)krb5int_gss_use_kdc_context();
    } else {
	*minor_status = EINVAL;
	return GSS_S_BAD_MECH;
    }

    return major_status;
} 

static struct gss_config krb5_mechanism = {
    { GSS_MECH_KRB5_OID_LENGTH, GSS_MECH_KRB5_OID },
    KRB5_GSS_CONFIG_INIT
};

gss_mechanism KRB5_CALLCONV
gss_mech_initialize(void)
{
    return &krb5_mechanism;
}

#ifdef _GSS_STATIC_LINK
#include "mglueP.h"

extern gss_mechanism KRB5_CALLCONV gss_mech_initialize(void);

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

    mech_krb5.mechNameStr = "kerberos_v5_ms";
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


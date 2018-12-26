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

#include "mglueP.h"

OM_uint32 KRB5_CALLCONV
gss_query_meta_data(OM_uint32 *minor_status,
		    gss_const_OID mech_oid,
		    gss_cred_id_t cred_handle,
		    gss_ctx_id_t *context_handle,
		    const gss_name_t targ_name,
		    OM_uint32 req_flags,
		    gss_buffer_t meta_data)
{
    OM_uint32		status, minor;
    gss_union_ctx_id_t	ctx;
    gss_union_name_t	union_name;
    gss_mechanism	mech;
    gss_OID		mech_type;
    gss_ctx_id_t	internal_ctx = GSS_C_NO_CONTEXT;
    gss_cred_id_t	internal_cred = GSS_C_NO_CREDENTIAL;
    gss_name_t		internal_name = GSS_C_NO_NAME;

    if (minor_status == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    if (context_handle == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    if (meta_data == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    *minor_status = 0;

    meta_data->length = 0;
    meta_data->value = NULL;

    ctx = (gss_union_ctx_id_t)*context_handle;
    if (ctx == NULL)
	mech = gssint_get_mechanism((gss_OID)mech_oid);
    else
	mech = gssint_get_mechanism(ctx->mech_type);

    if (mech == NULL)
	return GSS_S_BAD_MECH;
    if (mech->gss_query_meta_data == NULL)
	return GSS_S_UNAVAILABLE;

    mech_type = &mech->mech_type;

    if (cred_handle != GSS_C_NO_CREDENTIAL)
	internal_cred = gssint_get_mechanism_cred((gss_union_cred_t)cred_handle,
						  mech_type);

    union_name = (gss_union_name_t)targ_name;
    if (union_name != NULL) {
	if (union_name->mech_type != GSS_C_NO_OID &&
	    g_OID_equal(union_name->mech_type, mech_type)) {
	    internal_name = union_name->mech_name;
	} else {
	    status = gssint_import_internal_name(minor_status, mech_type,
						 union_name,
						 &internal_name);
	    if (GSS_ERROR(status))
		return status;
	}
    }

    status = mech->gss_query_meta_data(minor_status,
				       mech_type,
				       internal_cred,
				       ctx ? &ctx->internal_ctx_id : &internal_ctx,
				       internal_name,
				       req_flags,
				       meta_data);
    if (status == GSS_S_COMPLETE) {
	if (ctx == NULL && internal_ctx != GSS_C_NO_CONTEXT) {
	    /* Allocate a union context handle to wrap new context */
	    ctx = (gss_union_ctx_id_t)calloc(1, sizeof(*ctx));
	    if (ctx == NULL) {
		*minor_status = ENOMEM;
		gssint_delete_internal_sec_context(&minor,
						   &mech->mech_type,
						   &internal_ctx,
						   GSS_C_NO_BUFFER);
		return GSS_S_FAILURE;
	    }

	    status = generic_gss_copy_oid(minor_status,
					  mech_type,
					  &ctx->mech_type);
	    if (status != GSS_S_COMPLETE) {
		gssint_delete_internal_sec_context(&minor,
						   ctx->mech_type,
						   &internal_ctx,
						   GSS_C_NO_BUFFER);
		free(ctx);
		return status;
	    }

	    ctx->loopback = ctx;
	    ctx->internal_ctx_id = internal_ctx;
	    *context_handle = (gss_ctx_id_t)ctx;
	}
    } else
	map_error(minor_status, mech);

    return status;
}

OM_uint32 KRB5_CALLCONV
gss_exchange_meta_data(OM_uint32 *minor_status,
		       gss_const_OID mech_oid,
		       gss_cred_id_t cred_handle,
		       gss_ctx_id_t *context_handle,
		       const gss_name_t targ_name,
		       OM_uint32 req_flags,
		       gss_const_buffer_t meta_data)
{
    OM_uint32		status, minor;
    gss_union_ctx_id_t	ctx;
    gss_union_name_t	union_name;
    gss_mechanism	mech;
    gss_OID		mech_type;
    gss_ctx_id_t	internal_ctx = GSS_C_NO_CONTEXT;
    gss_cred_id_t	internal_cred = GSS_C_NO_CREDENTIAL;
    gss_name_t		internal_name = GSS_C_NO_NAME;

    if (minor_status == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    if (context_handle == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    if (meta_data == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    *minor_status = 0;

    ctx = (gss_union_ctx_id_t)*context_handle;
    if (ctx == NULL)
	mech = gssint_get_mechanism((gss_OID)mech_oid);
    else
	mech = gssint_get_mechanism(ctx->mech_type);

    if (mech == NULL)
	return GSS_S_BAD_MECH;
    if (mech->gss_exchange_meta_data == NULL)
	return GSS_S_UNAVAILABLE;

    mech_type = &mech->mech_type;

    if (cred_handle != GSS_C_NO_CREDENTIAL)
	internal_cred = gssint_get_mechanism_cred((gss_union_cred_t)cred_handle,
						  mech_type);

    union_name = (gss_union_name_t)targ_name;
    if (union_name != NULL) {
	if (union_name->mech_type != GSS_C_NO_OID &&
	    g_OID_equal(union_name->mech_type, mech_type)) {
	    internal_name = union_name->mech_name;
	} else {
	    status = gssint_import_internal_name(minor_status, mech_type,
						 union_name,
						 &internal_name);
	    if (GSS_ERROR(status))
		return status;
	}
    }

    status = mech->gss_exchange_meta_data(minor_status,
					  mech_type,
					  internal_cred,
					  ctx ? &ctx->internal_ctx_id : &internal_ctx,
					  internal_name,
					  req_flags,
					  meta_data);
    if (status == GSS_S_COMPLETE) {
	if (ctx == NULL && internal_ctx != GSS_C_NO_CONTEXT) {
	    /* Allocate a union context handle to wrap new context */
	    ctx = (gss_union_ctx_id_t)calloc(1, sizeof(*ctx));
	    if (ctx == NULL) {
		*minor_status = ENOMEM;
		gssint_delete_internal_sec_context(&minor,
						   &mech->mech_type,
						   &internal_ctx,
						   GSS_C_NO_BUFFER);
		return GSS_S_FAILURE;
	    }

	    status = generic_gss_copy_oid(minor_status,
					  mech_type,
					  &ctx->mech_type);
	    if (status != GSS_S_COMPLETE) {
		gssint_delete_internal_sec_context(&minor,
						   ctx->mech_type,
						   &internal_ctx,
						   GSS_C_NO_BUFFER);
		free(ctx);
		return status;
	    }

	    ctx->loopback = ctx;
	    ctx->internal_ctx_id = internal_ctx;
	    *context_handle = (gss_ctx_id_t)ctx;
	}
    } else
	map_error(minor_status, mech);

    return status;
}

OM_uint32 KRB5_CALLCONV
gss_query_mechanism_info(OM_uint32 *minor_status,
			 gss_const_OID mech_oid,
			 unsigned char auth_scheme[16])
{
    OM_uint32       status;
    gss_mechanism   mech;

    if (minor_status == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;
    if (auth_scheme == NULL)
	return GSS_S_CALL_INACCESSIBLE_READ;

    *minor_status = 0;

    memset(auth_scheme, 0, 16);

    mech = gssint_get_mechanism((gss_OID)mech_oid);
    if (mech == NULL)
	return GSS_S_BAD_MECH;
    if (mech->gss_query_mechanism_info == NULL)
	return GSS_S_UNAVAILABLE;

    status = mech->gss_query_mechanism_info(minor_status,
					    mech_oid,
					    auth_scheme);
    if (GSS_ERROR(status))
	map_error(minor_status, mech);

    return status;
}

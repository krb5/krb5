/* #pragma ident	"@(#)g_init_sec_context.c	1.20	03/10/24 SMI" */

/*
 * Copyright 1996 by Sun Microsystems, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of Sun Microsystems not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. Sun Microsystems makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * SUN MICROSYSTEMS DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL SUN MICROSYSTEMS BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 *  glue routine for gss_init_sec_context
 */

#include "mglueP.h"
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>

static OM_uint32
val_init_sec_ctx_args(
    OM_uint32 *minor_status,
    gss_cred_id_t claimant_cred_handle,
    gss_ctx_id_t *context_handle,
    gss_name_t target_name,
    gss_OID req_mech_type,
    OM_uint32 req_flags,
    OM_uint32 time_req,
    gss_channel_bindings_t input_chan_bindings,
    gss_buffer_t input_token,
    gss_OID *actual_mech_type,
    gss_buffer_t output_token,
    OM_uint32 *ret_flags,
    OM_uint32 *time_rec)
{

    /* Initialize outputs. */

    if (minor_status != NULL)
	*minor_status = 0;

    if (actual_mech_type != NULL)
	*actual_mech_type = GSS_C_NO_OID;

    if (output_token != GSS_C_NO_BUFFER) {
	output_token->length = 0;
	output_token->value = NULL;
    }

    /* Validate arguments. */

    if (minor_status == NULL)
	return (GSS_S_CALL_INACCESSIBLE_WRITE);

    if (context_handle == NULL)
	return (GSS_S_CALL_INACCESSIBLE_WRITE | GSS_S_NO_CONTEXT);

    if (target_name == NULL)
	return (GSS_S_CALL_INACCESSIBLE_READ | GSS_S_BAD_NAME);

    if (output_token == NULL)
	return (GSS_S_CALL_INACCESSIBLE_WRITE);

    return (GSS_S_COMPLETE);
}


OM_uint32 KRB5_CALLCONV
gss_init_sec_context (minor_status,
                      claimant_cred_handle,
                      context_handle,
                      target_name,
                      req_mech_type,
                      req_flags,
                      time_req,
                      input_chan_bindings,
                      input_token,
                      actual_mech_type,
                      output_token,
                      ret_flags,
                      time_rec)

OM_uint32 *		minor_status;
gss_cred_id_t		claimant_cred_handle;
gss_ctx_id_t *		context_handle;
gss_name_t		target_name;
gss_OID			req_mech_type;
OM_uint32		req_flags;
OM_uint32		time_req;
gss_channel_bindings_t	input_chan_bindings;
gss_buffer_t		input_token;
gss_OID *		actual_mech_type;
gss_buffer_t		output_token;
OM_uint32 *		ret_flags;
OM_uint32 *		time_rec;

{
    OM_uint32		status, temp_minor_status;
    gss_union_name_t	union_name;
    gss_union_cred_t	union_cred;
    gss_name_t		internal_name;
    gss_union_ctx_id_t	union_ctx_id;
    gss_OID		selected_mech;
    gss_mechanism	mech;
    gss_cred_id_t	input_cred_handle;

    status = val_init_sec_ctx_args(minor_status,
				   claimant_cred_handle,
				   context_handle,
				   target_name,
				   req_mech_type,
				   req_flags,
				   time_req,
				   input_chan_bindings,
				   input_token,
				   actual_mech_type,
				   output_token,
				   ret_flags,
				   time_rec);
    if (status != GSS_S_COMPLETE)
	return (status);

    status = gssint_select_mech_type(minor_status, req_mech_type,
				     &selected_mech);
    if (status != GSS_S_COMPLETE)
	return (status);

    union_name = (gss_union_name_t)target_name;

    /*
     * obtain the gss mechanism information for the requested
     * mechanism.  If mech_type is NULL, set it to the resultant
     * mechanism
     */
    mech = gssint_get_mechanism(selected_mech);
    if (mech == NULL)
	return (GSS_S_BAD_MECH);

    if (mech->gss_init_sec_context == NULL)
	return (GSS_S_UNAVAILABLE);

    /*
     * If target_name is mechanism_specific, then it must match the
     * mech_type that we're about to use.  Otherwise, do an import on
     * the external_name form of the target name.
     */
    if (union_name->mech_type &&
	g_OID_equal(union_name->mech_type, selected_mech)) {
	internal_name = union_name->mech_name;
    } else {
	if ((status = gssint_import_internal_name(minor_status, selected_mech,
						 union_name,
						 &internal_name)) != GSS_S_COMPLETE)
	    return (status);
    }

    /*
     * if context_handle is GSS_C_NO_CONTEXT, allocate a union context
     * descriptor to hold the mech type information as well as the
     * underlying mechanism context handle. Otherwise, cast the
     * value of *context_handle to the union context variable.
     */

    if(*context_handle == GSS_C_NO_CONTEXT) {
	status = GSS_S_FAILURE;
	union_ctx_id = (gss_union_ctx_id_t)
	    malloc(sizeof(gss_union_ctx_id_desc));
	if (union_ctx_id == NULL)
	    goto end;

	if (generic_gss_copy_oid(&temp_minor_status, selected_mech,
				 &union_ctx_id->mech_type) != GSS_S_COMPLETE) {
	    free(union_ctx_id);
	    goto end;
	}

	/* copy the supplied context handle */
	union_ctx_id->internal_ctx_id = GSS_C_NO_CONTEXT;
    } else
	union_ctx_id = (gss_union_ctx_id_t)*context_handle;

    /*
     * get the appropriate cred handle from the union cred struct.
     * defaults to GSS_C_NO_CREDENTIAL if there is no cred, which will
     * use the default credential.
     */
    union_cred = (gss_union_cred_t) claimant_cred_handle;
    input_cred_handle = gssint_get_mechanism_cred(union_cred, selected_mech);

    /*
     * now call the approprate underlying mechanism routine
     */

    status = mech->gss_init_sec_context(
	minor_status,
	input_cred_handle,
	&union_ctx_id->internal_ctx_id,
	internal_name,
	gssint_get_public_oid(selected_mech),
	req_flags,
	time_req,
	input_chan_bindings,
	input_token,
	actual_mech_type,
	output_token,
	ret_flags,
	time_rec);

    if (status != GSS_S_COMPLETE && status != GSS_S_CONTINUE_NEEDED) {
	/*
	 * the spec says (the preferred) method is to delete all
	 * context info on the first call to init, and on all
	 * subsequent calls make the caller responsible for
	 * calling gss_delete_sec_context
	 * However if the mechanism decided to null the internal context
	 * we should also null the union context to avoid dereferencing
	 * a null pointer in other gssapi calls
	 */
	map_error(minor_status, mech);
	if (union_ctx_id->internal_ctx_id == GSS_C_NO_CONTEXT)
	    *context_handle = GSS_C_NO_CONTEXT;
	if (*context_handle == GSS_C_NO_CONTEXT) {
	    free(union_ctx_id->mech_type->elements);
	    free(union_ctx_id->mech_type);
	    free(union_ctx_id);
	}
    } else if (*context_handle == GSS_C_NO_CONTEXT) {
	union_ctx_id->loopback = union_ctx_id;
	*context_handle = (gss_ctx_id_t)union_ctx_id;
    }

end:
    if (union_name->mech_name == NULL ||
	union_name->mech_name != internal_name) {
	(void) gssint_release_internal_name(&temp_minor_status,
					    selected_mech, &internal_name);
    }

    return(status);
}

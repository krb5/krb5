#ident  "@(#)gss_init_sec_context.c 1.20     95/08/07 SMI"

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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>

OM_uint32
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

OM_uint32 FAR *		minor_status;
gss_cred_id_t		claimant_cred_handle;
gss_ctx_id_t *		context_handle;
gss_name_t		target_name;
gss_OID			req_mech_type;
OM_uint32		req_flags;
OM_uint32		time_req;
gss_channel_bindings_t	input_chan_bindings;
gss_buffer_t		input_token;
gss_OID FAR *		actual_mech_type;
gss_buffer_t		output_token;
OM_uint32 FAR *		ret_flags;
OM_uint32 FAR *		time_rec;

{
    OM_uint32		status, temp_status, temp_minor_status;
    gss_union_name_t	union_name;
    gss_name_t		internal_name;
    gss_union_ctx_id_t	union_ctx_id;
    gss_OID		mech_type = (gss_OID) req_mech_type;
    gss_mechanism	mech;

    gss_initialize();

    if (context_handle == NULL)
	return GSS_S_NO_CONTEXT;
    
    /*
     * obtain the gss mechanism information for the requested
     * mechanism.  If mech_type is NULL, set it to the resultant
     * mechanism
     */
    mech = __gss_get_mechanism (mech_type);
    if (mech == NULL)
	return (GSS_S_BAD_MECH);

    if (mech_type == GSS_C_NULL_OID)
	mech_type = &mech->mech_type;

    /* 
     * Get the internal name for the mechanism requested from 
     * the supplied target name.
     */

    union_name = (gss_union_name_t) target_name;
    
    if ((temp_status = __gss_import_internal_name (
					     minor_status,
					     mech_type,
					     union_name,
					     &internal_name)))
	return (GSS_S_BAD_NAME);

    /*
     * if context_handle is GSS_C_NO_CONTEXT, allocate a union context
     * descriptor to hold the mech type information as well as the
     * underlying mechanism context handle. Otherwise, cast the
     * value of *context_handle to the union context variable.
     */
    
    if(*context_handle == GSS_C_NO_CONTEXT) {
	union_ctx_id = (gss_union_ctx_id_t)
	    malloc(sizeof(gss_union_ctx_id_desc));

	union_ctx_id->mech_type = (gss_OID)
	    malloc(sizeof(gss_OID_desc));

	/* copy in the mech type information */

	union_ctx_id->mech_type->elements = (void *)
	    malloc(mech_type->length);

	union_ctx_id->mech_type->length = mech_type->length;
	memcpy(union_ctx_id->mech_type->elements, mech_type->elements,
	       mech_type->length);

	/* copy the supplied context handle */

	union_ctx_id->internal_ctx_id = *context_handle;
    } else
	union_ctx_id = *context_handle;
    
    /*
     * now call the approprate underlying mechanism routine 
     */
    
    if (mech->gss_init_sec_context) {
	status = mech->gss_init_sec_context(
					    mech->context,
					    minor_status,
					    claimant_cred_handle,
					    &union_ctx_id->internal_ctx_id,
					    internal_name,
					    mech_type,
					    req_flags,
					    time_req,
					    input_chan_bindings,
					    input_token,
					    actual_mech_type,
					    output_token,
					    ret_flags,
					    time_rec);

	if (*context_handle == GSS_C_NO_CONTEXT)
	    *context_handle = (gss_ctx_id_t) union_ctx_id;

    } else
	status = GSS_S_BAD_BINDINGS;

    temp_status = __gss_release_internal_name(
					&temp_minor_status,
					mech_type,
					&internal_name);
	    
    if (temp_status != GSS_S_COMPLETE) {
	if (minor_status)
	    *minor_status = temp_minor_status;
	return(GSS_S_BAD_NAME);
    }
    
    return(status);
}

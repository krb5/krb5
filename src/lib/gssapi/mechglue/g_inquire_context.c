
#ident	"@(#)g_inquire_context.c 1.2     96/01/18 SMI"

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
 *  glue routine for gss_inquire_context
 */

#include "mglueP.h"

static OM_uint32
convert_name_to_union_name(
	gss_mechanism	mech,
	OM_uint32 *minor_status,
	gss_name_t * internal_name);


/* Last argument new for V2 */
OM_uint32 gss_inquire_context(
	    minor_status,
	    context_handle,
	    src_name,
	    targ_name,
	    lifetime_rec,
	    mech_type,
	    ctx_flags,
	    locally_initiated,
	    open)

OM_uint32 *	minor_status;
gss_ctx_id_t	context_handle;
gss_name_t *	src_name;
gss_name_t *	targ_name;
OM_uint32 *	lifetime_rec;
gss_OID *	mech_type;
OM_uint32 *	ctx_flags;
int *           locally_initiated;
int *		open;


{
    gss_union_ctx_id_t	ctx;
    gss_mechanism	mech;
    OM_uint32		status, temp_minor, temp_major;
    
    gss_initialize();

    /* if the context_handle is Null, return NO_CONTEXT error */
    
    if(context_handle == GSS_C_NO_CONTEXT)
	return(GSS_S_NO_CONTEXT);
    
    /*
     * select the approprate underlying mechanism routine and
     * call it.
     */
    
    ctx = (gss_union_ctx_id_t) context_handle;
    mech = __gss_get_mechanism (ctx->mech_type);
    
    if (!mech || !mech->gss_inquire_context || !mech->gss_display_name) {
	return(GSS_S_NO_CONTEXT);

    }

    status = mech->gss_inquire_context(
			mech->context,
			minor_status,
			ctx->internal_ctx_id,
			src_name,
			targ_name,
			lifetime_rec,
			mech_type,
			ctx_flags,
			locally_initiated,
			open);

    if (status != GSS_S_COMPLETE) {
	return status;
    }

    /* need to convert names */

    if (src_name) {
	    status = convert_name_to_union_name(mech, minor_status, src_name);

	    if (status != GSS_S_COMPLETE) {
		(void) mech->gss_release_name(mech->context,
						&temp_minor, src_name);
		(void) mech->gss_release_name(mech->context,
						&temp_minor, targ_name);
		if (mech_type) {
				gss_release_oid(&temp_minor, mech_type);
		}
		return (GSS_S_FAILURE);
	    }

    }

    if (targ_name) {
	    status = convert_name_to_union_name(mech, minor_status, targ_name);

	    if (status != GSS_S_COMPLETE) {
		(void) mech->gss_release_name(mech->context,
						&temp_minor, targ_name);
		if (mech_type) {
			gss_release_oid(&temp_minor, mech_type);
		}
		return (GSS_S_FAILURE);
	    }
    }

    return(GSS_S_COMPLETE);
}

static OM_uint32
convert_name_to_union_name(
			mech,
			minor_status,
			internal_name)
gss_mechanism	mech;
OM_uint32 *minor_status;
gss_name_t * internal_name;

{
	OM_uint32 status;
        gss_OID name_type;
	gss_union_name_t union_name;

	union_name  = (gss_union_name_t) malloc (sizeof(gss_union_name_desc));
	if (!union_name) 
		return (GSS_S_FAILURE);

	union_name->external_name = 
			(gss_buffer_t) malloc(sizeof(gss_buffer_desc));

	if (!union_name->external_name) {
		free(union_name);
		return (GSS_S_FAILURE);
	}
	
	status = mech->gss_display_name(
			mech->context,
			minor_status,
			*internal_name,
			union_name->external_name,
			&union_name->name_type);

	if (status != GSS_S_COMPLETE) {
		free(union_name->external_name);
		free(union_name);
		return (GSS_S_FAILURE);
	}

	status = mech->gss_release_name(
		mech->context,
		minor_status,
		internal_name);

	*internal_name =  union_name;

	return (GSS_S_COMPLETE);

}

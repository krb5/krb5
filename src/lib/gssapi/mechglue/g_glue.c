
#ident	"@(#)g_glue.c 1.1     96/02/06 SMI"

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

#include "mglueP.h"
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <errno.h>

#define g_OID_equal(o1,o2) \
   (((o1)->length == (o2)->length) && \
    (memcmp((o1)->elements,(o2)->elements,(int) (o1)->length) == 0))

extern gss_mechanism *__gss_mechs_array;

/*
 * This file contains the support routines for the glue layer.
 */

/*
 *  given the mechs_array and a mechanism OID, return the 
 *  pointer to the mechanism, or NULL if that mechanism is
 *  not supported.  If the requested OID is NULL, then return
 *  the first mechanism.
 */

gss_mechanism __gss_get_mechanism (gss_OID type)
{
    int	i;

    if (type == GSS_C_NULL_OID)
	return (__gss_mechs_array[0]);

    for (i=0; __gss_mechs_array[i]->mech_type.length != 0; i++) {
	if ((__gss_mechs_array[i]->mech_type.length == type->length) &&
	    (memcmp (__gss_mechs_array[i]->mech_type.elements, type->elements,
		     type->length) == 0)) {

	    return (__gss_mechs_array[i]);
	}
    }
    return NULL;
}


/*
 *  glue routine for get_mech_type
 *
 */

OM_uint32 __gss_get_mech_type(OID, token)

gss_OID *	OID;
gss_buffer_t	token;

{
    unsigned char * buffer_ptr;
    
    /*
     * This routine reads the prefix of "token" in order to determine
     * its mechanism type. It assumes the encoding suggested in
     * Appendix B of RFC 1508. This format starts out as follows :
     *
     * tag for APPLICATION 0, Sequence[constructed, definite length]
     * length of remainder of token
     * tag of OBJECT IDENTIFIER
     * length of mechanism OID
     * encoding of mechanism OID
     * <the rest of the token>
     *
     * Numerically, this looks like :
     *
     * 0x60
     * <length> - could be multiple bytes
     * 0x06
     * <length> - assume only one byte, hence OID length < 127
     * <mech OID bytes>
     *
     * The routine returns a pointer to the OID value. The return code is
     * the length of the OID, if successful; otherwise it is 0.
     */
    
    if (OID == NULL || *OID == GSS_C_NULL_OID)
	return (0);

    /* if the token is a null pointer, return a zero length OID */
    
    if(token == NULL) {
	(*OID)->length = 0;
	(*OID)->elements = NULL;
	return (0);
    }
    
    /* Skip past the APP/Sequnce byte and the token length */
    
    buffer_ptr = (unsigned char *) token->value;
    
    while(*(++buffer_ptr) & (1<<7))
	continue;
    
    /* increment buffer_ptr to point to the OID and return its length */
    
    (*OID)->length = (OM_uint32) *(buffer_ptr+3);
    (*OID)->elements = (void *) (buffer_ptr+4);
    return ((*OID)->length);
}


/*
 *  Internal routines to get and release an internal mechanism name
 */

#include "mglueP.h"

OM_uint32 __gss_import_internal_name (minor_status, mech_type, union_name, 
				internal_name)
OM_uint32	*minor_status;
gss_OID		mech_type;
gss_union_name_t	union_name;
gss_name_t	*internal_name;
{
    OM_uint32		status;
    gss_mechanism	mech;

    mech = __gss_get_mechanism (mech_type);
    if (mech) {
	if (mech->gss_import_name)
	    status = mech->gss_import_name (
					    mech->context,
					    minor_status,
					    union_name->external_name,
					    union_name->name_type,
					    internal_name);
	else
	    status = GSS_S_BAD_BINDINGS;

	return (status);
    }

    return (GSS_S_BAD_MECH);
}

OM_uint32 __gss_display_internal_name (minor_status, mech_type, internal_name, 
				 external_name, name_type)
OM_uint32	*minor_status;
gss_OID		mech_type;
gss_name_t	internal_name;
gss_buffer_t	external_name;
gss_OID		*name_type;
{
    OM_uint32		status;
    gss_mechanism	mech;

    mech = __gss_get_mechanism (mech_type);
    if (mech) {
	if (mech->gss_display_name)
	    status = mech->gss_display_name (
					     mech->context,
					     minor_status,
					     internal_name,
					     external_name,
					     name_type);
	else
	    status = GSS_S_BAD_BINDINGS;

	return (status);
    }

    return (GSS_S_BAD_MECH);
}

OM_uint32 __gss_release_internal_name (minor_status, mech_type, internal_name)
OM_uint32	*minor_status;
gss_OID		mech_type;
gss_name_t	*internal_name;
{
    OM_uint32		status;
    gss_mechanism	mech;

    mech = __gss_get_mechanism (mech_type);
    if (mech) {
	if (mech->gss_release_name)
	    status = mech->gss_release_name (
					     mech->context,
					     minor_status,
					     internal_name);
	else
	    status = GSS_S_BAD_BINDINGS;

	return (status);
    }

    return (GSS_S_BAD_MECH);
}


/*
 * This function converts an internal gssapi name to a union gssapi
 * name.  Note that internal_name should be considered "consumed" by
 * this call, whether or not we return an error.
 */
OM_uint32 __gss_convert_name_to_union_name(minor_status, mech,
					   internal_name, external_name)
    OM_uint32 *minor_status;
    gss_mechanism	mech;
    gss_name_t	internal_name;
    gss_name_t	*external_name;
{
    OM_uint32 major_status,tmp;
    gss_union_name_t union_name;

    union_name = (gss_union_name_t) malloc (sizeof(gss_union_name_desc));
    if (!union_name) {
	    *minor_status = ENOMEM;
	    goto allocation_failure;
    }
    union_name->mech_type = 0;
    union_name->mech_name = internal_name;
    union_name->name_type = 0;
    union_name->external_name = 0;

    major_status = generic_gss_copy_oid(minor_status, &mech->mech_type,
					&union_name->mech_type);
    if (major_status != GSS_S_COMPLETE)
	goto allocation_failure;

    union_name->external_name =
	(gss_buffer_t) malloc(sizeof(gss_buffer_desc));
    if (!union_name->external_name) {
	    *minor_status = ENOMEM;
	    goto allocation_failure;
    }
	
    major_status = mech->gss_display_name(mech->context, minor_status,
					  internal_name,
					  union_name->external_name,
					  &union_name->name_type);
    if (major_status != GSS_S_COMPLETE)
	goto allocation_failure;

    *external_name =  union_name;
    return (GSS_S_COMPLETE);

allocation_failure:
    if (union_name) {
	if (union_name->external_name) {
	    if (union_name->external_name->value)
		free(union_name->external_name->value);
	    free(union_name->external_name);
	}
	if (union_name->name_type)
	    gss_release_oid(&tmp, &union_name->name_type);
	if (union_name->mech_name)
	    __gss_release_internal_name(minor_status, union_name->mech_type,
					&union_name->mech_name);
	if (union_name->mech_type)
	    gss_release_oid(&tmp, &union_name->mech_type);
	free(union_name);
    }
    return (major_status);
}

/*
 * Glue routine for returning the mechanism-specific credential from a
 * external union credential.
 */
gss_cred_id_t
__gss_get_mechanism_cred(union_cred, mech_type)
    gss_union_cred_t	union_cred;
    gss_OID		mech_type;
{
    int		i;
    
    if (union_cred == GSS_C_NO_CREDENTIAL)
	return GSS_C_NO_CREDENTIAL;
    
    for (i=0; i < union_cred->count; i++) {
	if (g_OID_equal(mech_type, &union_cred->mechs_array[i]))
	    return union_cred->cred_array[i];
    }
    return GSS_C_NO_CREDENTIAL;
}

    

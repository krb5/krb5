#ident  "@(#)gss_inquire_cred.c 1.9     95/08/02 SMI"

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
 *  glue routine for gss_inquire_cred
 */

#include "mglueP.h"
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>

OM_uint32
gss_inquire_cred(minor_status,
                 cred_handle,
                 name,
                 lifetime,
		 cred_usage,
                 mechanisms)

OM_uint32 *		minor_status;
gss_cred_id_t 		cred_handle;
gss_name_t *		name;
OM_uint32 *		lifetime;
int *			cred_usage;
gss_OID_set *		mechanisms;

{
    OM_uint32		status, elapsed_time, temp_minor_status;
    gss_union_cred_t	union_cred;
    int			i;
    
    gss_initialize();

    if(cred_handle == GSS_C_NO_CREDENTIAL)
	
	/* This action doesn't conform to the spec. We are supposed
	 * to return information about the default credential.
	 * However, we don't know what mechanism the default
	 * credential is associated with, so we can't call
	 * the mechanism specific version of gss_inquire_cred().
	 * Consequently, we just return NO_CRED.
	 */
	
	return(GSS_S_NO_CRED);
    else
	
	/* get the cred_handle cast as a union_credentials structure */
	
	union_cred = (gss_union_cred_t) cred_handle;
    
    /*
     * get the information out of the union_cred structure that was
     * placed there during gss_acquire_cred.
     */
    
    if(cred_usage != NULL)
	*cred_usage = union_cred->auxinfo.cred_usage;
    
    if(lifetime != NULL) {
	elapsed_time = time(0) - union_cred->auxinfo.creation_time;
	*lifetime = union_cred->auxinfo.time_rec < elapsed_time ? 0 :
	union_cred->auxinfo.time_rec - elapsed_time;
    }
    
    /*
     * if name is non_null,
     * call gss_import_name(), giving it the printable name held within
     * union_cred in order to get an internal name to pass back to the
     * caller. If this call fails, return failure to our caller.
     */
    
    if(name != NULL)
	if(gss_import_name(&temp_minor_status,
			   &union_cred->auxinfo.name,
			   union_cred->auxinfo.name_type,
			   name) != GSS_S_COMPLETE)
	    return(GSS_S_DEFECTIVE_CREDENTIAL);
    
    /*
     * copy the mechanism set in union_cred into an OID set and return in
     * the mechanisms parameter.
     */
    
    if(mechanisms != NULL) {

	*mechanisms = (gss_OID_set) malloc(sizeof(gss_OID_set_desc));

	(*mechanisms)->count = union_cred->count;
	(*mechanisms)->elements =
	    (gss_OID) malloc(sizeof(gss_OID_desc) *
			     union_cred->count);

	for(i=0; i < union_cred->count; i++) {
	    (*mechanisms)->elements[i].length =
		union_cred->mechs_array[i].length;
	    (*mechanisms)->elements[i].elements = (void *)
		malloc(union_cred->mechs_array[i].length);
	    memcpy((*mechanisms)->elements[i].elements,
		   union_cred->mechs_array[i].elements,
		   union_cred->mechs_array[i].length);
	}
    }
    
    return(GSS_S_COMPLETE);
}

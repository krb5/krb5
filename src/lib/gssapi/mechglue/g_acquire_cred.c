#ident  "@(#)gss_acquire_cred.c 1.19     95/08/07 SMI"

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
 *  glue routine for gss_acquire_cred
 */

#include "mglueP.h"
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>

OM_uint32
gss_acquire_cred(minor_status,
                 desired_name,
                 time_req,
                 desired_mechs,
		 cred_usage,
                 output_cred_handle,
                 actual_mechs,
                 time_rec)

OM_uint32 *		minor_status;
gss_name_t		desired_name;
OM_uint32		time_req;
gss_OID_set		desired_mechs;
int			cred_usage;
gss_cred_id_t *		output_cred_handle;
gss_OID_set *		actual_mechs;
OM_uint32 *		time_rec;

{
    OM_uint32		status, temp_status,
    temp_minor_status, temp_time_rec = ~0;
    int			i, j, creds_acquired = 0;
    gss_union_name_t	union_name;
    gss_name_t		internal_name;
    gss_union_cred_t	creds;
    gss_OID_set_desc	default_OID_set;
    gss_OID_desc	default_OID;
    gss_mechanism	mech;
    
    /*
     * This struct is used to keep track of which mech_types are
     * actually available and to store the credentials returned
     * from them by each mechanism specific gss_acquire_cred() call.
     * The results are used to construct the final union_cred
     * structure returned by the glue layer gss_acquire_cred() call
     * and the actual_mechs gss_OID_set returned.
     */
    
    struct creds_returned {
	unsigned char	available;
	gss_cred_id_t 	cred;
    } *creds_returned;
    
    gss_initialize();

    /* Set this to NULL for now */

    if (actual_mechs)
	*actual_mechs = GSS_C_NULL_OID_SET;

    if (minor_status)
	*minor_status = 0;
    
    if (desired_name == 0)
	return GSS_S_BAD_NAME;

    /* No need to continue if we don't have a place to store the creds */
    if (output_cred_handle == NULL)
	return GSS_S_COMPLETE;

    /* get desired_name cast as a union_name type */
    
    union_name = (gss_union_name_t) desired_name;
    
    /*
     * if desired_mechs equals GSS_C_NULL_OID_SET, set it to the
     * first entry in the mechs_array.
     */
    
    if(desired_mechs == GSS_C_NULL_OID_SET) {
	if ((mech = __gss_get_mechanism (NULL)) == NULL)
	    return (GSS_S_BAD_MECH);

	desired_mechs = &default_OID_set;
	default_OID_set.count = 1 ;
	default_OID_set.elements = &default_OID;
	default_OID.length = mech->mech_type.length;
	default_OID.elements = mech->mech_type.elements;
    }	
    
    /*
     * Now allocate the creds returned array. There is one element
     * for each member of the desired_mechs argument. 
     */
    
    creds_returned = (struct creds_returned *)
	malloc(sizeof(struct creds_returned)
	       * desired_mechs->count);
    
    /*
     * For each requested mechanism in desired_mechs, determine if it
     * is supported. If so, mark the corresponding element in
     * creds_returned->available as 1 and call the mechanism
     * specific gss_acquire_cred(), placing the returned cred in
     * creds_returned->cred. If not, mark creds_returned->available as
     * 0.  */
    
    for(j=0; j < desired_mechs->count; j++) {

	creds_returned[j].available = 0;

	mech = __gss_get_mechanism (&desired_mechs->elements[j]);
	if (mech && mech->gss_acquire_cred) {

	    /*
	     * we first have to import the external name in
	     * union_name so it can be used in the
	     * gss_acquire_cred() call.
	     */

	    if ((status = __gss_import_internal_name(
					       minor_status,
					       &mech->mech_type,
					       union_name,
					       &internal_name))) {
		status = GSS_S_BAD_NAME;
		continue;
	    }
				
	    status = mech->gss_acquire_cred(
					    mech->context,
					    minor_status,
					    internal_name,
					    time_req,
					    desired_mechs,
					    cred_usage,
					    &creds_returned[j].cred,
					    NULL,
					    &temp_time_rec);

	    if ((temp_status = __gss_release_internal_name(
						     &temp_minor_status,
						     &mech->mech_type,
						     &internal_name))) {
		/* Not much we can do here, really... Just keep on going */
		;
	    }

	    /* 
	     * Add this into the creds_returned structure, if we got
	     * a good credential for this mechanism.
	     */
	    if(status == GSS_S_COMPLETE) {
		if (time_rec) {
		    *time_rec = *time_rec > temp_time_rec ?
			temp_time_rec : *time_rec;
		    temp_time_rec = *time_rec;
		}

		creds_returned[j].available = 1;
		creds_acquired++;
	    }	
	}
    }
    
    /*
     * Now allocate the creds struct, which will be cast as a gss_cred_id_t
     * and returned in the output_cred_handle argument. If there were
     * no credentials found, return an error. Also, allocate the
     * actual_mechs data.
     */
    
    if(creds_acquired == 0) {
	free (creds_returned);
	return(GSS_S_BAD_MECH);
    }
    
    creds = (gss_union_cred_t) malloc(sizeof(gss_union_cred_desc));
    
    creds->count = creds_acquired;
    
    creds->mechs_array = (gss_OID)
	malloc(sizeof(gss_OID_desc) * creds_acquired);
    
    creds->cred_array = (gss_cred_id_t *)
	malloc(sizeof(gss_cred_id_t) * creds_acquired);
    
    if(actual_mechs != NULL) {
	*actual_mechs = (gss_OID_set) malloc(sizeof(gss_OID_set_desc));

	(*actual_mechs)->count = creds_acquired;

	(*actual_mechs)->elements = (gss_OID)
	    malloc(sizeof(gss_OID_desc) * creds_acquired);
    }
    
    /*
     * copy the mechanisms found and their allocated credentials into the
     * creds structure. At the same time, build up the actual_mechs
     * data.
     */
    
    j = 0;
    
    for(i=0; i<desired_mechs->count; i++) {
	if(creds_returned[i].available) {

	    creds->mechs_array[j].length =
		desired_mechs->elements[i].length;
	    creds->mechs_array[j].elements = (void *)
		malloc(desired_mechs->elements[i].length);
	    memcpy(creds->mechs_array[j].elements,
		   desired_mechs->elements[i].elements,
		   desired_mechs->elements[i].length);
	    creds->cred_array[j] = creds_returned[i].cred;
	    if (actual_mechs) {
		    (*actual_mechs)->elements[j].length =
			desired_mechs->elements[i].length;
		    (*actual_mechs)->elements[j].elements = (void *)
			malloc(desired_mechs->elements[i].length);
		    memcpy((*actual_mechs)->elements[j].elements,
			   desired_mechs->elements[i].elements,
			   desired_mechs->elements[i].length);
	    }
	    j++;
	}
    }
    
    /* free the creds_returned struct, since we are done with it. */
    
    free(creds_returned);
    
    /* record the information needed for gss_inquire_cred() */
    
    creds->auxinfo.creation_time = time(0);
    creds->auxinfo.time_rec = temp_time_rec;
    creds->auxinfo.cred_usage =  cred_usage;
    
    /*
     * we can't just record the internal name, desired_name, since
     * it may be destroyed between now and the time gss_inquire_cred()
     * is called.  So we must record the printable name in a
     * gss_buffer_t, calling gss_display_name() to fill it in. When
     * gss_inquire_name() is called, we must then call gss_import_name()
     * to get the internal name that is required at that point.
     */
    if (gss_display_name(&temp_minor_status, desired_name,
			 &creds->auxinfo.name, &creds->auxinfo.name_type)
	!= GSS_S_COMPLETE) {
	
	/* This really shouldn't ever fail, but just in case.... */

	for(i=0; i < creds->count; i++) {
	    free(creds->mechs_array[i].elements);
	    if (actual_mechs) free((*actual_mechs)->elements[i].elements);
	}
	
	if (actual_mechs) {
		free((*actual_mechs)->elements);
		free(*actual_mechs);
		*actual_mechs = GSS_C_NULL_OID_SET;
	}
	free(creds->cred_array);
	free(creds->mechs_array);
	free(creds);
	
	return(GSS_S_BAD_NAME);
    }
    
    *output_cred_handle = (gss_cred_id_t) creds;
    return(GSS_S_COMPLETE);
}

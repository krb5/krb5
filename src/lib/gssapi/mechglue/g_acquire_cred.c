/* #ident  "@(#)gss_acquire_cred.c 1.19     95/08/07 SMI" */

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
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#include <errno.h>
#include <time.h>

#define g_OID_equal(o1,o2) \
   (((o1)->length == (o2)->length) && \
    (memcmp((o1)->elements,(o2)->elements,(int) (o1)->length) == 0))

static gss_OID_set
create_actual_mechs(creds)
    gss_union_cred_t	creds;
{
    gss_OID_set 	actual_mechs;
    int			i;

    actual_mechs = (gss_OID_set) malloc(sizeof(gss_OID_set_desc));
    if (!actual_mechs)
	return NULL;

    actual_mechs->elements = (gss_OID)
	    malloc(sizeof(gss_OID_desc) * creds->count);
    if (!actual_mechs->elements) {
	free(actual_mechs);
	return NULL;
    }
    
    actual_mechs->count = creds->count;

    for (i=0; i < creds->count; i++) {
	actual_mechs->elements[i].length = creds->mechs_array[i].length;
	actual_mechs->elements[i].elements = (void *)
	    malloc(creds->mechs_array[i].length);
	memcpy(actual_mechs->elements[i].elements,
	       creds->mechs_array[i].elements, creds->mechs_array[i].length);
    }

    return actual_mechs;
}


OM_uint32 KRB5_CALLCONV
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
    OM_uint32		status, temp_minor_status, temp_time_rec = ~0;
    unsigned int	i, j, creds_acquired = 0;
    int			k;
    gss_union_name_t	union_name;
    gss_name_t		internal_name;
    gss_union_cred_t	creds;
    gss_OID_set_desc	default_OID_set;
    gss_OID_desc	default_OID;
    gss_OID		specific_mech_type = 0;
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
    
    /* No need to continue if we don't have a place to store the creds */
    if (output_cred_handle == NULL)
	return GSS_S_COMPLETE;

    /* get desired_name cast as a union_name type */
    
    union_name = (gss_union_name_t) desired_name;

    if (union_name)
	    specific_mech_type = union_name->mech_type;
    
    /*
     * if desired_mechs equals GSS_C_NULL_OID_SET, then pick an
     * appropriate default.
     */
    if(desired_mechs == GSS_C_NULL_OID_SET) {
	/*
	 * If union_name->mech_type is NULL then we get the default
	 * mechanism; otherwise, we get the mechanism for the
	 * mechanism-specific name.
	 */
	mech = __gss_get_mechanism(specific_mech_type);
	if (mech == NULL)
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
	malloc(sizeof(struct creds_returned) * desired_mechs->count);
    
    /*
     * For each requested mechanism in desired_mechs, determine if it
     * is supported. If so, mark the corresponding element in
     * creds_returned->available as 1 and call the mechanism
     * specific gss_acquire_cred(), placing the returned cred in
     * creds_returned->cred. If not, mark creds_returned->available as
     * 0.
     */
    status = GSS_S_BAD_MECH;
    for (j=0; j < desired_mechs->count; j++) {
	creds_returned[j].available = 0;

	mech = __gss_get_mechanism (&desired_mechs->elements[j]);
	if (!mech || !mech->gss_acquire_cred)
	    continue;
	/*
	 * If this is a mechanism-specific name, then only use the
	 * mechanism of the name.
	 */
	if (specific_mech_type && !g_OID_equal(specific_mech_type,
					       &mech->mech_type))
	    continue;
	/*
	 * If this is not a mechanism-specific name, then we need to
	 * do an import the external name in union_name first.
	 */
	if (union_name == 0)
	    internal_name = (gss_name_t) 0;
	else if (!union_name->mech_type) {
	    if (__gss_import_internal_name(&temp_minor_status,
					   &mech->mech_type,
					   union_name, &internal_name)) {
		continue;
	    }
	} else
	    internal_name = union_name->mech_name;

	status = mech->gss_acquire_cred(mech->context, minor_status,
					internal_name, time_req,
					desired_mechs, cred_usage,
					&creds_returned[j].cred,
					NULL, &temp_time_rec);

	/* Release the internal name, if allocated above */
	if (union_name && !union_name->mech_type) {
	    (void) __gss_release_internal_name(&temp_minor_status,
					       &mech->mech_type,
					       &internal_name);
	}

	if (status != GSS_S_COMPLETE)
	    continue;

	/* 
	 * Add this into the creds_returned structure, if we got
	 * a good credential for this mechanism.
	 */
	if (time_rec) {
	    *time_rec = *time_rec > temp_time_rec ? temp_time_rec : *time_rec;
	    temp_time_rec = *time_rec;
	}

	creds_returned[j].available = 1;
	creds_acquired++;

	/*
	 * If union_name is set, then we're done.  Continue, and
	 * declare success.  Otherwise, if do an inquire credentials
	 * from the first mechanism that succeeds and use that as the
	 * union name.
	 */
	if (union_name)
	    continue;

	status = mech->gss_inquire_cred(mech->context, &temp_minor_status,
					creds_returned[j].cred,
					&internal_name, 0, 0, 0);
	if (status) {
	    /* Should never happen */
	    creds_returned[j].available = 0;
	    creds_acquired--;
	    if (mech->gss_release_cred)
		mech->gss_release_cred(mech->context, minor_status,
				       &creds_returned[j].cred);
	    continue;
	}

	status = __gss_convert_name_to_union_name(&temp_minor_status, mech,
						  internal_name,
						  (gss_name_t *) &union_name);
    }
    
    /*
     * Now allocate the creds struct, which will be cast as a gss_cred_id_t
     * and returned in the output_cred_handle argument. If there were
     * no credentials found, return an error. Also, allocate the
     * actual_mechs data.
     */
    if (creds_acquired == 0) {
	free (creds_returned);
	return (status);
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
    
    for (i=0; i<desired_mechs->count; i++) {
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
    if (desired_name) {
	status = gss_display_name(&temp_minor_status, desired_name,
				  &creds->auxinfo.name,
				  &creds->auxinfo.name_type);
	if (status) {
	    status = GSS_S_BAD_NAME;
	    goto error_out;
	}
    } else {
	status = gss_display_name(&temp_minor_status, union_name,
				  &creds->auxinfo.name,
				  &creds->auxinfo.name_type);
	if (status) {
	    status = GSS_S_BAD_NAME;
	    goto error_out;
	}
    }
    
    *output_cred_handle = (gss_cred_id_t) creds;
    return(GSS_S_COMPLETE);

error_out:
    for (k=0; k < creds->count; k++) {
	free(creds->mechs_array[k].elements);
	if (actual_mechs)
	    free((*actual_mechs)->elements[k].elements);
    }
	
    if (actual_mechs) {
	free((*actual_mechs)->elements);
	free(*actual_mechs);
	*actual_mechs = GSS_C_NULL_OID_SET;
    }
    free(creds->cred_array);
    free(creds->mechs_array);
    free(creds);
	
    return(status);
}

/* V2 KRB5_CALLCONV */
OM_uint32 KRB5_CALLCONV
gss_add_cred(minor_status, input_cred_handle,
		  desired_name, desired_mech, cred_usage,
		  initiator_time_req, acceptor_time_req,
		  output_cred_handle, actual_mechs, 
		  initiator_time_rec, acceptor_time_rec)
    OM_uint32		*minor_status;
    gss_cred_id_t	input_cred_handle;
    gss_name_t		desired_name;
    gss_OID		desired_mech;
    gss_cred_usage_t	cred_usage;
    OM_uint32		initiator_time_req;
    OM_uint32		acceptor_time_req;
    gss_cred_id_t	*output_cred_handle;
    gss_OID_set		*actual_mechs;
    OM_uint32		*initiator_time_rec;
    OM_uint32		*acceptor_time_rec;
{
    OM_uint32		status, temp_minor_status;
    OM_uint32		time_req, time_rec;
    gss_union_name_t	union_name;
    gss_union_cred_t	new_union_cred, union_cred;
    gss_name_t		internal_name;
    gss_mechanism	mech;
    gss_cred_id_t	cred;
    gss_OID		new_mechs_array;
    gss_cred_id_t *	new_cred_array;

    if (input_cred_handle == GSS_C_NO_CREDENTIAL)
	return GSS_S_NO_CRED;

    union_cred = (gss_union_cred_t) input_cred_handle;

    mech = __gss_get_mechanism(desired_mech);
    if (!mech)
	return GSS_S_BAD_MECH;

    if (__gss_get_mechanism_cred(union_cred, desired_mech) !=
	GSS_C_NO_CREDENTIAL)
	return GSS_S_DUPLICATE_ELEMENT;

    union_name = (gss_union_name_t) desired_name;
    if (union_name->mech_type) {
	if (!g_OID_equal(desired_mech, union_name->mech_type))
	    return GSS_S_BAD_NAMETYPE;
	internal_name = union_name->mech_name;
    } else {
	if (__gss_import_internal_name(minor_status, desired_mech,
				       union_name, &internal_name))
	    return (GSS_S_BAD_NAME);
    }

    if (cred_usage == GSS_C_ACCEPT)
	time_req = acceptor_time_req;
    else if (cred_usage == GSS_C_INITIATE)
	time_req = initiator_time_req;
    else if (cred_usage == GSS_C_BOTH)
	time_req = (acceptor_time_req > initiator_time_req) ?
	    acceptor_time_req : initiator_time_req;

    status = mech->gss_acquire_cred(mech->context, minor_status,
				    internal_name, time_req,
				    GSS_C_NULL_OID_SET, cred_usage,
				    &cred, NULL, &time_rec);
    if (status != GSS_S_COMPLETE)
	goto errout;

    new_mechs_array = (gss_OID)
	malloc(sizeof(gss_OID_desc) * (union_cred->count+1));
    
    new_cred_array = (gss_cred_id_t *)
	malloc(sizeof(gss_cred_id_t) * (union_cred->count+1));

    if (!new_mechs_array || !new_cred_array) {
	*minor_status = ENOMEM;
	status = GSS_S_FAILURE;
	goto errout;
    }


    if (acceptor_time_rec)
	if (cred_usage == GSS_C_ACCEPT || cred_usage == GSS_C_BOTH)
	    *acceptor_time_rec = time_rec;
    if (initiator_time_rec)
	if (cred_usage == GSS_C_INITIATE || cred_usage == GSS_C_BOTH)
	    *initiator_time_rec = time_rec;

    /*
     * OK, expand the mechanism array in the union credentials
     * (Look for the union label...)
     */
    memcpy(new_mechs_array, union_cred->mechs_array,
	   sizeof(gss_OID_desc) * union_cred->count);
    memcpy(new_cred_array, union_cred->cred_array,
	   sizeof(gss_cred_id_t) * union_cred->count);
    
    new_cred_array[union_cred->count] = cred;
    new_mechs_array[union_cred->count].length = desired_mech->length;
    new_mechs_array[union_cred->count].elements = malloc(desired_mech->length);
    if (!new_mechs_array[union_cred->count].elements) {
	*minor_status = ENOMEM;
	goto errout;
    }
    memcpy(new_mechs_array[union_cred->count].elements, desired_mech->elements,
	   desired_mech->length);

    if (output_cred_handle == NULL) {
	free(union_cred->mechs_array);
	free(union_cred->cred_array);
	new_union_cred = union_cred;
    } else {
	new_union_cred = malloc(sizeof(gss_union_cred_desc));
	if (new_union_cred == NULL) {
	    *minor_status = ENOMEM;
	    goto errout;
	}
	*new_union_cred = *union_cred;
	*output_cred_handle = new_union_cred;
    }
    new_union_cred->mechs_array = new_mechs_array;
    new_union_cred->cred_array = new_cred_array;
    new_union_cred->count++;
    new_mechs_array = 0;
    new_cred_array = 0;

    if (actual_mechs)
	*actual_mechs = create_actual_mechs(new_union_cred);
    
    status = GSS_S_COMPLETE;
    
errout:
    if (new_mechs_array)
	free(new_mechs_array);
    if (new_cred_array)
	free(new_cred_array);
    if (!union_name->mech_type) {
	(void) __gss_release_internal_name(&temp_minor_status,
					   desired_mech, &internal_name);
    }

    return(status);
}

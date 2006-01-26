/*
 * lib/gssapi/generic/oid_ops.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
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
 *
 */

/*
 * oid_ops.c - GSS-API V2 interfaces to manipulate OIDs
 */

#include "gssapiP_generic.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>

OM_uint32
generic_gss_release_oid(minor_status, oid)
    OM_uint32	*minor_status;
    gss_OID	*oid;
{
    *minor_status = 0;

    if (*oid == GSS_C_NO_OID)
	return(GSS_S_COMPLETE);

    /*
     * The V2 API says the following!
     *
     * gss_release_oid[()] will recognize any of the GSSAPI's own OID values,
     * and will silently ignore attempts to free these OIDs; for other OIDs
     * it will call the C free() routine for both the OID data and the
     * descriptor.  This allows applications to freely mix their own heap-
     * allocated OID values with OIDs returned by GSS-API.
     */
    if ((*oid != gss_nt_user_name) &&
	(*oid != gss_nt_machine_uid_name) &&
	(*oid != gss_nt_string_uid_name) &&
	(*oid != gss_nt_service_name) &&
	(*oid != gss_nt_exported_name) &&
	(*oid != gss_nt_service_name_v2)) {
	free((*oid)->elements);
	free(*oid);
    }
    *oid = GSS_C_NO_OID;
    return(GSS_S_COMPLETE);
}

OM_uint32
generic_gss_copy_oid(minor_status, oid, new_oid)
	OM_uint32	*minor_status;
	gss_OID		oid, *new_oid;
{
	gss_OID		p;

	p = (gss_OID) malloc(sizeof(gss_OID_desc));
	if (!p) {
		*minor_status = ENOMEM;
		return GSS_S_FAILURE;
	}
	p->length = oid->length;
	p->elements = malloc(p->length);
	if (!p->elements) {
		free(p);
		*minor_status = ENOMEM;
		return GSS_S_FAILURE;
	}
	memcpy(p->elements, oid->elements, p->length);
	*new_oid = p;
	return(GSS_S_COMPLETE);
}


OM_uint32
generic_gss_create_empty_oid_set(minor_status, oid_set)
    OM_uint32	*minor_status;
    gss_OID_set	*oid_set;
{
    if ((*oid_set = (gss_OID_set) malloc(sizeof(gss_OID_set_desc)))) {
	memset(*oid_set, 0, sizeof(gss_OID_set_desc));
	*minor_status = 0;
	return(GSS_S_COMPLETE);
    }
    else {
	*minor_status = ENOMEM;
	return(GSS_S_FAILURE);
    }
}

OM_uint32
generic_gss_add_oid_set_member(minor_status, member_oid, oid_set)
    OM_uint32	*minor_status;
    gss_OID	member_oid;
    gss_OID_set	*oid_set;
{
    gss_OID	elist;
    gss_OID	lastel;

    elist = (*oid_set)->elements;
    /* Get an enlarged copy of the array */
    if (((*oid_set)->elements = (gss_OID) malloc(((*oid_set)->count+1) *
						  sizeof(gss_OID_desc)))) {
	/* Copy in the old junk */
	if (elist)
	    memcpy((*oid_set)->elements,
		   elist,
		   ((*oid_set)->count * sizeof(gss_OID_desc)));

	/* Duplicate the input element */
	lastel = &(*oid_set)->elements[(*oid_set)->count];
	if ((lastel->elements =
	     (void *) malloc((size_t) member_oid->length))) {
	    /* Success - copy elements */
	    memcpy(lastel->elements, member_oid->elements,
		   (size_t) member_oid->length);
	    /* Set length */
	    lastel->length = member_oid->length;

	    /* Update count */
	    (*oid_set)->count++;
	    if (elist)
		free(elist);
	    *minor_status = 0;
	    return(GSS_S_COMPLETE);
	}
	else
	    free((*oid_set)->elements);
    }
    /* Failure - restore old contents of list */
    (*oid_set)->elements = elist;
    *minor_status = ENOMEM;
    return(GSS_S_FAILURE);
}

OM_uint32
generic_gss_test_oid_set_member(minor_status, member, set, present)
    OM_uint32	*minor_status;
    gss_OID	member;
    gss_OID_set	set;
    int		*present;
{
    size_t	i;
    int		result;

    result = 0;
    for (i=0; i<set->count; i++) {
	if ((set->elements[i].length == member->length) &&
	    !memcmp(set->elements[i].elements,
		    member->elements,
		    (size_t) member->length)) {
	    result = 1;
	    break;
	}
    }
    *present = result;
    *minor_status = 0;
    return(GSS_S_COMPLETE);
}

/*
 * OID<->string routines.  These are uuuuugly.
 */
OM_uint32
generic_gss_oid_to_str(minor_status, oid, oid_str)
    OM_uint32		*minor_status;
    gss_OID		oid;
    gss_buffer_t	oid_str;
{
    char		numstr[128];
    unsigned long	number;
    int			numshift;
    size_t		string_length;
    size_t		i;
    unsigned char	*cp;
    char		*bp;

    /* Decoded according to krb5/gssapi_krb5.c */

    /* First determine the size of the string */
    string_length = 0;
    number = 0;
    numshift = 0;
    cp = (unsigned char *) oid->elements;
    number = (unsigned long) cp[0];
    sprintf(numstr, "%ld ", number/40);
    string_length += strlen(numstr);
    sprintf(numstr, "%ld ", number%40);
    string_length += strlen(numstr);
    for (i=1; i<oid->length; i++) {
	if ( (size_t) (numshift+7) < (sizeof(unsigned long)*8)) {
	    number = (number << 7) | (cp[i] & 0x7f);
	    numshift += 7;
	}
	else {
	    *minor_status = EINVAL;
	    return(GSS_S_FAILURE);
	}
	if ((cp[i] & 0x80) == 0) {
	    sprintf(numstr, "%ld ", number);
	    string_length += strlen(numstr);
	    number = 0;
	    numshift = 0;
	}
    }
    /*
     * If we get here, we've calculated the length of "n n n ... n ".  Add 4
     * here for "{ " and "}\0".
     */
    string_length += 4;
    if ((bp = (char *) malloc(string_length))) {
	strcpy(bp, "{ ");
	number = (unsigned long) cp[0];
	sprintf(numstr, "%ld ", number/40);
	strcat(bp, numstr);
	sprintf(numstr, "%ld ", number%40);
	strcat(bp, numstr);
	number = 0;
	cp = (unsigned char *) oid->elements;
	for (i=1; i<oid->length; i++) {
	    number = (number << 7) | (cp[i] & 0x7f);
	    if ((cp[i] & 0x80) == 0) {
		sprintf(numstr, "%ld ", number);
		strcat(bp, numstr);
		number = 0;
	    }
	}
	strcat(bp, "}");
	oid_str->length = strlen(bp)+1;
	oid_str->value = (void *) bp;
	*minor_status = 0;
	return(GSS_S_COMPLETE);
    }
    *minor_status = ENOMEM;
    return(GSS_S_FAILURE);
}

OM_uint32
generic_gss_str_to_oid(minor_status, oid_str, oid)
    OM_uint32		*minor_status;
    gss_buffer_t	oid_str;
    gss_OID		*oid;
{
    char	*cp, *bp, *startp;
    int		brace;
    long	numbuf;
    long	onumbuf;
    OM_uint32	nbytes;
    int		idx;
    unsigned char *op;

    brace = 0;
    bp = (char *) oid_str->value;
    cp = bp;
    /* Skip over leading space */
    while ((bp < &cp[oid_str->length]) && isspace((int) *bp))
	bp++;
    if (*bp == '{') {
	brace = 1;
	bp++;
    }
    while ((bp < &cp[oid_str->length]) && isspace((int) *bp))
	bp++;
    startp = bp;
    nbytes = 0;

    /*
     * The first two numbers are chewed up by the first octet.
     */
    if (sscanf(bp, "%ld", &numbuf) != 1) {
	*minor_status = EINVAL;
	return(GSS_S_FAILURE);
    }
    while ((bp < &cp[oid_str->length]) && isdigit((int) *bp))
	bp++;
    while ((bp < &cp[oid_str->length]) && isspace((int) *bp))
	bp++;
    if (sscanf(bp, "%ld", &numbuf) != 1) {
	*minor_status = EINVAL;
	return(GSS_S_FAILURE);
    }
    while ((bp < &cp[oid_str->length]) && isdigit((int) *bp))
	bp++;
    while ((bp < &cp[oid_str->length]) && isspace((int) *bp))
	bp++;
    nbytes++;
    while (isdigit((int) *bp)) {
	if (sscanf(bp, "%ld", &numbuf) != 1) {
	    *minor_status = EINVAL;
	    return(GSS_S_FAILURE);
	}
	while (numbuf) {
	    nbytes++;
	    numbuf >>= 7;
	}
	while ((bp < &cp[oid_str->length]) && isdigit((int) *bp))
	    bp++;
	while ((bp < &cp[oid_str->length]) && isspace((int) *bp))
	    bp++;
    }
    if (brace && (*bp != '}')) {
	*minor_status = EINVAL;
	return(GSS_S_FAILURE);
    }

    /*
     * Phew!  We've come this far, so the syntax is good.
     */
    if ((*oid = (gss_OID) malloc(sizeof(gss_OID_desc)))) {
	if (((*oid)->elements = (void *) malloc((size_t) nbytes))) {
	    (*oid)->length = nbytes;
	    op = (unsigned char *) (*oid)->elements;
	    bp = startp;
	    sscanf(bp, "%ld", &numbuf);
	    while (isdigit((int) *bp))
		bp++;
	    while (isspace((int) *bp))
		bp++;
	    onumbuf = 40*numbuf;
	    sscanf(bp, "%ld", &numbuf);
	    onumbuf += numbuf;
	    *op = (unsigned char) onumbuf;
	    op++;
	    while (isdigit((int) *bp))
		bp++;
	    while (isspace((int) *bp))
		bp++;
	    while (isdigit((int) *bp)) {
		sscanf(bp, "%ld", &numbuf);
		nbytes = 0;
		/* Have to fill in the bytes msb-first */
		onumbuf = numbuf;
		while (numbuf) {
		    nbytes++;
		    numbuf >>= 7;
		}
		numbuf = onumbuf;
		op += nbytes;
		idx = -1;
		while (numbuf) {
		    op[idx] = (unsigned char) numbuf & 0x7f;
		    if (idx != -1)
			op[idx] |= 0x80;
		    idx--;
		    numbuf >>= 7;
		}
		while (isdigit((int) *bp))
		    bp++;
		while (isspace((int) *bp))
		    bp++;
	    }
	    *minor_status = 0;
	    return(GSS_S_COMPLETE);
	}
	else {
	    free(*oid);
	    *oid = GSS_C_NO_OID;
	}
    }
    *minor_status = ENOMEM;
    return(GSS_S_FAILURE);
}


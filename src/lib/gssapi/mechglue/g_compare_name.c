/* #ident  "@(#)gss_compare_name.c 1.13     95/08/02 SMI" */

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
 *  glue routine for gss_compare_name
 *
 */

#include "mglueP.h"
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>

#define g_OID_equal(o1,o2) \
   (((o1)->length == (o2)->length) && \
    (memcmp((o1)->elements,(o2)->elements,(int) (o1)->length) == 0))

OM_uint32 KRB5_CALLCONV
gss_compare_name (minor_status,
                  name1,
                  name2,
                  name_equal)

OM_uint32 *		minor_status;
gss_name_t		name1;
gss_name_t		name2;
int *			name_equal;

{
    OM_uint32		major_status, temp_minor;
    gss_union_name_t	union_name1, union_name2;
    gss_mechanism	mech;
    gss_name_t		internal_name;
    
    gss_initialize();

    if (name1 == 0 || name2 == 0) {
	if (name_equal)
	    *name_equal = 0;
	return GSS_S_BAD_NAME;
    }

    union_name1 = (gss_union_name_t) name1;
    union_name2 = (gss_union_name_t) name2;
    /*
     * Try our hardest to make union_name1 be the mechanism-specific
     * name.  (Of course we can't if both names aren't
     * mechanism-specific.)
     */
    if (union_name1->mech_type == 0) {
	union_name1 = (gss_union_name_t) name2;
	union_name2 = (gss_union_name_t) name1;
    }
    /*
     * If union_name1 is mechanism specific, then fetch its mechanism
     * information.
     */
    if (union_name1->mech_type) {
	mech = __gss_get_mechanism (union_name1->mech_type);
	if (!mech)
	    return (GSS_S_BAD_MECH);
	if (!mech->gss_compare_name)
	    return (GSS_S_BAD_BINDINGS);
    }
	
    if (name_equal == NULL)
	return GSS_S_COMPLETE;

    *name_equal = 0;		/* Default to *not* equal.... */

    /*
     * First case... both names are mechanism-specific
     */
    if (union_name1->mech_type && union_name2->mech_type) {
	if (!g_OID_equal(union_name1->mech_type, union_name2->mech_type))
	    return (GSS_S_COMPLETE);
	if ((union_name1->mech_name == 0) || (union_name2->mech_name == 0))
	    /* should never happen */
	    return (GSS_S_BAD_NAME);
	return (mech->gss_compare_name(mech->context, minor_status,
				       union_name1->mech_name,
				       union_name2->mech_name, name_equal));
	
    }

    /*
     * Second case... both names are NOT mechanism specific.
     * 
     * All we do here is make sure the two name_types are equal and then
     * that the external_names are equal. Note the we do not take care
     * of the case where two different external names map to the same
     * internal name. We cannot determine this, since we as yet do not
     * know what mechanism to use for calling the underlying
     * gss_import_name().
     */
    if (!union_name1->mech_type && !union_name2->mech_type) {
	if (!g_OID_equal(union_name1->name_type, union_name2->name_type))
	    return (GSS_S_COMPLETE);
	if ((union_name1->external_name->length !=
	     union_name2->external_name->length) ||
	    (memcmp(union_name1->external_name->value,
		    union_name2->external_name->value,
		    union_name1->external_name->length) != 0))
	    return (GSS_S_COMPLETE);
	*name_equal = 1;
	return (GSS_S_COMPLETE);
    }

    /*
     * Final case... one name is mechanism specific, the other isn't.
     * 
     * We attempt to convert the general name to the mechanism type of
     * the mechanism-specific name, and then do the compare.  If we
     * can't import the general name, then we return that the name is
     * _NOT_ equal.
     */
    if (union_name2->mech_type) {
	/* We make union_name1 the mechanism specific name. */
	union_name1 = (gss_union_name_t) name2;
	union_name2 = (gss_union_name_t) name1;
    }
    major_status = __gss_import_internal_name(minor_status,
					      union_name1->mech_type,
					      union_name2,
					      &internal_name);
    if (major_status != GSS_S_COMPLETE)
	return (GSS_S_COMPLETE);
    major_status = mech->gss_compare_name(mech->context, minor_status,
					  union_name1->mech_name,
					  internal_name, name_equal);
    __gss_release_internal_name(&temp_minor, union_name1->mech_type,
				&internal_name);
    return (major_status);
    
}

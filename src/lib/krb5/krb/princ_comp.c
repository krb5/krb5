/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * compare two principals, returning a krb5_boolean true if equal, false if
 * not.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_princ_comp_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif /* min */

krb5_boolean
krb5_principal_compare(princ1, princ2)
krb5_const_principal princ1;
krb5_const_principal princ2;
{
    register krb5_data * const *p1, * const *p2;

    for (p1 = princ1, p2 = princ2; *p1  && *p2; p1++, p2++) {
	if ((*p1)->length != (*p2)->length)
	    return FALSE;
	if (memcmp((*p1)->data, (*p2)->data, (*p1)->length))
						
	    return FALSE;
    }
    if (*p1 || *p2)			/* didn't both run out of components
					   at once */
	return FALSE;
    return TRUE;
}

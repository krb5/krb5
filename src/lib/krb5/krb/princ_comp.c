/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * compare two principals, returning a krb5_boolean true if equal, false if
 * not.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_princ_comp_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif /* min */

krb5_boolean
krb5_principal_compare(princ1, princ2)
const krb5_principal princ1;
const krb5_principal princ2;
{
    register krb5_data **p1, **p2;

    for (p1 = princ1, p2 = princ2; *p1  && *p2; p1++, p2++)
	if (strncmp((*p1)->data, (*p2)->data, min((*p1)->length,
						  (*p2)->length)))
	    return FALSE;
    if (*p1 || *p2)			/* didn't both run out at once */
	return FALSE;
    return TRUE;
}

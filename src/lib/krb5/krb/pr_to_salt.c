/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * krb5_principal2salt()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_pr_to_salt_c[] =
"$Id$";
#endif  /* !lint & !SABER */


#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

/*
 * Convert a krb5_principal into the default salt for that principal.
 */

krb5_error_code
krb5_principal2salt(pr, ret)
register krb5_const_principal pr;
krb5_data *ret;
{
    int size, offset;
    int nelem;
    register int i;

    if (pr == 0) {
	ret->length = 0;
	ret->data = 0;
	return 0;
    }

    nelem = krb5_princ_size(pr);

    size = krb5_princ_realm(pr)->length;

    for (i = 0; i < nelem; i++)
	size += krb5_princ_component(pr, i)->length;

    ret->length = size;
    if (!(ret->data = malloc (size)))
	return ENOMEM;

    offset = krb5_princ_realm(pr)->length;
    memcpy(ret->data, krb5_princ_realm(pr)->data, offset);

    for (i = 0; i < nelem; i++) {
	memcpy(&ret->data[offset], krb5_princ_component(pr, i)->data,
	       krb5_princ_component(pr, i)->length);
	offset += krb5_princ_component(pr, i)->length;
    }
    return 0;
}

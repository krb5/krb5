/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Glue between Kerberos version and ISODE 6.0 version of structures.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_pwds2kpwds[] =
"$Id$";
#endif	/* lint || saber */

#include <stdio.h>
#include <krb5/krb5.h>

#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

krb5_pwd_data *
KRB5_PWD__DATA2krb5_pwd_data(val, error)
register const struct type_KRB5_PasswdData *val;
register int *error;
{
    register krb5_pwd_data *retval;
    register passwd_phrase_element **element;
    register struct element_KRB5_14 *seq_ptr, *rv;
    register int i;


    if ((retval = (krb5_pwd_data *) calloc (1, sizeof(*retval))) == NULL) {
	fprintf(stderr, "pwds2kpwds: Unable to allocate retval space\n");
	*error = ENOMEM;
	return(0);
    }

    retval->sequence_count = val->passwd__sequence__count;

    seq_ptr = val->passwd__sequence;

    for (i = 0, rv = seq_ptr; rv; i++, rv = rv->next);

    /* Plus One for NULL Terminator */
    if ((element = (passwd_phrase_element **) xcalloc(i + 1, 
		sizeof(*element))) == NULL) {
	fprintf(stderr, 
		"pwds2kpwds: Unable to allocate passwd_phrase_element list\n");
	*error = ENOMEM;
	errout:
	    fprintf(stderr, "pwds2kpwds: Decode Failure\n");
	    krb5_free_pwd_data(retval);
	    return(0);
    }

    retval->element = element;

    for (i = 0, rv = seq_ptr; rv; rv = rv->next, i++) {
	element[i] = KRB5_PWD__SEQ2krb5_pwd_seq(rv->PasswdSequence,
			error);
	if(!element[i]) {
	    while(i >= 0) {
		krb5_free_pwd_sequences(element[i]);
		i--;
	    }
	    krb5_xfree(element);
	    goto errout;
	}
    }


    return(retval);
}

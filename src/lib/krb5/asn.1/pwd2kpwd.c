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
static char rcsid_pwd2kpwd[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

passwd_phrase_element *
KRB5_PWD__SEQ2krb5_pwd_seq(val, error)
const register struct type_KRB5_PasswdSequence *val;
register int *error;
{
    register passwd_phrase_element *retval;

    if ((retval = (passwd_phrase_element *) calloc(1, 
		sizeof(*retval))) == (passwd_phrase_element *) 0) {
	*error = ENOMEM;
	return(0);
    }

    retval->passwd = qbuf2krb5_data(val->passwd, error);
    if (!retval->passwd) {
	xfree(retval);
	return(0);
    }

    retval->phrase = qbuf2krb5_data(val->phrase, error);
    if (!retval->phrase) {
	xfree(retval);
	return(0);
    }

    return(retval);
}

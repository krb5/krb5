/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990,1991 by the Massachusetts Institute of Technology.
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
static char rcsid_g2unix_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

long
gentime2unix(val, error)
const struct type_UNIV_GeneralizedTime *val;
register int *error;
{
    UTC utcp;
    char *tmp;
    long retval;

    tmp = qb2str(val);
    if (!tmp) {
	*error = ENOMEM;
	return(0);
    } else
	*error = 0;

    utcp = str2gent(tmp, strlen(tmp));
    if (utcp == NULLUTC) {
	*error = EINVAL;
	free(tmp);
	return(0);
    }
    retval = gtime(ut2tm(utcp));
    if (retval == NOTOK) {
	*error = EINVAL;
	free(tmp);
	return(0);
    }
    free(tmp);
    return(retval);
}

/*
 * lib/krb5/asn.1/u2gen.c
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


#include <isode/psap.h>
#include <krb5/krb5.h>
#include <krb5/sysincl.h>		/* includes <time.h> */
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

struct type_UNIV_GeneralizedTime *
unix2gentime(val, error)
const int val;
register int *error;
{
    UTCtime utc;
    struct tm *tmp;
    PE pe;
    struct type_UNIV_GeneralizedTime *retval;
    long val1 = (long) val;

    tmp = gmtime(&val1);		/* convert long to tm struct */
    if (tmp->tm_year < 1900)
	tmp->tm_year += 1900;
    tm2ut(tmp, &utc);			/* convert tm struct to utc struct */
    
    pe = gent2prim(&utc);
    if (!pe) {
	*error = ENOMEM;
	return((struct type_UNIV_GeneralizedTime *) 0);
    } else
	*error = 0;
    retval = prim2qb(pe);
    if (!retval)
	*error = pe->pe_errno + ISODE_50_PE_ERR_NONE;
    (void) pe_free(pe);
    return(retval);
}


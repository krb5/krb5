/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Glue between Kerberos version and ISODE 6.0 version of structures.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_u2gen_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>			/* includes <time.h> */

#include <isode/psap.h>
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


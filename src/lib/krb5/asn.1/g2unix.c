/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Glue between Kerberos version and ISODE 6.0 version of structures.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_g2unix_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include "KRB5-types.h"
#include "asn1glue.h"
#include "asn1defs.h"

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
	return(0);
    }
    retval = gtime(ut2tm(utcp));
    if (retval == NOTOK) {
	*error = EINVAL;
	return(0);
    }
    return(retval);
}

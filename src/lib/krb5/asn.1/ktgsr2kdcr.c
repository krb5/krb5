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
static char rcsid_ktgsr2kdcr_c[] =
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

struct type_KRB5_TGS__REP *
krb5_tgs_rep2KRB5_KDC__REP(val, error)
const register krb5_kdc_rep *val;
register int *error;
{
    return (struct type_KRB5_TGS__REP *)
	krb5_kdc_rep2KRB5_KDC__REP(val, KRB5_TGS_REP, error);
}

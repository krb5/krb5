/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb_kntoln for krb425
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_kntoln_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include "krb425.h"

int
krb_kntoln(ad,lname)
AUTH_DAT *ad;
char *lname;
{
	krb5_error_code	retval;
	
	if (!_krb425_local_realm)
		if (retval = krb5_get_default_realm(&_krb425_local_realm))
			return(krb425error(retval));

	if (strcmp(ad->pinst,""))
		return(KFAILURE);
	if (strcmp(ad->prealm, _krb425_local_realm))
		return(KFAILURE);

	(void) strcpy(lname,ad->pname);
	return(KSUCCESS);
}

/*
 * lib/krb425/kntoln.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * krb_kntoln for krb425
 */


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

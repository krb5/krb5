/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb_get_lrealm for krb425
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_get_lrealm_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include "krb425.h"

int
krb_get_lrealm(realm, n)
char *realm;
int n;
{
	krb5_error_code r;
	char **realms;
	int i = 0;

	if (r = krb5_get_host_realm(0, &realms))
		return(krb425error(r));

	if (!realms)
		return(KFAILURE);
	
	while (i < n)
		if (!realms[i++]) {
			krb5_free_host_realm(realms);
			return(KFAILURE);
		}

	strncpy(realm, realms[n-1], REALM_SZ);
	krb5_free_host_realm(realms);
	return(KSUCCESS);
}

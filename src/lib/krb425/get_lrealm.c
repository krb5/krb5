/*
 * lib/krb425/get_lrealm.c
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
 * krb_get_lrealm for krb425
 */


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

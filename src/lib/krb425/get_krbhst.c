/*
 * lib/krb425/get_krbhst.c
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
 * krb_get_krbhst for krb425
 */


#include "krb425.h"

int
krb_get_krbhst(host, realm, n)
char *host;
char *realm;
int n;
{
	krb5_data realm5;
	char **hosts;
	krb5_error_code r;
	int i = 0;

	if (n < 1)
		n = 1;

	set_data5(realm5, realm);

	if (r = krb5_get_krbhst(&realm5, &hosts)) {
		return(krb425error(r));
	}
	if (!hosts)
		return(KFAILURE);
	
	while (i < n)
		if (!hosts[i++]) {
			krb5_free_krbhst(hosts);
			return(KFAILURE);
		}

	strncpy(host, hosts[n-1], REALM_SZ);
	krb5_free_krbhst(hosts);
	return(KSUCCESS);
}

#ifdef	NOT_IMPLEMENTED
krb_get_admhst(host, realm, n)
char *host;
char *realm;
int n;
{

}
#endif

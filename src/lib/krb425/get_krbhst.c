/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb_get_krbhst for krb425
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_get_krbhst_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
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

/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb_realmofhost for krb425
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_realmhost_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include "krb425.h"

char *
krb_realmofhost(host)
char *host;
{
	char **realms;
	char *domain;
	static char ret_realm[REALM_SZ+1];


        domain = index(host, '.');

        /* prepare default */
        if (domain) {
                char *cp;

                strncpy(ret_realm, &domain[1], REALM_SZ);
                ret_realm[REALM_SZ] = '\0';
                /* Upper-case realm */
                for (cp = ret_realm; *cp; cp++)
                        if (islower(*cp))
                                *cp = toupper(*cp);
        } else {
		if (!_krb425_local_realm &&
		    krb5_get_default_realm(&_krb425_local_realm))
			_krb425_local_realm = NULL;

		if (_krb425_local_realm) {
			strncpy(ret_realm, _krb425_local_realm, REALM_SZ);
			ret_realm[REALM_SZ-1] = 0;
		}
	}

	if (krb5_get_host_realm(host, &realms)) {
		return(ret_realm);
	}
	strncpy(ret_realm, realms[0], REALM_SZ);
	krb5_free_host_realm(realms);
	return(ret_realm);
}

/*
 * lib/krb425/realmhost.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * krb_realmofhost for krb425
 */

#include <string.h>

#include "krb425.h"

char *
krb_realmofhost(host)
char *host;
{
	char **realms;
	char *domain;
	static char ret_realm[REALM_SZ+1];


        domain = strchr(host, '.');

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

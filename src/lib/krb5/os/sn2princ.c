/*
 * $Source$
 * $Author$
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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
 * Convert a hostname and service name to a principal in the "standard"
 * form.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_sn2princ_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>
#include <netdb.h>
#include <ctype.h>

krb5_error_code
krb5_sname_to_principal(DECLARG(const char *,hostname),
			DECLARG(const char *,sname),
			DECLARG(krb5_boolean,canonicalize),
			DECLARG(krb5_principal *,ret_princ))
OLDDECLARG(const char *,hostname)
OLDDECLARG(const char *,sname)
OLDDECLARG(krb5_boolean,canonicalize)
OLDDECLARG(krb5_principal *,ret_princ)
{
    struct hostent *hp;
    char **hrealms, *remote_host;
    krb5_error_code retval;
    register char *cp;

    /* copy the hostname into non-volatile storage */

    if (canonicalize) {
	if (!(hp = gethostbyname(hostname)))
	    return KRB5_ERR_BAD_HOSTNAME;
	remote_host = strdup(hp->h_name);
    } else {
	remote_host = strdup(hostname);
    }
    if (!remote_host)
	return ENOMEM;

    for (cp = remote_host; *cp; cp++)
	if (isupper(*cp))
	    *cp = tolower(*cp);

    if (retval = krb5_get_host_realm(remote_host, &hrealms)) {
	free(remote_host);
	return retval;
    }
    if (!hrealms[0]) {
	free(remote_host);
	xfree(hrealms);
	return KRB5_ERR_HOST_REALM_UNKNOWN;
    }

    retval = krb5_build_principal(ret_princ, strlen(hrealms[0]), hrealms[0],
				  sname, remote_host, (char *)0);

    krb5_princ_type(*ret_princ) = KRB5_NT_SRV_HST;

    free(remote_host);
    krb5_free_host_realm(hrealms);
    return retval;
}


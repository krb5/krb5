/*
 * $Source$
 * $Author$
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
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
    krb5_principal lprinc;
    struct hostent *hp;
    char **hrealms, *remote_host;
    krb5_error_code retval;
    register char **cpp, *cp;

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
    if (!(lprinc = (krb5_principal) calloc(4, sizeof(*lprinc)))) {
	free(remote_host);
	krb5_free_host_realm(hrealms);
	return ENOMEM;
    }	
    if (!(lprinc[0] = (krb5_data *)malloc(sizeof(*lprinc[0])))) {
	krb5_free_host_realm(hrealms);
    nomem:
	free(remote_host);
	krb5_free_principal(lprinc);
	return ENOMEM;
    }
    lprinc[0]->data = hrealms[0];
    lprinc[0]->length = strlen(hrealms[0]);

    /* they're allocated; leave the first one alone, however */
    for (cpp = &hrealms[1]; *cpp; cpp++)
	xfree(*cpp);
    xfree(hrealms);

    if (!(lprinc[1] = (krb5_data *)malloc(sizeof(*lprinc[1])))) {
	goto nomem;
    }
    lprinc[1]->length = strlen(sname);
    lprinc[1]->data = strdup(sname);
    if (!(lprinc[2] = (krb5_data *)malloc(sizeof(*lprinc[2])))) {
	goto nomem;
    }
    lprinc[2]->length = strlen(remote_host);
    lprinc[2]->data = remote_host;

    *ret_princ = lprinc;
    return 0;
}


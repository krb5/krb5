/*
 * lib/krb5/os/sn2princ.c
 *
 * Copyright 1991,2002 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Convert a hostname and service name to a principal in the "standard"
 * form.
 */

#define NEED_SOCKETS
#include "k5-int.h"
#include "fake-addrinfo.h"
#include <ctype.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

krb5_error_code KRB5_CALLCONV
krb5_sname_to_principal(krb5_context context, const char *hostname, const char *sname, krb5_int32 type, krb5_principal *ret_princ)
{
    char **hrealms, *realm, *remote_host;
    krb5_error_code retval;
    register char *cp;
    char localname[MAXHOSTNAMELEN];


    if ((type == KRB5_NT_UNKNOWN) ||
	(type == KRB5_NT_SRV_HST)) {

	/* if hostname is NULL, use local hostname */
	if (! hostname) {
	    if (gethostname(localname, MAXHOSTNAMELEN))
		return SOCKET_ERRNO;
	    hostname = localname;
	}

	/* if sname is NULL, use "host" */
	if (! sname)
	    sname = "host";

	/* copy the hostname into non-volatile storage */

	if (type == KRB5_NT_SRV_HST) {
	    struct addrinfo *ai, hints;
	    int err;
	    char hnamebuf[NI_MAXHOST];

	    /* Note that the old code would accept numeric addresses,
	       and if the gethostbyaddr step could convert them to
	       real hostnames, you could actually get reasonable
	       results.  If the mapping failed, you'd get dotted
	       triples as realm names.  *sigh*

	       The latter has been fixed in hst_realm.c, but we should
	       keep supporting numeric addresses if they do have
	       hostnames associated.  */

	    memset(&hints, 0, sizeof(hints));
	    hints.ai_family = AF_INET;
	try_getaddrinfo_again:
	    err = getaddrinfo(hostname, 0, &hints, &ai);
	    if (err) {
		if (hints.ai_family == AF_INET) {
		    /* Just in case it's an IPv6-only name.  */
		    hints.ai_family = 0;
		    goto try_getaddrinfo_again;
		}
		return KRB5_ERR_BAD_HOSTNAME;
	    }
	    remote_host = strdup(ai->ai_canonname ? ai->ai_canonname : hostname);
	    if (!remote_host) {
		freeaddrinfo(ai);
		return ENOMEM;
	    }
	    /*
	     * Do a reverse resolution to get the full name, just in
	     * case there's some funny business going on.  If there
	     * isn't an in-addr record, give up.
	     */
	    /* XXX: This is *so* bogus.  There are several cases where
	       this won't get us the canonical name of the host, but
	       this is what we've trained people to expect.  We'll
	       probably fix it at some point, but let's try to
	       preserve the current behavior and only shake things up
	       once when it comes time to fix this lossage.  */
	    err = getnameinfo(ai->ai_addr, ai->ai_addrlen,
			      hnamebuf, sizeof(hnamebuf), 0, 0, NI_NAMEREQD);
	    freeaddrinfo(ai);
	    if (err == 0) {
		free(remote_host);
		remote_host = strdup(hnamebuf);
		if (!remote_host)
		    return ENOMEM;
	    }
	} else /* type == KRB5_NT_UNKNOWN */ {
	    remote_host = strdup(hostname);
	}
	if (!remote_host)
	    return ENOMEM;

	if (type == KRB5_NT_SRV_HST)
	    for (cp = remote_host; *cp; cp++)
		if (isupper((int) (*cp)))
		    *cp = tolower((int) (*cp));

	/*
	 * Windows NT5's broken resolver gratuitously tacks on a
	 * trailing period to the hostname (at least it does in
	 * Beta2).  Find and remove it.
	 */
	if (remote_host[0]) {
		cp = remote_host + strlen(remote_host)-1;
		if (*cp == '.')
			*cp = 0;
	}
	

	if ((retval = krb5_get_host_realm(context, remote_host, &hrealms))) {
	    free(remote_host);
	    return retval;
	}
	if (!hrealms[0]) {
	    free(remote_host);
	    krb5_xfree(hrealms);
	    return KRB5_ERR_HOST_REALM_UNKNOWN;
	}
	realm = hrealms[0];

	retval = krb5_build_principal(context, ret_princ, strlen(realm),
				      realm, sname, remote_host,
				      (char *)0);

	krb5_princ_type(context, *ret_princ) = type;

	free(remote_host);

	krb5_free_host_realm(context, hrealms);
	return retval;
    } else {
	return KRB5_SNAME_UNSUPP_NAMETYPE;
    }
}


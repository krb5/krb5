/*
 * lib/krb5/os/hst_realm.c
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
 * krb5_get_host_realm()
 */


/*
 Figures out the Kerberos realm names for host, filling in a
 pointer to an argv[] style list of names, terminated with a null pointer.
 
 If host is NULL, the local host's realms are determined.

 If there are no known realms for the host, the filled-in pointer is set
 to NULL.

 The pointer array and strings pointed to are all in allocated storage,
 and should be freed by the caller when finished.

 returns system errors
*/

/*
 * Implementation notes:
 *
 * this implementation only provides one realm per host, using the same
 * mapping file used in kerberos v4.

 * Given a fully-qualified domain-style primary host name,
 * return the name of the Kerberos realm for the host.
 * If the hostname contains no discernable domain, or an error occurs,
 * return the local realm name, as supplied by krb5_get_default_realm().
 * If the hostname contains a domain, but no translation is found,
 * the hostname's domain is converted to upper-case and returned.
 *
 * The format of each line of the translation file is:
 * domain_name kerberos_realm
 * -or-
 * host_name kerberos_realm
 *
 * domain_name should be of the form .XXX.YYY (e.g. .LCS.MIT.EDU)
 * host names should be in the usual form (e.g. FOO.BAR.BAZ)
 */

#define NEED_SOCKETS
#include "k5-int.h"
#include <ctype.h>
#include <stdio.h>
#ifdef USE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

/* for old Unixes and friends ... */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

krb5_error_code
krb5_get_host_realm(context, host, realmsp)
    krb5_context context;
    const char *host;
    char ***realmsp;
{
    char **retrealms = NULL;
    char *domain, *default_realm, *realm, *cp;
    krb5_error_code retval;
    int l;
    char local_host[MAXHOSTNAMELEN+1];

    if (host)
	strncpy(local_host, host, MAXHOSTNAMELEN);
    else {
	if (gethostname(local_host, sizeof(local_host)-1) == -1)
	    return errno;
    }
    local_host[sizeof(local_host)-1] = '\0';
    for (cp = local_host; *cp; cp++) {
	if (isupper(*cp))
	    *cp = tolower(*cp);
    }
    l = strlen(local_host);
    /* strip off trailing dot */
    if (l && local_host[l-1] == '.')
	    local_host[l-1] = 0;
    domain = strchr(local_host, '.');

    /* prepare default */
    if (domain) {
	if (!(default_realm = malloc(strlen(domain+1)+1)))
	    return ENOMEM;
	strcpy(default_realm, domain+1);
	/* Upper-case realm */
	for (cp = default_realm; *cp; cp++)
	    if (islower(*cp))
		*cp = toupper(*cp);
    } else {
	retval = krb5_get_default_realm(context, &default_realm);
	if (retval) {
	    krb5_xfree(retrealms);
	    return retval;
	}
    }

    if (domain) {
	retval = profile_get_string(context->profile, "domain_realm",
				    domain, 0, default_realm, &realm);
	free(default_realm);
	if (retval)
	    return retval;
	default_realm = realm;
    }

    retval = profile_get_string(context->profile, "domain_realm", local_host,
				0, default_realm, &realm);
    free(default_realm);
    if (retval)
	return retval;

    if (!(retrealms = (char **)calloc(2, sizeof(*retrealms)))) {
	free(realm);
	return ENOMEM;
    }

    retrealms[0] = realm;
    retrealms[1] = 0;
    
    *realmsp = retrealms;
    return 0;
}

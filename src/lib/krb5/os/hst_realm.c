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
#ifdef HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

/* for old Unixes and friends ... */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_get_host_realm(context, host, realmsp)
    krb5_context context;
    const char FAR *host;
    char FAR * FAR * FAR *realmsp;
{
    char **retrealms;
    char *default_realm, *realm, *cp;
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

    /*
       Search for the best match for the host or domain.
       Example: Given a host a.b.c.d, try to match on:
         1) A.B.C.D
	 2) .B.C.D
	 3) B.C.D
	 4) .C.D
	 5) C.D
	 6) .D
	 7) D
     */

    cp = local_host;
    realm = default_realm = (char *)NULL;
    while (cp) {
	retval = profile_get_string(context->profile, "domain_realm", cp,
				    0, (char *)NULL, &realm);
	if (retval)
	    return retval;
	if (realm != (char *)NULL)
	    break;	/* Match found */

	/* Setup for another test */
	if (*cp == '.') {
	    cp++;
	    if (default_realm == (char *)NULL) {
		/* If nothing else works, use the host's domain */
		default_realm = cp;
	    }
	} else {
	    cp = strchr(cp, '.');
	}
    }

    if (realm == (char *)NULL) {
	    if (default_realm != (char *)NULL) {
		    /* We are defaulting to the realm of the host */
		    if (!(cp = (char *)malloc(strlen(default_realm)+1)))
			    return ENOMEM;
		    strcpy(cp, default_realm);
		    realm = cp;

		    /* Assume the realm name is upper case */
		    for (cp = realm; *cp; cp++)
			    if (islower(*cp))
				    *cp = toupper(*cp);
	    } else {
		    /* We are defaulting to the local realm */
		    retval = krb5_get_default_realm(context, &realm);
		    if (retval) {
			    return retval;
		    }
	    }
    }
    if (!(retrealms = (char **)calloc(2, sizeof(*retrealms)))) {
	if (realm != (char *)NULL)
	    free(realm);
	return ENOMEM;
    }

    retrealms[0] = realm;
    retrealms[1] = 0;
    
    *realmsp = retrealms;
    return 0;
}

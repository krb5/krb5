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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
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

#ifdef KRB5_DNS_LOOKUP       
#ifdef WSHELPER
#include <wshelper.h>
#else /* WSHELPER */
#include <arpa/inet.h>       
#include <arpa/nameser.h>    
#include <resolv.h>          
#include <netdb.h>
#endif /* WSHELPER */
#endif /* KRB5_DNS_LOOKUP */ 

/* for old Unixes and friends ... */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

#define MAX_DNS_NAMELEN (15*(MAXHOSTNAMELEN + 1)+1)

#ifdef KRB5_DNS_LOOKUP
/*
 * Try to look up a TXT record pointing to a Kerberos realm
 */

krb5_error_code
krb5_try_realm_txt_rr(prefix, name, realm)
    const char *prefix, *name;
    char **realm;
{
    union {
        unsigned char bytes[2048];
        HEADER hdr;
    } answer;
    unsigned char *p;
    char host[MAX_DNS_NAMELEN], *h;
    int size;
    int type, class, numanswers, numqueries, rdlen, len;

    /*
     * Form our query, and send it via DNS
     */

    if (name == NULL || name[0] == '\0') {
        strcpy(host,prefix);
    } else {
        if ( strlen(prefix) + strlen(name) + 3 > MAX_DNS_NAMELEN )
            return KRB5_ERR_HOST_REALM_UNKNOWN;
        sprintf(host,"%s.%s", prefix, name);

        /* Realm names don't (normally) end with ".", but if the query
           doesn't end with "." and doesn't get an answer as is, the
           resolv code will try appending the local domain.  Since the
           realm names are absolutes, let's stop that.  

           But only if a name has been specified.  If we are performing
           a search on the prefix alone then the intention is to allow
           the local domain or domain search lists to be expanded.
        */

        h = host + strlen (host);
        if (h > host && h[-1] != '.')
            strcpy (h, ".");
    }
    size = res_search(host, C_IN, T_TXT, answer.bytes, sizeof(answer.bytes));

    if (size < 0)
	return KRB5_ERR_HOST_REALM_UNKNOWN;

    p = answer.bytes;

    numqueries = ntohs(answer.hdr.qdcount);
    numanswers = ntohs(answer.hdr.ancount);

    p += sizeof(HEADER);

    /*
     * We need to skip over the questions before we can get to the answers,
     * which means we have to iterate over every query record.  We use
     * dn_expand to tell us how long each compressed name is.
     */

#define INCR_CHECK(x, y) x += y; if (x > size + answer.bytes) \
                         return KRB5_ERR_HOST_REALM_UNKNOWN
#define CHECK(x, y) if (x + y > size + answer.bytes) \
                         return KRB5_ERR_HOST_REALM_UNKNOWN
#define NTOHSP(x, y) x[0] << 8 | x[1]; x += y

    while (numqueries--) {
	len = dn_expand(answer.bytes, answer.bytes + size, p, host, 
                         sizeof(host));
	if (len < 0)
	    return KRB5_ERR_HOST_REALM_UNKNOWN;
	INCR_CHECK(p, len + 4);		/* Name plus type plus class */
    }

    /*
     * We're now pointing at the answer records.  Process the first
     * TXT record we find.
     */

    while (numanswers--) {
	
	/* First the name; use dn_expand to get the compressed size */
	len = dn_expand(answer.bytes, answer.bytes + size, p,
			host, sizeof(host));
	if (len < 0)
	    return KRB5_ERR_HOST_REALM_UNKNOWN;
	INCR_CHECK(p, len);

	/* Next is the query type */
        CHECK(p, 2);
	type = NTOHSP(p,2);

	/* Next is the query class; also skip over 4 byte TTL */
        CHECK(p,6);
	class = NTOHSP(p,6);

	/* Record data length - make sure we aren't truncated */

        CHECK(p,2);
	rdlen = NTOHSP(p,2);

	if (p + rdlen > answer.bytes + size)
	    return KRB5_ERR_HOST_REALM_UNKNOWN;

	/*
	 * If this is a TXT record, return the string.  Note that the
	 * string has a 1-byte length in the front
	 */
	/* XXX What about flagging multiple TXT records as an error?  */

	if (class == C_IN && type == T_TXT) {
	    len = *p++;
	    if (p + len > answer.bytes + size)
		return KRB5_ERR_HOST_REALM_UNKNOWN;
	    *realm = malloc(len + 1);
	    if (*realm == NULL)
		return ENOMEM;
	    strncpy(*realm, (char *) p, len);
	    (*realm)[len] = '\0';
            /* Avoid a common error. */
            if ( (*realm)[len-1] == '.' )
                (*realm)[len-1] = '\0';
	    return 0;
	}
    }

    return KRB5_ERR_HOST_REALM_UNKNOWN;
}
#endif /* KRB5_DNS_LOOKUP */


KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_get_host_realm(context, host, realmsp)
    krb5_context context;
    const char FAR *host;
    char FAR * FAR * FAR *realmsp;
{
    char **retrealms;
    char *default_realm, *realm, *cp, *temp_realm;
    krb5_error_code retval;
    int l;
    char local_host[MAX_DNS_NAMELEN+1];
    struct hostent *h;


    if (host)
	strncpy(local_host, host, sizeof(local_host));
    else {
	if (gethostname(local_host, sizeof(local_host)) == -1)
	    return SOCKET_ERRNO;
	/*
	 * Try to make sure that we have a fully qualified name if
	 * possible.  We need to handle the case where the host has a
	 * dot but is not FQDN, so we call gethostbyname.
	 */
	h = gethostbyname(local_host);
	if (h) {
	    strncpy(local_host, h->h_name, sizeof(local_host));
	}
    }
    local_host[sizeof(local_host) - 1] = '\0';

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
    temp_realm = 0;
    while (cp) {
	retval = profile_get_string(context->profile, "domain_realm", cp,
				    0, (char *)NULL, &temp_realm);
	if (retval)
	    return retval;
	if (temp_realm != (char *)NULL)
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
    if (temp_realm) {
        realm = malloc(strlen(temp_realm) + 1);
        if (!realm) {
            profile_release_string(temp_realm);
            return ENOMEM;
        }
        strcpy(realm, temp_realm);
        profile_release_string(temp_realm);
    }

#ifdef KRB5_DNS_LOOKUP
    if (realm == (char *)NULL) {
        int use_dns = _krb5_use_dns(context);
        if ( use_dns ) {
            /*
             * Since this didn't appear in our config file, try looking
             * it up via DNS.  Look for a TXT records of the form:
             *
             * _kerberos.<hostname>
             * _kerberos.<searchlist>
             * _kerberos.<defaultrealm>
             *
             */
            cp = local_host;
            do {
                retval = krb5_try_realm_txt_rr("_kerberos", cp, &realm);
                cp = strchr(cp,'.');
                if (cp) 
                    cp++;
            } while (retval && cp && cp[0]);
            if (retval)
                retval = krb5_try_realm_txt_rr("_kerberos", "", &realm);
            if (retval && default_realm) {
                cp = default_realm;
                do {
                    retval = krb5_try_realm_txt_rr("_kerberos", cp, &realm);
                    cp = strchr(cp,'.');
                    if (cp) 
                        cp++;
                } while (retval && cp && cp[0]);
            }
        }
    }
#endif /* KRB5_DNS_LOOKUP */
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

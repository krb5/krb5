/*
 * realmofhost.c
 *
 * Copyright 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * routine to convert hostname into realm name.
 */

#include "mit-copyright.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#ifdef HAS_STDLIB_H
#include <stdlib.h>
#else
extern char *malloc();
#endif
#define	DEFINE_SOCKADDR		/* Ask for MAXHOSTNAMELEN */
#include "krb.h"

/*
 * krb_realmofhost.
 * Given a fully-qualified domain-style primary host name,
 * return the name of the Kerberos realm for the host.
 * If the hostname contains no discernable domain, or an error occurs,
 * return the local realm name, as supplied by get_krbrlm().
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

static char ret_realm[REALM_SZ+1];

char * INTERFACE
krb_realmofhost(host)
char *host;
{
	char *domain;
	FILE *trans_file;
	FILE *krb__get_realmsfile();
 	/*
 	 * This used to be MAXHOSTNAMELEN, but we don't know how big
 	 * that will necessarily be on all systems, so assume 1024.
 	 */
 	char trans_host[1025];
	char trans_realm[REALM_SZ+1];
	int retval;
	struct hostent *h;
	char *lhost;

	/* First, canonicalize it.  This is in case the caller
	   didn't have a fully qualified domain name.  */
	if ((h=gethostbyname(host)) == NULL)
		lhost = host;
	else {
		lhost = h->h_name;
#ifdef DO_REVERSE_RESOLVE
		if (h->h_addr_list != NULL && h->h_addr_list[0] != NULL) {
			char *rev_addr; int rev_type, rev_len;

			rev_type = h->h_addrtype;
			rev_len = h->h_length;
			rev_addr = malloc(rev_len);
			if (rev_addr != NULL) {
				memcpy(rev_addr, h->h_addr_list[0], rev_len);
				h = gethostbyaddr(rev_addr, rev_len, rev_type);
				free(rev_addr);
				if (h == NULL)
					lhost = host;
				else
					lhost = h->h_name;
			}
		}
#endif
	}

	domain = strchr(lhost, '.');

	/* prepare default */
	if (domain) {
		char *cp;

		/* If the domain is just below the top, e.g., CYGNUS.COM,
		   then we special-case it; if someone really wants a
		   realm called COM they will just have to specify it
		   properly. */
		if (((cp = strchr(domain+1, '.')) == (char *) 0)
		    /* Handle root domain properly (COM.): */
		    || (*(cp + 1) == '\0'))
		  domain = lhost - 1;	/* -1 fakes "period" before domain */

		strncpy(ret_realm, domain+1, REALM_SZ);
		ret_realm[REALM_SZ] = '\0';
		/* Upper-case realm */
		for (cp = ret_realm; *cp; cp++)
			if (islower(*cp))
				*cp = toupper(*cp);
	} else {
		krb_get_lrealm(ret_realm, 1);
	}

	if ((trans_file = krb__get_realmsfile()) == (FILE *) 0)
		/* krb_errno = KRB_NO_TRANS */
		return(ret_realm);

	/* loop while not exact match, and more entries to read */
	while (1) {
	        /* XXX REALM_SZ == 40 */
		if ((retval = fscanf(trans_file, "%1023s %40s",
				     trans_host, trans_realm)) != 2) {
			if (retval == EOF)
			  break;
			continue;	/* ignore broken lines */
		}
		trans_host[(MAXHOSTNAMELEN <= 1023) ? MAXHOSTNAMELEN : 1023]
			= '\0';
		trans_realm[REALM_SZ] = '\0';
		if (trans_host[0] == '.') {
		  /* want domain match only */
		  if (domain && (strlen(trans_host) == strlen(domain))
		      && !strcasecmp (trans_host, domain)) {
		    /* got domain match, save for later */
		    (void) strcpy (ret_realm, trans_realm);
		    continue;
		  }
		} else {
		  /* want exact match of hostname */
		  if ((strlen(lhost) == strlen(trans_host)) &&
		      !strcasecmp (trans_host, lhost)) {
		    (void) strcpy (ret_realm, trans_realm);
		    break;
		  }
		}
	}
	fclose (trans_file);
	return ret_realm;
}

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

#define DEF_REALMNAME_SIZE	256

extern char *krb5_trans_file;

#ifdef _WINDOWS
/*
 * Windows DLL can't use the fscanf routine. We need fscanf to read
 * in the host and realm. Read_2str with read_1str duplicate the needed
 * functionality. See also realm_dom.c.
 */
static int
read_1str (FILE *fp, char *buf, int buflen) {
    int c;

    while (1) {
        c = fgetc (fp);                         /* Past leading whitespace */
        if (c == EOF)
            return 0;
        if (! isspace (c))
            break;
    }

    while (1) {
        if (buflen > 0) {                       /* Store the character */
            *buf++ = (char) c;
            --buflen;
        }
        if (buflen <= 0)                        /* Fscanf stops scanning... */
            break;                              /* ...when buffer is full */

        c = fgetc (fp);                         /* Get next character */
        if (c == EOF || isspace (c))
            break;
    }

    if (buflen)                                 /* Make ASCIIZ if room */
        *buf = '\0';

    return 1;
}

static int 
read_2str (FILE *fp, char *b1, int l1, char *b2, int l2) {
    int n;

    n = read_1str (fp, b1, l1);                 /* Read first string */
    if (!n) return EOF;
    n = read_1str (fp, b2, l2);                 /* Read second string */
    if (!n) return 1;
    return 2;
}

#endif /* _WINDOWS */

krb5_error_code INTERFACE
krb5_get_host_realm(context, host, realmsp)
    krb5_context context;
    const char *host;
    char ***realmsp;
{
    char **retrealms;
    char *domain;
    FILE *trans_file;
    char trans_host[MAXHOSTNAMELEN+1];
    char local_host[MAXHOSTNAMELEN+1];
    char trans_realm[DEF_REALMNAME_SIZE];
    krb5_error_code retval;
    int scanval;
    char scanstring[7+2*16];		/* 7 chars + 16 for each decimal
					   conversion */

    if (!(retrealms = (char **)calloc(2, sizeof(*retrealms))))
	return ENOMEM;
    if (!host) {
	if (gethostname(local_host, sizeof(local_host)-1) == -1)
	    return errno;
	local_host[sizeof(local_host)-1] = '\0';
	host = local_host;
    }
    domain = strchr(host, '.');

    /* prepare default */
    if (domain) {
	char *cp;

	if (!(retrealms[0] = malloc(strlen(&domain[1])+1))) {
	    krb5_xfree(retrealms);
	    return ENOMEM;
	}
	strcpy(retrealms[0], &domain[1]);
	/* Upper-case realm */
	for (cp = retrealms[0]; *cp; cp++)
	    if (islower(*cp))
		*cp = toupper(*cp);
    } else {
	if (retval = krb5_get_default_realm(context, &retrealms[0])) {
	    krb5_xfree(retrealms);
	    return retval;
	}
    }

    if ((trans_file = fopen(krb5_trans_file, "r")) == (FILE *) 0) {
	krb5_xfree(retrealms[0]);
	krb5_xfree(retrealms);
	return KRB5_TRANS_CANTOPEN;
    }
    (void) sprintf(scanstring, "%%%ds %%%ds",
		   sizeof(trans_host)-1,sizeof(trans_realm)-1);
    while (1) {
        #ifdef _WINDOWS
            scanval = read_2str (trans_file, trans_host, sizeof(trans_host)-1,
                trans_realm, sizeof(trans_realm)-1);
        #else
            scanval = fscanf(trans_file, scanstring, trans_host, trans_realm));
        #endif
	if (scanval != 2) {
	    if (scanval == EOF) {
		fclose(trans_file);
		goto out;
	    }
	    continue;			/* ignore broken lines */
	}
	trans_host[sizeof(trans_host)-1] = '\0';
	trans_realm[sizeof(trans_realm)-1] = '\0';
	if (!strcasecmp(trans_host, host)) {
	    /* exact match of hostname, so return the realm */
	    if (!(retrealms[0] = realloc(retrealms[0],
					 strlen(trans_realm)+1))) {
		krb5_xfree(retrealms);
		return ENOMEM;
	    }
	    (void) strcpy(retrealms[0], trans_realm);
	    fclose(trans_file);
	    goto out;
	}
	if ((trans_host[0] == '.') && domain) { 
	    /* this is a possible domain match */
	    if (!strcasecmp(trans_host, domain)) {
		/* domain match, save for later */
		if (!(retrealms[0] = realloc(retrealms[0],
					     strlen(trans_realm)+1))) {
		    krb5_xfree(retrealms);
		    return ENOMEM;
		}
		(void) strcpy(retrealms[0], trans_realm);
		continue;
	    }
	}
    }
 out:
    *realmsp = retrealms;
    return 0;
}




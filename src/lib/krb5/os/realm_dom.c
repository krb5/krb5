/*
 * lib/krb5/os/realm_dom.c
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
 * krb5_get_realm_domain()
 */


/*
 * Determines the proper domain name for a realm.  This is mainly so that
 * a krb4 principal can be converted properly into a krb5 principal.
 * Currently, the same style of mapping file used in krb4.
 *
 * If realm is NULL, this function will assume the default realm
 * of the local host.
 *
 * The returned domain is allocated, and must be freed by the caller.
 *
 * This was hacked together from krb5_get_host_realm().
 */

#include "k5-int.h"
#include <ctype.h>
#include <stdio.h>

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
 * functionality. See also host_realm.c
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
krb5_get_realm_domain(context, realm, domain)
    krb5_context context;
    const char *realm;
    char **domain;
{
    char **realmlist = NULL;
    char *retdomain = NULL;
    char trans_host[MAXHOSTNAMELEN+1];
    char trans_realm[DEF_REALMNAME_SIZE];
    krb5_error_code retval;
    FILE *trans_file;
    int scanval;
    char scanstring[7+2*16];		/* 7 chars + 16 for each decimal
					   conversion */

    if (realm == NULL) {
	if (retval = krb5_get_host_realm(context, NULL, &realmlist))
	    return retval;
	realm = realmlist[0];
    }
    krb5_find_config_files();
    if ((trans_file = fopen(krb5_trans_file, "r")) == (FILE *) 0) {
	if (realmlist != NULL) {
	    krb5_xfree(realmlist[0]);
	    krb5_xfree(realmlist);
	}
	return KRB5_TRANS_CANTOPEN;
    }
    (void) sprintf(scanstring, "%%%ds %%%ds",
		   sizeof(trans_host)-1,sizeof(trans_realm)-1);
    while (1) {
#ifdef _WINDOWS
            scanval = read_2str (trans_file, trans_host, sizeof(trans_host)-1,
                trans_realm, sizeof(trans_realm)-1);
#else
            scanval = fscanf(trans_file, scanstring, trans_host, trans_realm);
#endif
	if (scanval != 2) {
	    if (scanval == EOF) {
		fclose(trans_file);
		if (realmlist != NULL) {
		    krb5_xfree(realmlist[0]);
		    krb5_xfree(realmlist);
		}
		if ((retdomain = malloc(strlen(realm) + 2)) == NULL)
		    return ENOMEM;
		strcpy(retdomain, ".");
		strcat(retdomain, realm); /* return the realm as the domain
					     if lookup fails */
		*domain = retdomain;
		return 0;
	    }
	    continue;
	}
	trans_host[sizeof(trans_host)-1] = '\0';
	trans_realm[sizeof(trans_realm)-1] = '\0';
	if (!strcmp(trans_realm, realm)) {
	    if (trans_host[0] == '.') {
		if ((retdomain = malloc(strlen(trans_host) + 1)) == NULL) {
		    if (realmlist != NULL) {
			krb5_xfree(realmlist[0]);
			krb5_xfree(realmlist);
		    }
		    return ENOMEM;
		}
		(void)strcpy(retdomain, trans_host);
		fclose(trans_file);
		if (realmlist != NULL) {
		    krb5_xfree(realmlist[0]);
		    krb5_xfree(realmlist);
		}
		*domain = retdomain;
		return 0;
	    } else
		continue;
	}
    }
}

/*
 * $Source$
 * $Author$
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

#if !defined(lint) && !defined(SABER)
static char rcsid_hst_realm_c[] =
"$Id$";
#endif	/* !lint & !SABER */

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

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>
#include <krb5/sysincl.h>
#include <ctype.h>

#include <stdio.h>

/* for old Unixes and friends ... */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

#define DEF_REALMNAME_SIZE	256

extern char *krb5_trans_file;

krb5_error_code
krb5_get_realm_domain(realm, domain)
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
	if (retval = krb5_get_host_realm(NULL, &realmlist))
	    return retval;
	realm = realmlist[0];
    }
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
	if ((scanval = fscanf(trans_file, scanstring,
			      trans_host, trans_realm)) != 2) {
	    if (scanval == EOF) {
		fclose(trans_file);
		if (realmlist != NULL) {
		    krb5_xfree(realmlist[0]);
		    krb5_xfree(realmlist);
		}
		*domain = NULL;
		return 0;
	    }
	    continue;
	}
	trans_host[sizeof(trans_host)-1] = '\0';
	trans_realm[sizeof(trans_realm)-1] = '\0';
	if (!strcmp(trans_realm, realm)) {
	    if (trans_host[0] == '.') {
		if ((retdomain = malloc(strlen(trans_realm) + 1)) == NULL) {
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

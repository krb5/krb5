/*
 * $Source$
 * $Author$
 *
 * Copyright 1992 by the Massachusetts Institute of Technology.
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
 * Build a principal from a V4 specification
 * 
 * NOTE: This is highly site specific, and is only really necessary
 * for sites who need to convert from V4 to V5.  It is used by both
 * the KDC and the kdb5_convert program.  Since its use is highly
 * specialized, the necesary information is just going to be
 * hard-coded in this file.
 */

#include <krb5/krb5.h>
#include <string.h>

struct krb_convert {
	char	*v4_str;
	char	*v5_str;
	int	flags;
};

#define DO_REALM_CONVERSION 0x00000001

/*
 * Kadmin doesn't do realm conversion because it's currently
 * kadmin/REALM.NAME.  It should be kadmin/kerberos.master.host, but
 * we'll fix that in the next release.
 */
static struct krb_convert sconv_list[] = {
    "kadmin",	"kadmin",	0,
    "rcmd",	"host",		DO_REALM_CONVERSION,
    "discuss",	"discuss",	DO_REALM_CONVERSION,
    "rvdsrv",	"rvdsrv",	DO_REALM_CONVERSION,
    "sample",	"sample",	DO_REALM_CONVERSION,
    "olc",	"olc",		DO_REALM_CONVERSION,
    "pop",	"pop",		DO_REALM_CONVERSION,
    "sis",	"sis",		DO_REALM_CONVERSION,
    "rfs",	"rfs",		DO_REALM_CONVERSION,
    0,		0,
};

static struct krb_convert rconv_list[] = {
	"ATHENA.MIT.EDU",	".mit.edu",
	0,			0
};

krb5_error_code
krb5_425_conv_principal(name, instance, realm, princ)
    const char	*name;
    const char	*instance;
    const char	*realm;
    krb5_principal	*princ;
{
    struct krb_convert *p;
    char buf[256];		/* V4 instances are limited to 40 characters */
		
    if (instance) {
	if (instance[0] == '\0') {
	    instance = 0;
	    goto not_service;
	}
	p = sconv_list;
	while (1) {
	    if (!p->v4_str)
		goto not_service;
	    if (!strcmp(p->v4_str, name))
		break;
	    p++;
	}
	name = p->v5_str;
	if (p->flags & DO_REALM_CONVERSION) {
	    strcpy(buf, instance);
	    p = rconv_list;
	    while (1) {
		if (!p->v4_str)
		    break;
		if (!strcmp(p->v4_str, realm))
		    break;
		p++;
	    }
	    if (p->v5_str)
		strcat(buf, p->v5_str);
	    instance = buf;
	}
	}

    not_service:	
	return(krb5_build_principal(princ, strlen(realm), realm, name,
				    instance, 0));
    }

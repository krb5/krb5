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

struct krb_convert {
	char	*v4_str;
	char	*v5_str;
};

static struct krb_convert sconv_list[] = {
	"rcmd",		"host",
	"discuss",	"discuss",
	"rvdsrv",	"rvdsrv",
	"olc",		"olc",
	"pop",		"pop",
	"sis",		"sis",
	"rfs",		"rfs",
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

not_service:	
	return(krb5_build_principal(princ, strlen(realm), realm, name,
				    instance, 0));
}

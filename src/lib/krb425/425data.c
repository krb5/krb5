/*
 * lib/krb425/425data.c
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
 * Common data for krb425 library
 */


#include "krb425.h"

char 			*_krb425_local_realm = 0;
krb5_ccache 		_krb425_ccache = 0;
int			_krb425_error_init = 0;
krb5_keyblock		_krb425_servkey;

#ifdef	EBUG
char *
basename(s)
char *s;
{
	char *r;
	char *rindex();

	if (r = rindex(s, '/'))
		return(r+1);
	return(s);
}
#endif

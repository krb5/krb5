/*
 * $Source$
 * $Author$
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
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
 * Allocate & prepare a default replay cache for a server.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_srv_rcache_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

krb5_error_code
krb5_get_server_rcache(piece, rcptr)
const char *piece;
krb5_rcache *rcptr;
{
    krb5_rcache rcache;
    char *cachename;
    extern krb5_deltat krb5_clockskew;
    krb5_error_code retval;
    int len = strlen(piece);

    if (rcache = (krb5_rcache) malloc(sizeof(*rcache))) {
	if (!(retval = krb5_rc_resolve_type(&rcache, "dfl"))) {

	    if (cachename = malloc(len+1+3)) {
		strcpy(cachename, "rc_");
		strcat(cachename, piece);
		cachename[len+3] = '\0';

		if (!(retval = krb5_rc_resolve(rcache, cachename))) {
		    if (!((retval = krb5_rc_recover(rcache)) &&
			  (retval = krb5_rc_initialize(rcache,
						       krb5_clockskew)))) {
			*rcptr = rcache;
			return 0;
		    }
		}
	    } else
		retval = ENOMEM;
	}
	xfree(rcache);
    } else
	retval = ENOMEM;
    return retval;
}

/*
 * $Source$
 * $Author$
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
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

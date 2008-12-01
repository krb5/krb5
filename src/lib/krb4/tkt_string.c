/*
 * tkt_string.c
 *
 * Copyright 1985, 1986, 1987, 1988, 2002 by the Massachusetts
 * Institute of Technology.  All Rights Reserved.
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
 */

#include "krb.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "autoconf.h"
#include "port-sockets.h" /* XXX this gets us MAXPATHLEN but we should find
			     a better way */

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#else
char *getenv();
#endif


#ifdef _WIN32
typedef unsigned long uid_t;
uid_t getuid(void) { return 0; }
#endif /* _WIN32 */

/*
 * This routine is used to generate the name of the file that holds
 * the user's cache of server tickets and associated session keys.
 *
 * If it is set, krb_ticket_string contains the ticket file name.
 * Otherwise, the filename is constructed as follows:
 *
 * If it is set, the environment variable "KRBTKFILE" will be used as
 * the ticket file name.  Otherwise TKT_ROOT (defined in "krb.h") and
 * the user's uid are concatenated to produce the ticket file name
 * (e.g., "/tmp/tkt123").  A pointer to the string containing the ticket
 * file name is returned.
 */

static char krb_ticket_string[MAXPATHLEN];

const char *tkt_string()
{
    char *env;
    uid_t getuid();

    if (!*krb_ticket_string) {
	env = getenv("KRBTKFILE");
        if (env) {
	    (void) strncpy(krb_ticket_string, env,
			   sizeof(krb_ticket_string)-1);
	    krb_ticket_string[sizeof(krb_ticket_string)-1] = '\0';
	} else {
	    /* 32 bits of signed integer will always fit in 11 characters
	     (including the sign), so no need to worry about overflow */
	    (void) snprintf(krb_ticket_string, sizeof(krb_ticket_string),
			    "%s%d",TKT_ROOT,(int) getuid());
        }
    }
    return krb_ticket_string;
}

/*
 * This routine is used to set the name of the file that holds the user's
 * cache of server tickets and associated session keys.
 *
 * The value passed in is copied into local storage.
 *
 * NOTE:  This routine should be called during initialization, before other
 * Kerberos routines are called; otherwise tkt_string() above may be called
 * and return an undesired ticket file name until this routine is called.
 */

void KRB5_CALLCONV
krb_set_tkt_string(val)
    const char *val;
{
    (void) strncpy(krb_ticket_string, val, sizeof(krb_ticket_string)-1);
    krb_ticket_string[sizeof(krb_ticket_string)-1] = '\0';
}

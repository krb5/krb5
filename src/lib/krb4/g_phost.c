/*
 * lib/krb4/g_phost.c
 *
 * Copyright 1988, 2001 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "krb.h"

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "port-sockets.h"

/*
 * This routine takes an alias for a host name and returns the first
 * field, lower case, of its domain name.  For example, if "menel" is
 * an alias for host officially named "menelaus" (in /etc/hosts), for
 * the host whose official name is "MENELAUS.MIT.EDU", the name "menelaus"
 * is returned.
 *
 * This is done for historical Athena reasons: the Kerberos name of
 * rcmd servers (rlogin, rsh, rcp) is of the form "rcmd.host@realm"
 * where "host"is the lowercase for of the host name ("menelaus").
 * This should go away: the instance should be the domain name
 * (MENELAUS.MIT.EDU).  But for now we need this routine...
 *
 * A pointer to the name is returned, if found, otherwise a pointer
 * to the original "alias" argument is returned.
 */

char * KRB5_CALLCONV
krb_get_phost(alias)
    char *alias;
{
    struct hostent *h;
    char *p;
    unsigned char *ucp;
    static char hostname_mem[MAXHOSTNAMELEN];
#ifdef DO_REVERSE_RESOLVE
    char *rev_addr; int rev_type, rev_len;
#endif

    if ((h=gethostbyname(alias)) != (struct hostent *)NULL ) {
#ifdef DO_REVERSE_RESOLVE
	if (! h->h_addr_list ||! h->h_addr_list[0]) {
		return(0);
	}
	rev_type = h->h_addrtype;
	rev_len = h->h_length;
	rev_addr = malloc(rev_len);
	_fmemcpy(rev_addr, h->h_addr_list[0], rev_len);
	h = gethostbyaddr(rev_addr, rev_len, rev_type);
	free(rev_addr);
	if (h == 0) {
		return (0);
	}
#endif
	/* We don't want to return a *, so we copy to a safe location. */
	strncpy (hostname_mem, h->h_name, sizeof (hostname_mem));
	/* Bail out if h_name is too long. */
	if (hostname_mem[MAXHOSTNAMELEN-1] != '\0')
	    return NULL;
	p = strchr( hostname_mem, '.' );
        if (p)
            *p = 0;
        ucp = (unsigned char *)hostname_mem;
        do {
            if (isupper(*ucp)) *ucp=tolower(*ucp);
        } while (*ucp++);
    }
    return(hostname_mem);
}

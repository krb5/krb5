/*
 * g_phost.c
 *
 * Copyright 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

#include "mit-copyright.h"
#define	DEFINE_SOCKADDR		/* For struct hostent, <netdb.h>, etc */
#include "krb.h"

#include <stdio.h>
#include <ctype.h>
#include <string.h>

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

KRB5_DLLIMP char FAR * KRB5_CALLCONV
krb_get_phost(alias)
    char FAR *alias;
{
    struct hostent FAR *h;
    char *p;
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
	/* We don't want to return a FAR *, so we copy to a safe location. */
	strncpy (hostname_mem, h->h_name, sizeof (hostname_mem));
	hostname_mem[MAXHOSTNAMELEN-1]='\0';
	p = strchr( hostname_mem, '.' );
        if (p)
            *p = 0;
        p = hostname_mem;
        do {
            if (isupper(*p)) *p=tolower(*p);
        } while (*p++);
    }
    return(hostname_mem);
}

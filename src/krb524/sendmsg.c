/*
 * Copyright 1990,1991,1997 by the Massachusetts Institute of Technology.
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
 *
 * Send a packet to a service and await a reply, using an exponential
 * backoff retry algorithm.  This is based on krb5_sendto_kdc.
 */

/* Grab socket stuff.  This might want to go away later. */
#define NEED_SOCKETS
#define NEED_LOWLEVEL_IO
#include "fake-addrinfo.h" /* for custom addrinfo if needed */
#include "k5-int.h"

#ifndef _WIN32
#include <unistd.h>
#include <sys/time.h>
#endif

#include <stdlib.h>
#include <string.h>

#if TARGET_OS_MAC
#include <Kerberos/krb.h>
#include <Kerberos/krb524.h>
#else
#include <krb.h>
#include "krb524.h"
#endif

/*
 * krb524_sendto_kdc:
 *
 * A slightly modified version of krb5_sendto_kdc.
 *
 * send the formatted request 'message' to a KDC for realm 'realm' and
 * return the response (if any) in 'reply'.
 *
 * If the message is sent and a response is received, 0 is returned,
 * otherwise an error code is returned.
 *
 * The storage for 'reply' is allocated and should be freed by the caller
 * when finished.
 */

krb5_error_code
krb524_sendto_kdc (context, message, realm, reply)
    krb5_context context;
    const krb5_data * message;
    const krb5_data * realm;
    krb5_data * reply;
{
    int i;
    struct addrlist al = ADDRLIST_INIT;
    struct servent *serv;
    krb5_error_code retval;
    krb5int_access internals;
    int port;

    retval = krb5int_accessor(&internals, KRB5INT_ACCESS_VERSION);
    if (retval)
	return retval;
    /*
     * find KDC location(s) for realm
     */

    serv = getservbyname(KRB524_SERVICE, "udp");
    port = serv ? serv->s_port : htons (KRB524_PORT);

    retval = internals.krb5_locate_server(context, realm, &al, 0,
					  "krb524_server", "_krb524",
					  SOCK_DGRAM, port, 0);
    if (retval == KRB5_REALM_CANT_RESOLVE || retval == KRB5_REALM_UNKNOWN) {
	/* Fallback heuristic: Assume krb524 port on every KDC might
	   work.  */
	retval = internals.krb5_locate_kdc(context, realm, &al, 0, SOCK_DGRAM);
	/*
	 * Bash the ports numbers.
	 */
	if (retval == 0)
	    for (i = 0; i < al.naddrs; i++) {
		al.addrs[i]->ai_socktype = SOCK_DGRAM;
		if (al.addrs[i]->ai_family == AF_INET)
		    sa2sin (al.addrs[i]->ai_addr)->sin_port = port;
	    }
    }
    if (retval)
	return retval;
    if (al.naddrs == 0)
	return KRB5_REALM_UNKNOWN;

    retval = internals.sendto_udp (context, message, &al, reply);
    internals.free_addrlist (&al);
    return retval;
}

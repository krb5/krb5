/*
 * lib/krb5/os/genaddrs.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
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
 * Take an IP addr & port and generate a full IP address.
 */

#define NEED_SOCKETS
#include "k5-int.h"
#include "os-proto.h"

#ifndef _WINSOCKAPI_
#include <netinet/in.h>
#endif

krb5_error_code INTERFACE
krb5_auth_con_genaddrs(context, auth_context, fd, flags)
    krb5_context 	  context;
    krb5_auth_context 	* auth_context;
    int			  fd, flags;
{
    krb5_error_code 	  retval;
    krb5_address	  * laddr;
    krb5_address	  * raddr;

#ifdef KRB5_USE_INET
    struct sockaddr_in saddr;
    krb5_address lcaddr;
    krb5_address rcaddr;
    int ssize;

    ssize = sizeof(struct sockaddr);
    if ((flags & KRB5_AUTH_CONTEXT_GENERATE_LOCAL_FULL_ADDR) ||
	(flags & KRB5_AUTH_CONTEXT_GENERATE_LOCAL_ADDR)) {
    	if (retval = getsockname(fd, &saddr, &ssize)) 
	    return retval;

    	if (flags & KRB5_AUTH_CONTEXT_GENERATE_LOCAL_FULL_ADDR) {
	    if (retval = krb5_make_fulladdr(context, &saddr, &lcaddr))
		return retval;
    	} else {
    	    lcaddr.contents = (krb5_octet *)&saddr.sin_addr;
    	    lcaddr.length = sizeof(saddr.sin_addr);
    	    lcaddr.addrtype = ADDRTYPE_INET;
	}
	laddr = &lcaddr;
    } else {
	laddr = NULL;
    }

    if ((flags & KRB5_AUTH_CONTEXT_GENERATE_REMOTE_FULL_ADDR) ||
	(flags & KRB5_AUTH_CONTEXT_GENERATE_REMOTE_ADDR)) {
        if (retval = getpeername(fd, &saddr, &ssize))
	    return retval;

    	if (flags & KRB5_AUTH_CONTEXT_GENERATE_REMOTE_FULL_ADDR) {
	    if (retval = krb5_make_fulladdr(context, &saddr, &rcaddr)) {
		if (flags & KRB5_AUTH_CONTEXT_GENERATE_LOCAL_FULL_ADDR) 
		    krb5_xfree(laddr->contents);
		return retval;
	    }
    	} else {
    	    rcaddr.contents = (krb5_octet *)&saddr.sin_addr;
    	    rcaddr.length = sizeof(saddr.sin_addr);
    	    rcaddr.addrtype = ADDRTYPE_INET;
	}
	raddr = &rcaddr;
    } else {
	raddr = NULL;
    }

    return (krb5_auth_con_setaddrs(context, auth_context, laddr, raddr));
#else
    return KRB5_PROG_ATYPE_NOSUPP;
#endif
}

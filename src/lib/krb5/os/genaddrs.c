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

#if !defined(_WINSOCKAPI_) && !defined(HAVE_MACSOCK_H)
#include <netinet/in.h>
#endif

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_auth_con_genaddrs(context, auth_context, infd, flags)
    krb5_context 	context;
    krb5_auth_context 	auth_context;
    int		  	infd;
    int			flags;
{
    krb5_error_code 	  retval;
    krb5_address	* laddr;
    krb5_address	* lport;
    krb5_address	* raddr;
    krb5_address	* rport;
    SOCKET		fd = (SOCKET) infd;

#ifdef KRB5_USE_INET
    struct sockaddr_in lsaddr, rsaddr;
    krb5_address lcaddr, rcaddr;
    krb5_address lcport, rcport;
    int ssize;

    ssize = sizeof(struct sockaddr);
    if ((flags & KRB5_AUTH_CONTEXT_GENERATE_LOCAL_FULL_ADDR) ||
	(flags & KRB5_AUTH_CONTEXT_GENERATE_LOCAL_ADDR)) {
    	if ((retval = getsockname(fd, (struct sockaddr *) &lsaddr, &ssize)))
	    return retval;

    	if (flags & KRB5_AUTH_CONTEXT_GENERATE_LOCAL_FULL_ADDR) {
    	    lcport.contents = (krb5_octet *)&lsaddr.sin_port;
    	    lcport.length = sizeof(lsaddr.sin_port);
    	    lcport.addrtype = ADDRTYPE_IPPORT;
	    lport = &lcport;
	} else {
	    lport = NULL;
    	} 
    	lcaddr.contents = (krb5_octet *)&lsaddr.sin_addr;
    	lcaddr.length = sizeof(lsaddr.sin_addr);
    	lcaddr.addrtype = ADDRTYPE_INET;
	laddr = &lcaddr;
    } else {
	laddr = NULL;
	lport = NULL;
    }

    if ((flags & KRB5_AUTH_CONTEXT_GENERATE_REMOTE_FULL_ADDR) ||
	(flags & KRB5_AUTH_CONTEXT_GENERATE_REMOTE_ADDR)) {
        if ((retval = getpeername(fd, (struct sockaddr *) &rsaddr, &ssize)))
	    return retval;

    	if (flags & KRB5_AUTH_CONTEXT_GENERATE_REMOTE_FULL_ADDR) {
    	    rcport.contents = (krb5_octet *)&rsaddr.sin_port;
    	    rcport.length = sizeof(rsaddr.sin_port);
    	    rcport.addrtype = ADDRTYPE_IPPORT;
	    rport = &rcport;
	} else {
	    rport = NULL;
	}
    	rcaddr.contents = (krb5_octet *)&rsaddr.sin_addr;
    	rcaddr.length = sizeof(rsaddr.sin_addr);
    	rcaddr.addrtype = ADDRTYPE_INET;
	raddr = &rcaddr;
    } else {
	raddr = NULL;
	rport = NULL;
    }

    if (!(retval = krb5_auth_con_setaddrs(context, auth_context, laddr, raddr)))
    	return (krb5_auth_con_setports(context, auth_context, lport, rport));
    return retval;
#else
    return KRB5_PROG_ATYPE_NOSUPP;
#endif
}

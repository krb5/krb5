/*
 * lib/krb5/os/gen_rname.c
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
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
 * take a port-style address and unique string, and return
 * a replay cache tag string.
 */

#define NEED_SOCKETS
#include "k5-int.h"
#include "os-proto.h"

krb5_error_code INTERFACE
krb5_gen_replay_name(context, address, uniq, string)
    krb5_context context;
    const krb5_address *address;
    const char *uniq;
    char **string;
{
#ifdef KRB5_USE_INET
    krb5_int16 port;
    krb5_int32 addr;
    register krb5_error_code retval;
    register char *tmp, *tmp2;
    struct in_addr inaddr;

    if (retval = krb5_unpack_full_ipaddr(context, address, &addr, &port))
	return retval;
    inaddr.s_addr = addr;

    tmp = inet_ntoa(inaddr);
    tmp2 = malloc(strlen(uniq)+strlen(tmp)+1+1+5); /* 1 for NUL,
						      1 for ,,
						      5 for digits (65535 is max) */
    if (!tmp2)
	return ENOMEM;
    (void) sprintf(tmp2, "%s%s,%u",uniq,tmp,ntohs(port));
    *string = tmp2;
    return 0;
#else
    return KRB5_PROG_ATYPE_NOSUPP;
#endif
}

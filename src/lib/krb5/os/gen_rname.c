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
 * take a port-style address and unique string, and return
 * a replay cache tag string.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_gen_rname_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/osconf.h>

#include <krb5/ext-proto.h>
#include <krb5/libos-proto.h>
#include "os-proto.h"
#ifdef KRB5_USE_INET
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

krb5_error_code
krb5_gen_replay_name(address, uniq, string)
krb5_address *address;
const char *uniq;
char **string;
{
#ifdef KRB5_USE_INET
    krb5_int16 port;
    krb5_int32 addr;
    register krb5_error_code retval;
    register char *tmp, *tmp2;
    struct in_addr inaddr;

    if (retval = krb5_unpack_full_ipaddr(address, &addr, &port))
	return retval;
    inaddr.s_addr = addr;

    tmp = inet_ntoa(inaddr);
    tmp2 = malloc(strlen(uniq)+strlen(tmp)+1+1+5); /* 1 for NUL,
						      1 for /,
						      5 for digits (65535 is max) */
    if (!tmp2)
	return ENOMEM;
    (void) sprintf(tmp2, "%s%s/%u",uniq,tmp,ntohs(port));
    *string = tmp2;
    return 0;
#else
    return KRB5_PROG_ATYPE_NOSUPP;
#endif
}

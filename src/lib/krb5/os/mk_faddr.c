/*
 * lib/krb5/os/full_ipadr.c
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

#ifdef KRB5_USE_INET

#include "os-proto.h"
#ifndef _WINSOCKAPI_
#include <netinet/in.h>
#endif

krb5_error_code INTERFACE
krb5_make_fulladdr(context, saddr, kaddr)
    krb5_context 	  context;
    struct sockaddr_in 	* saddr;
    krb5_address	* kaddr;
{
    krb5_int32 smushaddr = (krb5_int32)saddr->sin_addr.s_addr;  /* net order */
    krb5_int16 smushport = (krb5_int16)saddr->sin_port; 	/* ditto */
    register krb5_octet * marshal;
    krb5_int32 tmp32;
    krb5_int16 tmp16;

    kaddr->addrtype = ADDRTYPE_ADDRPORT;
    kaddr->length = sizeof(saddr->sin_addr) + sizeof(saddr->sin_port) +
		    (4 * sizeof(krb5_int32));

    if (!(kaddr->contents = (krb5_octet *)malloc(kaddr->length)))
	return ENOMEM;

    marshal = kaddr->contents;

    tmp16 = ADDRTYPE_INET;
    *marshal++ = 0x00;
    *marshal++ = 0x00;
    *marshal++ = tmp16 & 0xff;
    *marshal++ = (tmp16 >> 8) & 0xff;

    tmp32 = sizeof(smushaddr);
    *marshal++ = tmp32 & 0xff;
    *marshal++ = (tmp32 >> 8) & 0xff;
    *marshal++ = (tmp32 >> 16) & 0xff;
    *marshal++ = (tmp32 >> 24) & 0xff;

    (void) memcpy((char *)marshal, (char *)&smushaddr, sizeof(smushaddr));
    marshal += sizeof(smushaddr);

    tmp16 = ADDRTYPE_IPPORT;
    *marshal++ = 0x00;
    *marshal++ = 0x00;
    *marshal++ = tmp16 & 0xff;
    *marshal++ = (tmp16 >> 8) & 0xff;

    tmp32 = sizeof(smushport);
    *marshal++ = tmp32 & 0xff;
    *marshal++ = (tmp32 >> 8) & 0xff;
    *marshal++ = (tmp32 >> 16) & 0xff;
    *marshal++ = (tmp32 >> 24) & 0xff;

    (void) memcpy((char *)marshal, (char *)&smushport, sizeof(smushport));
    marshal += sizeof(smushport);

    return 0;
}
#endif

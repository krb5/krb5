/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1989 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * hostaddr definitions for Kerberos version 5.
 */

#include <krb5/copyright.h>

#ifndef __KRB5_HOSTADDR__
#define __KRB5_HOSTADDR__

/* structure for address */
typedef struct _krb5_address {
    krb5_addrtype addrtype;
    int length;
    krb5_octet contents[1];		/* actually can be more, depending
					   on length */
} krb5_address;

/* per Kerberos v5 protocol spec */
#define	ADDRTYPE_INET	0x0002
#define	ADDRTYPE_CHAOS	0x0005
#define	ADDRTYPE_XNS	0x0006
#define	ADDRTYPE_ISO	0x0007
#define ADDRTYPE_DDP	0x0010

/* macros to determine if a type is a local type */
#define ADDRTYPE_IS_LOCAL(addrtype) (addrtype & 0x8000)

/* implementation-specific stuff: */
typedef struct _krb5_fulladdr {
    krb5_address *address;
    unsigned long port;			/* port, for some address types.
					   large enough for most protos? */
} krb5_fulladdr;

#endif /* __KRB5_HOSTADDR__ */



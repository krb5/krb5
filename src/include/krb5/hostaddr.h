/*
 * include/krb5/hostaddr.h
 *
 * Copyright 1989,1991 by the Massachusetts Institute of Technology.
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
 * hostaddr definitions for Kerberos version 5.
 */

#ifndef KRB5_HOSTADDR__
#define KRB5_HOSTADDR__

/* structure for address */
typedef struct _krb5_address {
    krb5_magic magic;
    krb5_addrtype addrtype;
    int length;
    krb5_octet FAR *contents;
} krb5_address;

/* per Kerberos v5 protocol spec */
#define	ADDRTYPE_INET	0x0002
#define	ADDRTYPE_CHAOS	0x0005
#define	ADDRTYPE_XNS	0x0006
#define	ADDRTYPE_ISO	0x0007
#define ADDRTYPE_DDP	0x0010
/* not yet in the spec... */
#define ADDRTYPE_ADDRPORT	0x0100
#define ADDRTYPE_IPPORT		0x0101

/* macros to determine if a type is a local type */
#define ADDRTYPE_IS_LOCAL(addrtype) (addrtype & 0x8000)

/* implementation-specific stuff: */
typedef struct _krb5_fulladdr {
    krb5_address FAR *address;
    unsigned long port;			/* port, for some address types.
					   large enough for most protos? */
} krb5_fulladdr;

#endif /* KRB5_HOSTADDR__ */



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
 * Take an ADDRPORT address and split into IP addr & port.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_port2ip_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/osconf.h>

#ifdef KRB5_USE_INET

#include <krb5/ext-proto.h>
#include <krb5/libos-proto.h>
#include "os-proto.h"
#include <netinet/in.h>

krb5_error_code
krb5_unpack_full_ipaddr(inaddr, adr, port)
const krb5_address *inaddr;
krb5_int32 *adr;
krb5_int16 *port;
{
    unsigned long smushaddr;
    unsigned short smushport;
    register krb5_octet *marshal;
    krb5_addrtype temptype;
    krb5_int32 templength;

    if (inaddr->addrtype != ADDRTYPE_ADDRPORT)
	return KRB5_PROG_ATYPE_NOSUPP;

    if (inaddr->length != sizeof(smushaddr)+ sizeof(smushport) +
	2*sizeof(temptype) + 2*sizeof(templength))
	return KRB5_PROG_ATYPE_NOSUPP;

    marshal = inaddr->contents;

    (void) memcpy((char *)&temptype, (char *)marshal, sizeof(temptype));
    marshal += sizeof(temptype);
    if (temptype != htons(ADDRTYPE_INET))
	return KRB5_PROG_ATYPE_NOSUPP;

    (void) memcpy((char *)&templength, (char *)marshal, sizeof(templength));
    marshal += sizeof(templength);
    if (templength != htonl(sizeof(smushaddr)))
	return KRB5_PROG_ATYPE_NOSUPP;

    (void) memcpy((char *)&smushaddr, (char *)marshal, sizeof(smushaddr));
    /* leave in net order */
    marshal += sizeof(smushaddr);

    (void) memcpy((char *)&temptype, (char *)marshal, sizeof(temptype));
    marshal += sizeof(temptype);
    if (temptype != htons(ADDRTYPE_IPPORT))
	return KRB5_PROG_ATYPE_NOSUPP;

    (void) memcpy((char *)&templength, (char *)marshal, sizeof(templength));
    marshal += sizeof(templength);
    if (templength != htonl(sizeof(smushport)))
	return KRB5_PROG_ATYPE_NOSUPP;

    (void) memcpy((char *)&smushport, (char *)marshal, sizeof(smushport));
    /* leave in net order */

    *adr = (krb5_int32) smushaddr;
    *port = (krb5_int16) smushport;
    return 0;
}
#endif

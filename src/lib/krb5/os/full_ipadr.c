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
 * Take an IP addr & port and generate a full IP address.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_full_ipadr_c[] =
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
krb5_make_full_ipaddr(DECLARG(krb5_int32, adr),
		      DECLARG(krb5_int16, port),
		      DECLARG(krb5_address **,outaddr))
OLDDECLARG(krb5_int32, adr)
OLDDECLARG(krb5_int16, port)
OLDDECLARG(krb5_address **,outaddr)
{
    unsigned long smushaddr = (unsigned long) adr; /* already in net order */
    unsigned short smushport = (unsigned short) port; /* ditto */
    register krb5_address *retaddr;
    register krb5_octet *marshal;
    krb5_addrtype temptype;
    krb5_int32 templength;

    if (!(retaddr = (krb5_address *)malloc(sizeof(*retaddr)))) {
	return ENOMEM;
    }
    retaddr->addrtype = ADDRTYPE_ADDRPORT;
    retaddr->length = sizeof(smushaddr)+ sizeof(smushport) +
	2*sizeof(temptype) + 2*sizeof(templength);

    if (!(retaddr->contents = (krb5_octet *)malloc(retaddr->length))) {
	xfree(retaddr);
	return ENOMEM;
    }
    marshal = retaddr->contents;

    temptype = htons(ADDRTYPE_INET);
    (void) memcpy((char *)marshal, (char *)&temptype, sizeof(temptype));
    marshal += sizeof(temptype);

    templength = htonl(sizeof(smushaddr));
    (void) memcpy((char *)marshal, (char *)&templength, sizeof(templength));
    marshal += sizeof(templength);

    (void) memcpy((char *)marshal, (char *)&smushaddr, sizeof(smushaddr));
    marshal += sizeof(smushaddr);

    temptype = htons(ADDRTYPE_IPPORT);
    (void) memcpy((char *)marshal, (char *)&temptype, sizeof(temptype));
    marshal += sizeof(temptype);

    templength = htonl(sizeof(smushport));
    (void) memcpy((char *)marshal, (char *)&templength, sizeof(templength));
    marshal += sizeof(templength);

    (void) memcpy((char *)marshal, (char *)&smushport, sizeof(smushport));
    marshal += sizeof(smushport);

    *outaddr = retaddr;
    return 0;
}
#endif

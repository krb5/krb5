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
static char rcsid_gen_port_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/osconf.h>
#include <krb5/ext-proto.h>
#include <krb5/libos-proto.h>
#include "os-proto.h"

krb5_error_code
krb5_gen_portaddr(addr, ptr, outaddr)
const krb5_address *addr;
krb5_const_pointer ptr;
krb5_address **outaddr;
{
#ifdef KRB5_USE_INET
    krb5_int32 adr;
    krb5_int16 port;

    if (addr->addrtype != ADDRTYPE_INET)
	return KRB5_PROG_ATYPE_NOSUPP;
    port = *(krb5_int16 *)ptr;
    
    memcpy((char *)&adr, (char *)addr->contents, sizeof(adr));
    return krb5_make_full_ipaddr(adr, port, outaddr);
#else
    return KRB5_PROG_ATYPE_NOSUPP;
#endif
}

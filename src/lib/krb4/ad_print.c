/*
 * ad_print.c
 *
 * Copyright 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * Miscellaneous debug printing utilities
 */

#include "mit-copyright.h"
#define	DEFINE_SOCKADDR		/* Request definitions for sockets */
#include "krb.h"
#include "des.h"
#include <stdio.h>

#ifndef _WINDOWS

/*
 * Print some of the contents of the given authenticator structure
 * (AUTH_DAT defined in "krb.h").  Fields printed are:
 *
 * pname, pinst, prealm, netaddr, flags, cksum, timestamp, session
 */

void
ad_print(x)
    AUTH_DAT *x;
{
    struct in_addr ina;
    ina.s_addr = x->address;
  
    printf("\n%s %s %s ", x->pname, x->pinst, x->prealm);
    far_fputs (inet_ntoa(ina), stdout);
    printf(" flags %u cksum 0x%lX\n\ttkt_tm 0x%lX sess_key",
           x->k_flags, x->checksum, x->time_sec);
    printf("[8] =");
#ifdef NOENCRYPTION
    placebo_cblock_print(x->session);
#else /* Do Encryption */
    des_cblock_print_file(x->session,stdout);
#endif /* NOENCRYPTION */
    /* skip reply for now */
}

#ifdef NOENCRYPTION
/*
 * Print in hex the 8 bytes of the given session key.
 *
 * Printed format is:  " 0x { x, x, x, x, x, x, x, x }"
 */

placebo_cblock_print(x)
    des_cblock x;
{
    unsigned char *y = (unsigned char *) x;
    register int i = 0;

    printf(" 0x { ");

    while (i++ <8) {
        printf("%x",*y++);
        if (i<8) printf(", ");
    }
    printf(" }");
}
#endif /* NOENCRYPTION */

#endif

/*
 * lib/krb4/ad_print.c
 *
 * Copyright 1988 by the Massachusetts Institute of Technology.  All
 * Rights Reserved.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "krb.h"
#include "des.h"
#include "krb4int.h"
#include <stdio.h>
#include "port-sockets.h"

#ifndef _WIN32

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
            x->k_flags, (long) x->checksum, (long) x->time_sec);
    printf("[8] =");
#ifdef NOENCRYPTION
    placebo_cblock_print(x->session);
#else /* Do Encryption */
    des_cblock_print_file(&x->session,stdout);
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

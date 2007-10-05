/*
 * pkt_clen.c
 *
 * Copyright 1985, 1986, 1987, 1988 by the Massachusetts Institute
 * of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

#include "mit-copyright.h"
#include <string.h>
#include "krb.h"
#include "prot.h"

extern int krb_debug;
int swap_bytes=0;

/*
 * Given a pointer to an AUTH_MSG_KDC_REPLY packet, return the length of
 * its ciphertext portion.  The external variable "swap_bytes" is assumed
 * to have been set to indicate whether or not the packet is in local
 * byte order.  pkt_clen() takes this into account when reading the
 * ciphertext length out of the packet.
 */

int
pkt_clen(pkt)
    KTEXT pkt;
{
    static unsigned short temp;
    int clen = 0;

    /* Start of ticket list */
    unsigned char *ptr = pkt_a_realm(pkt) + 10
	+ strlen((char *)pkt_a_realm(pkt));

    /* Finally the length */
    memcpy((char *)&temp, (char *)(++ptr), 2); /* alignment */
    if (swap_bytes)
	temp = krb4_swab16(temp);    

    clen = (int) temp;

    DEB (("Clen is %d\n",clen));
    return(clen);
}

/*
 * lib/krb4/mk_err.c
 *
 * Copyright 1985, 1986, 1987, 1988, 2000 by the Massachusetts
 * Institute of Technology.  All Rights Reserved.
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
#include "prot.h"
#include <string.h>

/*
 * This routine creates a general purpose error reply message.  It
 * doesn't use KTEXT because application protocol may have long
 * messages, and may want this part of buffer contiguous to other
 * stuff.
 *
 * The error reply is built in "p", using the error code "e" and
 * error text "e_string" given.  The length of the error reply is
 * returned.
 *
 * The error reply is in the following format:
 *
 * unsigned char	KRB_PROT_VERSION	protocol version no.
 * unsigned char	AUTH_MSG_APPL_ERR	message type
 * (least significant
 * bit of above)	HOST_BYTE_ORDER		local byte order
 * 4 bytes		e			given error code
 * string		e_string		given error text
 */

long KRB5_CALLCONV
krb_mk_err(p, e, e_string)
    u_char *p;		/* Where to build error packet */
    KRB4_32 e;			/* Error code */
    char *e_string;		/* Text of error */
{
    u_char      *start;
    size_t	e_len;

    e_len = strlen(e_string) + 1;

    /* Just return the buffer length if p is NULL, because writing to the
     * buffer would be a bad idea.  Note that this feature is a change from
     * previous versions, and can therefore only be used safely in this
     * source tree, where we know this function supports it. */
    if (p == NULL) {
        return 1 + 1 + 4 + e_len;
    }

    start = p;

    /* Create fixed part of packet */
    *p++ = KRB_PROT_VERSION;
    *p++ = AUTH_MSG_APPL_ERR;

    /* Add the basic info */
    KRB4_PUT32BE(p, e);
    memcpy(p, e_string, e_len); /* err text */
    p += e_len;

    /* And return the length */
    return p - start;
}

/*
 * mk_err.c
 *
 * Copyright 1985, 1986, 1987, 1988 by the Massachusetts Institute
 * of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

#include "mit-copyright.h"
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

KRB5_DLLIMP long KRB5_CALLCONV
krb_mk_err(p,e,e_string)
    u_char FAR *p;		/* Where to build error packet */
    KRB4_32 e;			/* Error code */
    char FAR *e_string;		/* Text of error */
{
    u_char      *start;

    /* Just return the buffer length if p is NULL, because writing to the
     * buffer would be a bad idea.  Note that this feature is a change from
     * previous versions, and can therefore only be used safely in this
     * source tree, where we know this function supports it. */
    if(p == NULL) {
        return 2 + sizeof(e) + strlen(e_string);
    }

    start = p;

    /* Create fixed part of packet */
    *p++ = (unsigned char) KRB_PROT_VERSION;
    *p = (unsigned char) AUTH_MSG_APPL_ERR;
    *p++ |= HOST_BYTE_ORDER;

    /* Add the basic info */
    memcpy((char *)p, (char *)&e, 4); /* err code */
    p += sizeof(e);
    (void) strcpy((char *)p,e_string); /* err text */
    p += strlen(e_string);

    /* And return the length */
    return p-start;
}

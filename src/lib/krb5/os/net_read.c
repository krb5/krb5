/*
 * $Source$
 * $Author$
 *
 * Copyright 1987, 1988, 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_net_read_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

/*
 * krb5_net_read() reads from the file descriptor "fd" to the buffer
 * "buf", until either 1) "len" bytes have been read or 2) cannot
 * read anymore from "fd".  It returns the number of bytes read
 * or a read() error.  (The calling interface is identical to
 * read(2).)
 *
 * XXX must not use non-blocking I/O
 */

int
krb5_net_read(fd, buf, len)
int fd;
register char *buf;
register int len;
{
    int cc, len2 = 0;

    do {
	cc = read(fd, buf, len);
	if (cc < 0)
	    return(cc);		 /* errno is already set */
	else if (cc == 0) {
	    return(len2);
	} else {
	    buf += cc;
	    len2 += cc;
	    len -= cc;
	}
    } while (len > 0);
    return(len2);
}

/*
 * $Source$
 * $Author$
 *
 * Copyright 1987, 1988, 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_net_write_c[] =
"$Header$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/ext-proto.h>

/*
 * krb5_net_write() writes "len" bytes from "buf" to the file
 * descriptor "fd".  It returns the number of bytes written or
 * a write() error.  (The calling interface is identical to
 * write(2).)
 *
 * XXX must not use non-blocking I/O
 */

int
krb5_net_write(fd, buf, len)
int fd;
register char *buf;
int len;
{
    int cc;
    register int wrlen = len;
    do {
	cc = write(fd, buf, wrlen);
	if (cc < 0)
	    return(cc);
	else {
	    buf += cc;
	    wrlen -= cc;
	}
    } while (wrlen > 0);
    return(len);
}

/*
 * netwrite.c
 *
 * Copyright 1987, 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

#include "mit-copyright.h"
#include <errno.h>
#define	DEFINE_SOCKADDR
#include "krb.h"
#ifndef _WINDOWS
extern int errno;
#endif

/*
 * krb_net_write() writes "len" bytes from "buf" to the file
 * descriptor "fd".  It returns the number of bytes written or
 * a write() error.  (The calling interface is identical to
 * write(2).)
 *
 * XXX must not use non-blocking I/O
 */
int
krb_net_write(fd, buf, len)
int fd;
register char *buf;
int len;
{
    int cc;
    register int wrlen = len;
    do {
	cc = SOCKET_WRITE(fd, buf, wrlen);
	if (cc < 0)
	  {
	    if (SOCKET_ERRNO == SOCKET_EINTR)
	      continue;
	    return(cc);
	  }
	else {
	    buf += cc;
	    wrlen -= cc;
	}
    } while (wrlen > 0);
    return(len);
}

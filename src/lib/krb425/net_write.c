/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb_net_write for krb425
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_net_write_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include "krb425.h"

int
krb_net_write(fd,buf,len)
int fd;
char *buf;
int len;
{
    int cc;
    extern int write();
    register int wrlen = len;
#ifdef	EBUG
	EPRINT "Write data: ``");
    for (cc = 0; cc < len && cc < 24; ++cc) {
	fprintf(stderr, "%c", (buf[cc] < ' ' || buf[cc] > '~') ? '.' : buf[cc]);
    }
    if (cc < len) {
        fprintf(stderr, "''(%d)\n", len);
    } else {
        fprintf(stderr, "''\n");
    }
#endif
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

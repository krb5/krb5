/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb_net_read for krb425
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_net_read_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include "krb425.h"

int
krb_net_read(fd,buf,len)
int fd;
char *buf;
int len;
{
    extern int read();
    int cc, len2 = 0;
#ifdef	EBUG
    char *obuf = buf;
#endif

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
#ifdef  EBUG
	buf = obuf;
        EPRINT "Read data: ``");
    for (cc = 0; cc < len2 && cc < 24; ++cc) {
        fprintf(stderr, "%c", (buf[cc] < ' ' || buf[cc] > '~') ? '.' : buf[cc]);
    }
    if (cc < len2) {
        fprintf(stderr, "''(%d)\n", len2);
    } else {
        fprintf(stderr, "''\n");
    }
#endif
    return(len2);
}

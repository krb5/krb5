/*
 * lib/krb425/net_read.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * krb_net_read for krb425
 */


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

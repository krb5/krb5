/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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
 * krb_net_write for krb425
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_net_write_c[] =
"$Id$";
#endif	/* !lint & !SABER */

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

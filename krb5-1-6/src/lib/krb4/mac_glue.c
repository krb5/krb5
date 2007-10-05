/*
 * mac_glue.c
 *
 * Copyright 1989 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * Macintosh ooperating system interface for Kerberos.
 */

#include "mit-copyright.h"
#include "krb.h"

/* Mac Cincludes */
#include <string.h>
#include <stddef.h>

/* FIXME!  swab should be swapping, but for initial test, don't bother.  */

void swab(char *from, char *to, int nbytes) {}

mymemset( void *s, register int c, register size_t n )
{
	// written because memset doesn't work in think C (ARGGGG!!!!!!)
	register char *j = s;
	while( n-- )
		*j++ = c;
}

int INTERFACE
krb_start_session (x)
	char *x;
{
	return KSUCCESS;
}

int INTERFACE
krb_end_session (x)
	char *x;
{
	return KSUCCESS;
}

/* FIXME:  These stubs should go away.  */
int read() {return 0;}
int write () {return 0;}
int krb_ignore_ip_address = 0;

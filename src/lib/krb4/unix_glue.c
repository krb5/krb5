/*
 * unix_glue.c
 * 
 * Glue code for pasting Kerberos into the Unix environment.
 *
 * Originally written by John Gilmore, Cygnus Support, May '94.
 * Public Domain.
 */

#include "krb.h"
#include <sys/time.h>

/* Start and end Kerberos library access.  On Unix, this is a No-op.  */
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

char FAR * INTERFACE
krb_get_default_user ()
{
	return 0;		/* FIXME */
}

int INTERFACE
krb_set_default_user (x)
	char *x;
{
	return KFAILURE;	/* FIXME */
}

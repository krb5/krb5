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
#include "krb4int.h"

/* Start and end Kerberos library access.  On Unix, this is a No-op.  */
int
krb_start_session (x)
	char *x;
{
	return KSUCCESS;
}

int
krb_end_session (x)
	char *x;
{
	return KSUCCESS;
}

char *
krb_get_default_user ()
{
	return 0;		/* FIXME */
}

int
krb_set_default_user (x)
	char *x;
{
	return KFAILURE;	/* FIXME */
}

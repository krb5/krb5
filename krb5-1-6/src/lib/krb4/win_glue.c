/*
 * win-glue.c
 * 
 * Glue code for pasting Kerberos into the Windows environment.
 *
 * Originally written by John Gilmore, Cygnus Support, May '94.
 * Public Domain.
 */

#include "krb.h"

#include <sys/types.h>
#include <stdio.h>
#include <windows.h>


/*
 * We needed a way to print out what might be FAR pointers on Windows,
 * but might be ordinary pointers on real machines.  Printf modifiers
 * scattered through the code don't cut it,
 * since they might break on real machines.  Microloss
 * didn't provide a function to print a char *, so we wrote one.
 * It gets #define'd to fputs on real machines. 
 */
int
far_fputs(string, stream)
	char *string;
	FILE *stream;
{
	return fprintf(stream, "%Fs", string);
}

int
krb_start_session(x)
     char *x;
{
	return KSUCCESS;
}

int
krb_end_session(x)
     char *x;
{
	return KSUCCESS;
}

void KRB5_CALLCONV
krb_set_tkt_string(val)
char *val;
{
}

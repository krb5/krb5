/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Common data for krb425 library
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_425data_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include "krb425.h"

char 			*_krb425_local_realm = 0;
krb5_ccache 		_krb425_ccache = 0;
int			_krb425_error_init = 0;

#ifdef	EBUG
char *
basename(s)
char *s;
{
	char *r;
	char *rindex();

	if (r = rindex(s, '/'))
		return(r+1);
	return(s);
}
#endif

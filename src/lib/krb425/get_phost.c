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
 * krb_get_phost for krb425
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_get_phost_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include "krb425.h"

char *
krb_get_phost(alias)
char *alias;
{
	struct hostent *h;
	char *phost = alias;

	if ((h = gethostbyname(alias)) != (struct hostent *)0 ) {
		char *p;
#ifdef	OLD_CRUFT
		if (p = index( h->h_name, '.' ))
			*p = 0;
#endif
		p = phost = h->h_name;
		do {
			if (isupper(*p)) *p=tolower(*p);
		} while (*p++);
	}
	return(phost);
}

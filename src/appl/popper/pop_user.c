/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef lint
static char copyright[] = "Copyright (c) 1990 Regents of the University of California.\nAll rights reserved.\n";
/* based on @(#)pop_user.c	2.1  3/18/91 */
#endif

#include <stdio.h>
#include <sys/types.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#else
#include <string.h>
#endif
#include "popper.h"

#ifdef KERBEROS
#ifdef KRB4
#ifdef KRB5
 #error you can only use one of KRB4, KRB5
#endif
#include <krb.h>
extern AUTH_DAT kdata;
#endif /* KRB4 */
#ifdef KRB5
#include "krb5.h"
#include "com_err.h"
extern krb5_principal ext_client;
extern char *client_name;
#endif /* KRB5 */
#endif /* KERBEROS */

/* 
 *  user:   Prompt for the user name at the start of a POP session
 */

int pop_user (p)
POP     *   p;
{
#ifndef KERBEROS
    /*  Save the user name */
    (void)strcpy(p->user, p->pop_parm[1]);

#else /* KERBEROS */

    if(strcmp(p->pop_parm[1], p->user))
      {
#ifdef KRB4
	pop_log(p, POP_WARNING, "%s: auth failed: %s.%s@@%s vs %s",
		p->client, kdata.pname, kdata.pinst, kdata.prealm, 
		p->pop_parm[1]);
#else
	pop_log(p, POP_WARNING, "%s: auth failed: %s vs %s",
		p->client, p->user, p->pop_parm[1]);
#endif
        return(pop_msg(p,POP_FAILURE,
		       "Wrong username supplied (%s vs. %s).\n", p->user,
		       p->pop_parm[1]));
      }

#endif /* KERBEROS */

    /*  Tell the user that the password is required */
    return (pop_msg(p,POP_SUCCESS,"Password required for %s.",p->user));
}

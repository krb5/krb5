/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_free_krbhst() function
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_free_krbhs_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>

#include <krb5/ext-proto.h>

/*
 Frees the storage taken by a host list returned by krb5_get_krbhst.
 */

krb5_error_code
krb5_free_krbhst(hostlist)
char * const *hostlist;
{
    register char * const *cp;

    for (cp = hostlist; *cp; cp++)
	free(*cp);
    xfree(hostlist);
    return 0;
}

/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_free_realm_tree()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_free_rtree_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

void
krb5_free_realm_tree(realms)
const krb5_principal *realms;
{
    register const krb5_principal *nrealms = realms;
    while (*nrealms) {
	krb5_free_principal(*nrealms);
	realms++;
    }
    xfree(realms);
}

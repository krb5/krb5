/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Find default credential cache
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_default_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

static krb5_ccache default_ccache;

krb5_ccache krb5_cc_default()
{
    if (default_ccache == 0)
	krb5_cc_resolve(krb5_cc_default_name(), &default_ccache);

    /* ignore errors; any error will be fatal in future derefs by the
       caller. */

    return default_ccache;
}

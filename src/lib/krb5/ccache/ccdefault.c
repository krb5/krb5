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

krb5_error_code krb5_cc_default(ccache)
krb5_ccache *ccache;
{
    return krb5_cc_resolve(krb5_cc_default_name(), ccache);
}

/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * macros used in Kerberos code.
 */

#include <krb5/copyright.h>

#ifndef __KRB5_MACROS__
#define __KRB5_MACROS__

#define valid_etype(etype)     ((etype <= max_cryptosystem) && (etype > 0) && csarray[etype])

#endif /* __KRB5_MACROS__ */

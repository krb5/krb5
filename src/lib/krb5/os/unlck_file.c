/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * libos: krb5_lock_file routine
 */

#ifndef	lint
static char rcsid_unlock_file_c [] =
"$Id$";
#endif	/* lint */

#include <stdio.h>

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/libos.h>
#include <krb5/libos-proto.h>

krb5_error_code
krb5_unlock_file(filep)
FILE *filep;
{
    return krb5_lock_file(filep, KRB5_LOCKMODE_UNLOCK);
}

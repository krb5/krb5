/*
 * lib/krb5/os/unlck_file.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * libos: krb5_lock_file routine
 */


#include <stdio.h>

#include <krb5/krb5.h>
#include <krb5/libos.h>
#include <krb5/los-proto.h>

krb5_error_code
krb5_unlock_file(context, filep, pathname)
    krb5_context context;
    FILE *filep;
    char *pathname;
{
    return krb5_lock_file(context, filep, pathname, KRB5_LOCKMODE_UNLOCK);
}

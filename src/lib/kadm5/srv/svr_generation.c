/*
 * lib/kadm5/srv/svr_generation.c
 *
 * (C) Copyright 2001 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include        <sys/types.h>
#include        <sys/time.h>
#include        <kadm5/admin.h>
#include        "k5-int.h"
#include        <krb5/kdb.h>
#include        <stdio.h>
#include        <string.h>
#include        "server_internal.h"
#include        <stdarg.h>
#include        <stdlib.h>

kadm5_ret_t
kadm5_get_generation_number(void *server_handle, krb5_int32 *generation)
{
    krb5_principal	princ;
    krb5_db_entry	kdb;
    osa_princ_ent_rec	adb;
    krb5_error_code	ret;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    ret = krb5_db_setup_mkey_name(handle->context, handle->params.mkey_name,
    				  handle->params.realm, NULL, &princ);
    if (ret)
        return KADM5_FAILURE;

    ret = kdb_get_entry(handle, princ, &kdb, &adb);
    if (ret)
        return KADM5_UNK_PRINC;

    ret = krb5_dbe_lookup_generation_number_general(handle->context, &kdb,
    						    generation);
    if (ret)
        return KADM5_FAILURE;

    ret = kdb_free_entry(handle, &kdb, &adb);
    /* if (ret), that sucks, but if we've got the generation number, it
       seems wrong to fail out. */

    krb5_free_principal(handle->context, princ);

    return KADM5_OK;
}


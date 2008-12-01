/*
 * lib/krb4/password_to_key.c
 *
 * Copyright 1999, 2002 by the Massachusetts Institute of Technology.
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
 * password_to_key functions merged from KfM
 */

#include <string.h>
#include <stdlib.h>

#ifdef USE_CCAPI
#include <CredentialsCache.h>
#endif
#include "krb.h"
#include "krb4int.h"

#include "k5-platform.h"

/*
 * passwd_to_key(): given a password, return a DES key.
 * There are extra arguments here which (used to be?)
 * used by srvtab_to_key().
 *
 * If the "passwd" argument is not null, generate a DES
 * key from it, using string_to_key().
 *
 * If the "passwd" argument is null, then on a Unix system we call
 * des_read_password() to prompt for a password and then convert it
 * into a DES key.  But "prompting" the user is harder in a Windows or
 * Macintosh environment, so we rely on our caller to explicitly do
 * that now.
 *
 * In either case, the resulting key is put in the "key" argument,
 * and 0 is returned.
 */


key_proc_type *krb_get_keyprocs (key_proc_type keyproc)
{
    static key_proc_type default_keyprocs[4] = { mit_passwd_to_key, 
                                                 afs_passwd_to_key, 
                                                 krb5_passwd_to_key, 
                                                 NULL };
                                                  
    static key_proc_type user_keyprocs[2] = { NULL, NULL };
    
    /* generate the list of key procs */
    if (keyproc == NULL) {
        return default_keyprocs; /* use the default */
    } else {
        user_keyprocs[0] = keyproc;
        return user_keyprocs;  /* use the caller provided keyprocs */
    }
}

int KRB5_CALLCONV
mit_passwd_to_key(
    char	*user,
    char	*instance,
    char	*realm,
    char	*passwd,
    C_Block	key)
{
#if 0 /* what system? */
#pragma unused(user)
#pragma unused(instance)
#pragma unused(realm)
#endif

    if (passwd) {
        des_string_to_key(passwd, key);
    } else {
#if !(defined(_WIN32) || defined(USE_LOGIN_LIBRARY))
        des_read_password((des_cblock *)key, "Password", 0);
#else
        return (-1);
#endif
    }
    return (0);
}

/* So we can use a v4 kinit against a v5 kdc with no krb4 salted key */
int KRB5_CALLCONV
krb5_passwd_to_key(
    char	*user,
    char	*instance,
    char	*realm,
    char	*passwd,
    C_Block	key)
{
    char	*p;

    if (user && instance && realm && passwd) {
	if (strlen(realm) + strlen(user) + strlen(instance) > MAX_K_NAME_SZ)
	    /* XXX Is this right?  The old code returned 0, which is
	       also what it returns after sucessfully generating a
	       key.  The other error path returns -1.  */
	    return 0;
	if (asprintf(&p, "%s%s%s%s", passwd, realm, user, instance) >= 0) {
            des_string_to_key (p, key);
            free (p);
            return 0;
        }
    }
    return -1;
}

int KRB5_CALLCONV
afs_passwd_to_key(
    char	*user,
    char	*instance,
    char	*realm,
    char	*passwd,
    C_Block	key)
{
#if 0 /* what system? */
#pragma unused(user)
#pragma unused(instance)
#endif

    if (passwd) {
        afs_string_to_key(passwd, realm, key);
    } else {
#if !(defined(_WIN32) || defined(USE_LOGIN_LIBRARY))
        des_read_password((des_cblock *)key, "Password", 0);
#else
        return (-1);
#endif
    }
    return (0);
}

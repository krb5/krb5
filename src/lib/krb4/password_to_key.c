/*
 * password_to_key.c -- password_to_key functions merged from KfM
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
 */

#include <string.h>
#include <stdlib.h>

#if TARGET_OS_MAC
#include <Kerberos/CredentialsCache.h>
#endif
#include "krb.h"
#include "krb4int.h"

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

#if TARGET_OS_MAC
/*ARGSUSED */
int 
krb_get_keyprocs(KRB_UINT32 stkType,
		 key_proc_array kps, key_proc_type_array sts)
{
    /* generates the list of key procs */
    /* always try them all, but try the specified one first */
    switch (stkType) {
    case cc_v4_stk_afs:
	kps[0] = afs_passwd_to_key;
	sts[0] = cc_v4_stk_afs;

	kps[1] = mit_passwd_to_key;
	sts[1] = cc_v4_stk_des;

	kps[2] = krb5_passwd_to_key;
	sts[2] = cc_v4_stk_krb5;

	kps[3] = NULL;
	break;
    case cc_v4_stk_des:
    case cc_v4_stk_unknown:
    default:
	kps[0] = mit_passwd_to_key;
	sts[0] = cc_v4_stk_des;

	kps[1] = afs_passwd_to_key;
	sts[1] = cc_v4_stk_afs;

	kps[2] = krb5_passwd_to_key;
	sts[2] = cc_v4_stk_krb5;

	kps[3] = NULL;
	break;
    }
    return KSUCCESS;
}
#endif

int
mit_passwd_to_key(char *user, char *instance, char *realm,
		  char *passwd, C_Block key)
{
#pragma unused(user)
#pragma unused(instance)
#pragma unused(realm)

    if (passwd)
        mit_string_to_key(passwd, key);
#if !(defined(_WINDOWS) || defined(macintosh))
    else {
        des_read_password((C_Block *)key, "Password: ", 0);
    }
#endif /* unix */
    return (0);
}

/* So we can use a v4 kinit against a v5 kdc with no krb4 salted key */
int
krb5_passwd_to_key(char *user, char *instance, char *realm,
		   char *passwd, C_Block key)
{
    if (user && instance && realm && passwd) {
        unsigned int len = MAX_K_NAME_SZ + strlen(passwd) + 1;
        char *p = malloc (len);
        if (p != NULL) {
            snprintf (p, len, "%s%s%s%s", passwd, realm, user, instance);
            p[len - 1] = '\0';
            mit_string_to_key (p, key);
            free (p);
            return 0;
        }
    }
    return -1;
}

int
afs_passwd_to_key(char *user, char *instance, char *realm,
		  char *passwd, C_Block key)
{
#pragma unused(user)
#pragma unused(instance)

    if (passwd)
        afs_string_to_key(passwd, realm, key);
#if !(defined(_WINDOWS) || defined(macintosh))
    else {
        des_read_password((C_Block *)key, "Password: ", 0);
    }
#endif /* unix */
    return (0);
}

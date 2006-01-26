/*
 * lib/krb4/g_svc_in_tkt.c
 *
 * Copyright 1987, 1988 by the Massachusetts Institute of Technology.
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
#include "krb.h"
#include "prot.h"
#include "krb4int.h"

/*
 * This file contains two routines: srvtab_to_key(), which gets
 * a server's key from a srvtab file, and krb_get_svc_in_tkt() which
 * gets an initial ticket for a server.
 */

/*
 * srvtab_to_key(): given a "srvtab" file (where the keys for the
 * service on a host are stored), return the private key of the
 * given service (user.instance@realm).
 *
 * srvtab_to_key() passes its arguments on to read_service_key(),
 * plus one additional argument, the key version number.
 * (Currently, the key version number is always 0; this value
 * is treated as a wildcard by read_service_key().)
 *
 * If the "srvtab" argument is null, KEYFILE (defined in "krb.h")
 * is passed in its place.
 *
 * It returns the return value of the read_service_key() call.
 * The service key is placed in "key".
 */

static int srvtab_to_key(user, instance, realm, srvtab, key)
    char *user, *instance, *realm, *srvtab;
    C_Block key;
{
    if (!srvtab)
        srvtab = KEYFILE;

    return(read_service_key(user, instance, realm, 0, srvtab,
                            (char *)key));
}

/*
 * krb_get_svc_in_tkt() passes its arguments on to krb_get_in_tkt(),
 * plus two additional arguments: a pointer to the srvtab_to_key()
 * function to be used to get the key from the key file and a NULL
 * for the decryption procedure indicating that krb_get_in_tkt should 
 * use the default method of decrypting the response from the KDC.
 *
 * It returns the return value of the krb_get_in_tkt() call.
 */

int KRB5_CALLCONV
krb_get_svc_in_tkt(user, instance, realm, service, sinstance, life, srvtab)
    char *user, *instance, *realm, *service, *sinstance;
    int life;
    char *srvtab;
{
    return(krb_get_in_tkt(user, instance, realm, service, sinstance, life,
                          (key_proc_type) srvtab_to_key, NULL, srvtab));
}

/* and we need a preauth version as well. */
static C_Block old_key;
 
static int stub_key(user,instance,realm,passwd,key)
    char *user, *instance, *realm, *passwd;
    C_Block key;
{
   memcpy(key, old_key, sizeof(C_Block));
   return 0;
}

int
krb_get_svc_in_tkt_preauth(user, instance, realm, service, sinstance, life, srvtab)
    char *user, *instance, *realm, *service, *sinstance;
    int life;
    char *srvtab;
{
   char *preauth_p;
   int   preauth_len;
   int   ret_st;
 
   krb_mk_preauth(&preauth_p, &preauth_len,
                  (key_proc_type) srvtab_to_key, user, instance, realm,
		  srvtab, old_key);
   ret_st = krb_get_in_tkt_preauth(user,instance,realm,service,sinstance,life,
				   (key_proc_type) stub_key, NULL, srvtab,
				   preauth_p, preauth_len);
 
   krb_free_preauth(preauth_p, preauth_len);
   return ret_st;
}

/* DEC's dss-kerberos adds krb_svc_init; simple enough */

int
krb_svc_init(user,instance,realm,lifetime,srvtab_file,tkt_file)
    char *user;
    char *instance;
    char *realm;
    int lifetime;
    char *srvtab_file;
    char *tkt_file;
{
    if (tkt_file)
	krb_set_tkt_string(tkt_file);

    return krb_get_svc_in_tkt(user,instance,realm,
			      KRB_TICKET_GRANTING_TICKET,realm,lifetime,srvtab_file);
}


int
krb_svc_init_preauth(user,instance,realm,lifetime,srvtab_file,tkt_file)
    char *user;
    char *instance;
    char *realm;
    int lifetime;
    char *srvtab_file;
    char *tkt_file;
{
    if (tkt_file)
        krb_set_tkt_string(tkt_file);
 
    return krb_get_svc_in_tkt_preauth(user,instance,realm,
                              	      KRB_TICKET_GRANTING_TICKET,realm,lifetime,srvtab_file);
}

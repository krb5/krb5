/*
 * g_svc_in_tkt.c
 *
 * Copyright 1987, 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

#include "mit-copyright.h"
#include "krb.h"
#include "prot.h"
#include <string.h>

#ifndef NULL
#define NULL 0
#endif

extern char *krb__get_srvtabname();

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

KRB5_DLLIMP int KRB5_CALLCONV
krb_get_svc_in_tkt(user, instance, realm, service, sinstance, life, srvtab)
    char FAR *user, FAR *instance, FAR *realm, FAR *service, FAR *sinstance;
    int life;
    char FAR *srvtab;
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
			      "krbtgt",realm,lifetime,srvtab_file);
}


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
                              	      "krbtgt",realm,lifetime,srvtab_file);
}

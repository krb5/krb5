/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_get_in_tkt_with_skey()
 *	
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_in_tkt_skey_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/krb5_err.h>

#include <errno.h>
#include <krb5/ext-proto.h>
#include <krb5/asn1.h>			/* XXX for krb5_free_keyblock! */

struct skey_keyproc_arg {
    krb5_keyblock *key;
    krb5_principal server;		/* it's a pointer, really! */
};

/*
 * Key-generator for in_tkt_skey, below.
 * "keyseed" is actually a krb5_keyblock *, or NULL if we should fetch
 * from system area.
 */
static krb5_error_code
skey_keyproc(DECLARG(const krb5_keytype, type),
	     DECLARG(krb5_keyblock **, key),
	     DECLARG(krb5_pointer, keyseed))
OLDDECLARG(const krb5_keytype, type)
OLDDECLARG(krb5_keyblock **, key)
OLDDECLARG(krb5_pointer, keyseed)
{
    krb5_keyblock *realkey;
    struct skey_keyproc_arg *arg;
    krb5_error_code retval;
    krb5_keytab kt_id;
    krb5_keytab_entry kt_ent;

    arg = (struct skey_keyproc_arg *)keyseed;

    if (!valid_keytype(type))
	return KRB5_PROG_ETYPE_NOSUPP;

    if (arg->server) {
	/* do keytab stuff */
	/* else we need to fetch from system key place */
	if (retval = krb5_kt_default(&kt_id))
	    return retval;
	if (retval = krb5_kt_get_entry(kt_id, arg->server,
				       0, /* don't have vno available */
				       &kt_ent))
	    return retval;
    }
#define cleanup() {if (arg->server) (void) krb5_kt_free_entry(&kt_ent);}

    realkey = (krb5_keyblock *)malloc(sizeof(*realkey));
    if (!realkey) {
	cleanup();
	return ENOMEM;
    }    

    if (arg->key)
	retval = krb5_copy_keyblock(arg->key, realkey);
    else
	retval = krb5_copy_keyblock(&kt_ent.key, realkey);
    if (retval) {
	free((char *)realkey);
	cleanup();
	return retval;
    }
	
    if (realkey->keytype != type) {
	krb5_free_keyblock(realkey);
	cleanup();
	return KRB5_PROG_ETYPE_NOSUPP;
    }	

    *key = realkey;
    cleanup();
    return 0;
}

/*
 Similar to krb5_get_in_tkt_with_password.

 Attempts to get an initial ticket for creds->client to use server
 creds->server, (realm is taken from creds->client), with options
 options, requesting encryption type etype, and using
 creds->times.starttime,  creds->times.endtime,  creds->times.renew_till
 as from, till, and rtime.  creds->times.renew_till is ignored unless
 the RENEWABLE option is requested.

 If addrs is non-NULL, it is used for the addresses requested.  If it is
 null, the system standard addresses are used.

 If keyblock is NULL, an appropriate key for creds->client is retrieved
 from the system key store (e.g. /etc/srvtab).  If keyblock is non-NULL,
 it is used as the decryption key.

 A succesful call will place the ticket in the credentials cache ccache.

 returns system errors, encryption errors

 */
krb5_error_code
krb5_get_in_tkt_with_skey(DECLARG(const krb5_flags, options),
			  DECLARG(krb5_address * const *, addrs),
			  DECLARG(const krb5_enctype, etype),
			  DECLARG(const krb5_keyblock *,key),
			  DECLARG(krb5_ccache, ccache),
			  DECLARG(krb5_creds *,creds))
OLDDECLARG(const krb5_flags, options)
OLDDECLARG(krb5_address * const *, addrs)
OLDDECLARG(const krb5_enctype, etype)
OLDDECLARG(const krb5_keyblock *,key)
OLDDECLARG(krb5_ccache, ccache)
OLDDECLARG(krb5_creds *, creds)
{
    struct skey_keyproc_arg arg;
    krb5_keytype keytype;

    if (key) {
	arg.key = (krb5_keyblock *)key;
	arg.server = 0;
	keytype = key->keytype;
    } else {
	arg.key = 0;
	arg.server = creds->server;
	if (!valid_etype(etype))
	    return(KRB5_PROG_ETYPE_NOSUPP);

	keytype = krb5_csarray[etype]->system->proto_keytype;
    }
    return (krb5_get_in_tkt(options, addrs, etype, keytype, skey_keyproc,
			    (krb5_pointer) &arg,
			    krb5_kdc_rep_decrypt_proc,
			    0,
			    creds,
			    ccache));
}

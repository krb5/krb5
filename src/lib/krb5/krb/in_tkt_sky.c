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
skey_keyproc(DECLARG(krb5_keytype, type),
	     DECLARG(krb5_keyblock **, key),
	     DECLARG(krb5_pointer, keyseed))
OLDDECLARG(krb5_keytype, type)
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
	return KRB5KDC_ERR_ETYPE_NOSUPP; /* XXX */

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
	*realkey = *arg->key;
    else
	*realkey = *kt_ent.key;
    if (realkey->keytype != type) {
	free((char *)realkey);
	cleanup();
	return KRB5KDC_ERR_ETYPE_NOSUPP; /* XXX */
    }	

    /* allocate a copy of the contents */
    if (!(realkey->contents = (krb5_octet *)malloc(realkey->length))) {
	free((char *)realkey);
	cleanup();
	return ENOMEM;
    }
    bcopy((char *)arg->key->contents,
	  (char *)realkey->contents, realkey->length);
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
krb5_get_in_tkt_with_skey(DECLARG(krb5_flags, options),
			  DECLARG(krb5_address **, addrs),
			  DECLARG(krb5_enctype, etype),
			  DECLARG(krb5_keyblock *,key),
			  DECLARG(krb5_ccache, ccache),
			  DECLARG(krb5_creds *,creds))
OLDDECLARG(krb5_flags, options)
OLDDECLARG(krb5_address **, addrs)
OLDDECLARG(krb5_enctype, etype)
OLDDECLARG(krb5_keyblock *,key)
OLDDECLARG(krb5_ccache, ccache)
OLDDECLARG(krb5_creds *, creds)
{
    struct skey_keyproc_arg arg;
    krb5_keytype keytype;

    if (key) {
	arg.key = key;
	arg.server = 0;
	keytype = key->keytype;
    } else {
	arg.key = 0;
	arg.server = creds->server;
	keytype = find_keytype(etype);	/* XXX */
    }
    return (krb5_get_in_tkt(options, addrs, etype, keytype, skey_keyproc,
			    (krb5_pointer) &arg,
			    krb5_kdc_rep_decrypt_proc, 0,
			    creds, ccache));
}

/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_get_in_tkt_with_password()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_in_tkt_pwd_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/libos-proto.h>

struct pwd_keyproc_arg {
    krb5_principal who;
    krb5_data password;
};

extern char *krb5_default_pwd_prompt1;

/* 
 * key-producing procedure for use by krb5_get_in_tkt_with_password.
 */

static krb5_error_code
pwd_keyproc(DECLARG(const krb5_keytype, type),
	    DECLARG(krb5_keyblock **, key),
	    DECLARG(krb5_const_pointer, keyseed))
OLDDECLARG(const krb5_keytype, type)
OLDDECLARG(krb5_keyblock **, key)
OLDDECLARG(krb5_const_pointer, keyseed)
{
    krb5_error_code retval;
    struct pwd_keyproc_arg *arg, arg2;
    char pwdbuf[BUFSIZ];
    int pwsize = sizeof(pwdbuf);

    if (!valid_keytype(type))
	return KRB5_PROG_KEYTYPE_NOSUPP;

    arg = (struct pwd_keyproc_arg *)keyseed;
    if (!arg->password.length) {
	if (retval = krb5_read_password(krb5_default_pwd_prompt1,
					0,
					pwdbuf, &pwsize))
	    return retval;
	arg2 = *arg;
	arg = &arg2;
	arg->password.length = pwsize;
	arg->password.data = pwdbuf;
    }
    *key = (krb5_keyblock *)malloc(sizeof(**key));
    if (!*key)
	return ENOMEM;
    
    if (retval = (*krb5_keytype_array[type]->system->
		  string_to_key)(type,
				 *key,
				 &arg->password,
				 arg->who)) {
	free((char *) *key);
	return(retval);
    }
    return 0;
}

/*
 Attempts to get an initial ticket for creds->client to use server
 creds->server, (realm is taken from creds->client), with options
 options, requesting encryption type etype, and using
 creds->times.starttime,  creds->times.endtime,  creds->times.renew_till
 as from, till, and rtime.  creds->times.renew_till is ignored unless
 the RENEWABLE option is requested.

 If addrs is non-NULL, it is used for the addresses requested.  If it is
 null, the system standard addresses are used.

 If password is non-NULL, it is converted using the cryptosystem entry
 point for a string conversion routine, seeded with the client's name.
 If password is passed as NULL, the password is read from the terminal,
 and then converted into a key.

 A succesful call will place the ticket in the credentials cache ccache.

 returns system errors, encryption errors
 */
krb5_error_code
krb5_get_in_tkt_with_password(DECLARG(const krb5_flags, options),
			      DECLARG(krb5_address * const *, addrs),
			      DECLARG(const krb5_enctype, etype),
			      DECLARG(const krb5_keytype, keytype),
			      DECLARG(const char *, password),
			      DECLARG(krb5_ccache, ccache),
			      DECLARG(krb5_creds *, creds))
OLDDECLARG(const krb5_flags, options)
OLDDECLARG(krb5_address * const *, addrs)
OLDDECLARG(const krb5_enctype, etype)
OLDDECLARG(const krb5_keytype, keytype)
OLDDECLARG(const char *, password)
OLDDECLARG(krb5_ccache, ccache)
OLDDECLARG(krb5_creds *, creds)
{
    krb5_error_code retval;
    struct pwd_keyproc_arg keyseed;


    keyseed.password.data = (char *)password;
    if (password)
	keyseed.password.length = strlen(password);
    else
	keyseed.password.length = 0;
    keyseed.who = creds->client;

    retval = krb5_get_in_tkt(options, addrs, etype, keytype, pwd_keyproc,
			     (krb5_pointer) &keyseed,
			     krb5_kdc_rep_decrypt_proc, 0,
			     creds, ccache);
    return retval;
}


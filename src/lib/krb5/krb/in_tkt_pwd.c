/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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
 * krb5_get_in_tkt_with_password()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_in_tkt_pwd_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>

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
            DECLARG(krb5_const_pointer, keyseed),
            DECLARG(krb5_pa_data **,padata))
OLDDECLARG(const krb5_keytype, type)
OLDDECLARG(krb5_keyblock **, key)
OLDDECLARG(krb5_const_pointer, keyseed)
OLDDECLARG(krb5_pa_data **,padata)
{
    krb5_data salt;
    krb5_error_code retval;
    const struct pwd_keyproc_arg *arg;
    struct pwd_keyproc_arg arg2;
    char pwdbuf[BUFSIZ];
    int pwsize = sizeof(pwdbuf);
    char f_salt = 0, use_salt = 0;

    if (!valid_keytype(type))
	return KRB5_PROG_KEYTYPE_NOSUPP;

    if (padata) {
        krb5_pa_data **ptr;

        for (ptr = padata; *ptr; ptr++)
        {
            if ((*ptr)->pa_type == KRB5_PADATA_PW_SALT)
            {
                /* use KDC-supplied salt, instead of default */
                salt.length = (*ptr)->length;
                salt.data = (char *)(*ptr)->contents;
		use_salt = 1;
                break;
            }
        }
    }
    arg = (const struct pwd_keyproc_arg *)keyseed;
    if (!use_salt) {
	/* need to use flattened principal */
	if (retval = krb5_principal2salt(arg->who, &salt))
	    return(retval);
	f_salt = 1;
    }

    if (!arg->password.length) {
	if (retval = krb5_read_password(krb5_default_pwd_prompt1,
					0,
					pwdbuf, &pwsize)) {
	    if (f_salt) xfree(salt.data);
	    return retval;
	}
	arg2 = *arg;
        arg2.password.length = pwsize;
        arg2.password.data = pwdbuf;
	arg = &arg2;
    }
    *key = (krb5_keyblock *)malloc(sizeof(**key));
    if (!*key) {
	if (f_salt) xfree(salt.data);
	return ENOMEM;
    }    
    if (retval = (*krb5_keytype_array[type]->system->
		  string_to_key)(type,
				 *key,
				 &arg->password,
                                 &salt)) {
	xfree(*key);
	if (f_salt) xfree(salt.data);
	return(retval);
    }
    if (f_salt) xfree(salt.data);
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
			      DECLARG(const krb5_preauthtype, pre_auth_type),
			      DECLARG(const krb5_enctype, etype),
			      DECLARG(const krb5_keytype, keytype),
			      DECLARG(const char *, password),
			      DECLARG(krb5_ccache, ccache),
			      DECLARG(krb5_creds *, creds), 
			      DECLARG(krb5_kdc_rep **, ret_as_reply))
OLDDECLARG(const krb5_flags, options)
OLDDECLARG(krb5_address * const *, addrs)
OLDDECLARG(const krb5_preauthtype, pre_auth_type)
OLDDECLARG(const krb5_enctype, etype)
OLDDECLARG(const krb5_keytype, keytype)
OLDDECLARG(const char *, password)
OLDDECLARG(krb5_ccache, ccache)
OLDDECLARG(krb5_creds *, creds)
OLDDECLARG(krb5_kdc_rep **, ret_as_reply)
{
    krb5_error_code retval;
    struct pwd_keyproc_arg keyseed;


    keyseed.password.data = (char *)password;
    if (password)
	keyseed.password.length = strlen(password);
    else
	keyseed.password.length = 0;
    keyseed.who = creds->client;

    retval = krb5_get_in_tkt(options, addrs, pre_auth_type, etype,
			     keytype, pwd_keyproc, (krb5_pointer) &keyseed,
			     krb5_kdc_rep_decrypt_proc, 0,
			     creds, ccache, ret_as_reply);
    return retval;
}


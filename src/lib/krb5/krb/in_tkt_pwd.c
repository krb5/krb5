/*
 * lib/krb5/krb/in_tkt_pwd.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * krb5_get_in_tkt_with_password()
 */


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
pwd_keyproc(context, type, key, keyseed, padata)
    krb5_context context;
    const krb5_keytype type;
    krb5_keyblock ** key;
    krb5_const_pointer keyseed;
    krb5_pa_data ** padata;
{
    krb5_data salt;
    krb5_error_code retval;
    krb5_encrypt_block eblock;
    const struct pwd_keyproc_arg *arg;
    struct pwd_keyproc_arg arg2;
    char pwdbuf[BUFSIZ];
    int pwsize = sizeof(pwdbuf);
    char f_salt = 0, use_salt = 0;

    if (!valid_keytype(type))
	return KRB5_PROG_KEYTYPE_NOSUPP;

    krb5_use_keytype(context, &eblock, type);
    
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
	if (retval = krb5_principal2salt(context, arg->who, &salt))
	    return(retval);
	f_salt = 1;
    }

    if (!arg->password.length) {
	if (retval = krb5_read_password(context, krb5_default_pwd_prompt1,
					0,
					pwdbuf, &pwsize)) {
	    if (f_salt) krb5_xfree(salt.data);
	    return retval;
	}
	arg2 = *arg;
        arg2.password.length = pwsize;
        arg2.password.data = pwdbuf;
	arg = &arg2;
    }
    *key = (krb5_keyblock *)malloc(sizeof(**key));
    if (!*key) {
	if (f_salt) krb5_xfree(salt.data);
	return ENOMEM;
    }
    retval = krb5_string_to_key(context, &eblock, type, *key, &arg->password, &salt);
    if (retval) {
	krb5_xfree(*key);
	if (f_salt) krb5_xfree(salt.data);
	return(retval);
    }
    if (f_salt) krb5_xfree(salt.data);
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
krb5_get_in_tkt_with_password(context, options, addrs, pre_auth_type, etype,
			      keytype, password, ccache, creds, ret_as_reply)
    krb5_context context;
    const krb5_flags options;
    krb5_address * const * addrs;
    const krb5_preauthtype pre_auth_type;
    const krb5_enctype etype;
    const krb5_keytype keytype;
    const char * password;
    krb5_ccache ccache;
    krb5_creds * creds;
    krb5_kdc_rep ** ret_as_reply;
{
    krb5_error_code retval;
    struct pwd_keyproc_arg keyseed;


    keyseed.password.data = (char *)password;
    if (password)
	keyseed.password.length = strlen(password);
    else
	keyseed.password.length = 0;
    keyseed.who = creds->client;

    retval = krb5_get_in_tkt(context, options, addrs, pre_auth_type, etype,
			     keytype, pwd_keyproc, (krb5_pointer) &keyseed,
			     krb5_kdc_rep_decrypt_proc, 0,
			     creds, ccache, ret_as_reply);
    return retval;
}


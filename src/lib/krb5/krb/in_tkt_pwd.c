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

#include "k5-int.h"

extern char *krb5_default_pwd_prompt1;

/* 
 * key-producing procedure for use by krb5_get_in_tkt_with_password.
 */
krb5_error_code pwd_keyproc
    PROTOTYPE((krb5_context,
               const krb5_enctype,
               krb5_data *,
               krb5_const_pointer,
               krb5_keyblock **));

krb5_error_code
pwd_keyproc(context, type, salt, keyseed, key)
    krb5_context context;
    const krb5_enctype type;
    krb5_data * salt;
    krb5_const_pointer keyseed;
    krb5_keyblock ** key;
{
    krb5_error_code retval;
    krb5_encrypt_block eblock;
    char pwdbuf[BUFSIZ];
    krb5_data * password;
    int pwsize = sizeof(pwdbuf);

    if (!valid_enctype(type))
	return KRB5_PROG_ETYPE_NOSUPP;

    krb5_use_enctype(context, &eblock, type);
    
    password = (krb5_data *)keyseed;

    if (!password->length) {
	if ((retval = krb5_read_password(context, krb5_default_pwd_prompt1, 0,
					 pwdbuf, &pwsize))) {
	    return retval;
	}
        password->length = pwsize;
        password->data = pwdbuf;
    }

    if (!(*key = (krb5_keyblock *)malloc(sizeof(**key))))
	return ENOMEM;

    if ((retval = krb5_string_to_key(context,&eblock,type,*key,password,salt)))
	krb5_xfree(*key);
    return(retval);
}

/*
 Attempts to get an initial ticket for creds->client to use server
 creds->server, (realm is taken from creds->client), with options
 options, and using creds->times.starttime, creds->times.endtime,
 creds->times.renew_till as from, till, and rtime.  
 creds->times.renew_till is ignored unless the RENEWABLE option is requested.

 If addrs is non-NULL, it is used for the addresses requested.  If it is
 null, the system standard addresses are used.

 If password is non-NULL, it is converted using the cryptosystem entry
 point for a string conversion routine, seeded with the client's name.
 If password is passed as NULL, the password is read from the terminal,
 and then converted into a key.

 A succesful call will place the ticket in the credentials cache ccache.

 returns system errors, encryption errors
 */
krb5_error_code INTERFACE
krb5_get_in_tkt_with_password(context, options, addrs, ktypes, pre_auth_types, 
			      password, ccache, creds, ret_as_reply)
    krb5_context context;
    const krb5_flags options;
    krb5_address * const * addrs;
    krb5_enctype * ktypes;
    krb5_preauthtype * pre_auth_types;
    const char * password;
    krb5_ccache ccache;
    krb5_creds * creds;
    krb5_kdc_rep ** ret_as_reply;
{
    krb5_error_code retval;
    krb5_data data;


    if ((data.data = (char *)password)) {
	data.length = strlen(password);
    } else {
	data.length = 0;
    }

    retval = krb5_get_in_tkt(context, options, addrs, ktypes, pre_auth_types, 
			     pwd_keyproc, (krb5_pointer) &data,
			     krb5_kdc_rep_decrypt_proc, 0,
			     creds, ccache, ret_as_reply);
    return retval;
}


/*
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
 */

/*
 * This file contains routines for establishing, verifying, and any other
 * necessary functions, for utilizing the pre-authentication field of the 
 * kerberos kdc request, with various hardware/software verification devices.
 */


#include "k5-int.h"
#include <stdio.h>
#include <time.h>
#include <syslog.h>
#ifdef _MSDOS
#define getpid _getpid
#include <process.h>
#endif

static krb5_preauth_obtain_proc obtain_enc_ts_padata;

static krb5_preauth_ops preauth_systems[] = {
    {
	KV5M_PREAUTH_OPS,
	KRB5_PADATA_ENC_TIMESTAMP,
        0,
        obtain_enc_ts_padata,
        0,
    },
    { -1,}
};

static krb5_error_code find_pa_system
    PROTOTYPE((int type, krb5_preauth_ops **Preauth_proc));

/* some typedef's for the function args to make things look a bit cleaner */

typedef krb5_error_code (*git_key_proc) PROTOTYPE((krb5_context,
						   const krb5_enctype,
						   krb5_data *,
						   krb5_const_pointer,
						   krb5_keyblock **));

krb5_error_code
krb5_encrypt_data(context, key, ivec, data, enc_data)
    krb5_context	context;
    krb5_keyblock *	key;
    krb5_pointer	ivec;
    krb5_data *		data;
    krb5_enc_data *	enc_data;
{
    krb5_error_code	retval;
    krb5_encrypt_block	eblock;

    krb5_use_enctype(context, &eblock, key->enctype);

    enc_data->magic = KV5M_ENC_DATA;
    enc_data->kvno = 0;
    enc_data->enctype = key->enctype;
    enc_data->ciphertext.length = krb5_encrypt_size(data->length,
						    eblock.crypto_entry);
    enc_data->ciphertext.data = malloc(enc_data->ciphertext.length);
    if (enc_data->ciphertext.data == 0)
	return ENOMEM;

    if ((retval = krb5_process_key(context, &eblock, key)) != 0)
	goto cleanup;

    if ((retval = krb5_encrypt(context, (krb5_pointer) data->data,
			       (krb5_pointer) enc_data->ciphertext.data,
			       data->length, &eblock, ivec))) {
    	krb5_finish_key(context, &eblock);
        goto cleanup;
    }
    (void) krb5_finish_key(context, &eblock);

    return 0;

cleanup:
    free(enc_data->ciphertext.data);
    return retval;
}

    
krb5_error_code krb5_obtain_padata(context, preauth_to_use, key_proc,
				   key_seed, creds, request)
    krb5_context		context;
    krb5_pa_data **		preauth_to_use;
    git_key_proc 		key_proc;
    krb5_const_pointer		key_seed;
    krb5_creds *		creds;
    krb5_kdc_req *		request;
{
    krb5_error_code		retval;
    krb5_etype_info	    	etype_info = 0;
    krb5_pa_data **		pa;
    krb5_pa_data **		send_pa_list;
    krb5_pa_data **		send_pa;
    krb5_preauth_ops 		*ops;
    krb5_keyblock *		def_enc_key = 0;
    krb5_enctype 		enctype;
    krb5_data 			salt;
    krb5_data			scratch;
    int				size;
    int				f_salt = 0;

    if (preauth_to_use == NULL)
	return 0;

    for (pa = preauth_to_use, size=0; *pa; pa++, size++) {
	if ((*pa)->pa_type == KRB5_PADATA_ETYPE_INFO) {
	    scratch.length = (*pa)->length;
	    scratch.data = (*pa)->contents;
	    retval = decode_krb5_etype_info(&scratch, &etype_info);
	    if (retval)
		return retval;
	}
    }

    if ((send_pa_list = malloc((size+1) * sizeof(krb5_pa_data *))) == NULL)
	return ENOMEM;

    send_pa = send_pa_list;
    *send_pa = 0;

    enctype = request->ktype[0];
    salt.data = 0;
    salt.length = -1;
    if (etype_info) {
	enctype = etype_info[0]->etype;
	salt.data = etype_info[0]->salt;
	salt.length = etype_info[0]->length;
    }
    if (salt.length == -1) {
	if ((retval = krb5_principal2salt(context, request->client, &salt)))
	    return(retval);
	f_salt = 1;
    }
    
    if ((retval = (*key_proc)(context, enctype, &salt, key_seed,
			      &def_enc_key)))
	goto cleanup;
    

    for (pa = preauth_to_use; *pa; pa++) {
	if (find_pa_system((*pa)->pa_type, &ops))
	    continue;

	if (ops->obtain == 0)
	    continue;
	
	retval = ((ops)->obtain)(context, *pa, etype_info, def_enc_key,
				 key_proc, key_seed, creds,
				 request, send_pa);
	if (retval)
	    goto cleanup;

	if (*send_pa)
	    send_pa++;
	*send_pa = 0;
    }

    retval = 0;

    if (send_pa_list[0]) {
	request->padata = send_pa_list;
	send_pa_list = 0;
    }

cleanup:
    if (f_salt)
	krb5_xfree(salt.data);
    if (send_pa_list)
	krb5_free_pa_data(context, send_pa_list);
    if (def_enc_key)
	krb5_free_keyblock(context, def_enc_key);
    return retval;
    
}

krb5_error_code
krb5_process_padata(context, request, as_reply, key_proc, keyseed,
		    creds, do_more)
    krb5_context	context;
    krb5_kdc_req *	request;
    krb5_kdc_rep *	as_reply;
    git_key_proc	key_proc;
    krb5_const_pointer	keyseed;
    krb5_creds *	creds;
    krb5_int32 *	do_more;
{
    *do_more = 0;
    return 0;
}

static krb5_error_code
obtain_enc_ts_padata(context, in_padata, etype_info, def_enc_key,
		     key_proc, key_seed, creds, request, out_padata)
    krb5_context		context;
    krb5_pa_data *		in_padata;
    krb5_etype_info		etype_info;
    krb5_keyblock *		def_enc_key;
    git_key_proc 		key_proc;
    krb5_const_pointer		key_seed;
    krb5_creds *		creds;
    krb5_kdc_req *		request;
    krb5_pa_data **		out_padata;
{
    krb5_pa_enc_ts		pa_enc;
    krb5_error_code		retval;
    krb5_data *			scratch;
    krb5_enc_data 		enc_data;
    krb5_pa_data *		pa;
    

    enc_data.ciphertext.data = 0;

    retval = krb5_us_timeofday(context, &pa_enc.patimestamp, &pa_enc.pausec);
    if (retval)
	return retval;

    if ((retval = encode_krb5_pa_enc_ts(&pa_enc, &scratch)) != 0)
	return retval;

    if ((retval = krb5_encrypt_data(context, def_enc_key, 0, scratch,
				    &enc_data)))
	goto cleanup;

    krb5_free_data(context, scratch);
    scratch = 0;
    
    if ((retval = encode_krb5_enc_data(&enc_data, &scratch)) != 0)
	goto cleanup;

    if ((pa = malloc(sizeof(krb5_pa_data))) == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }

    pa->magic = KV5M_PA_DATA;
    pa->pa_type = KRB5_PADATA_ENC_TIMESTAMP;
    pa->length = scratch->length;
    pa->contents = scratch->data;

    *out_padata = pa;

    krb5_xfree(scratch);
    scratch = 0;

    retval = 0;
    
cleanup:
    if (scratch)
	krb5_free_data(context, scratch);
    if (enc_data.ciphertext.data)
	krb5_xfree(enc_data.ciphertext.data);
    return retval;
}

static krb5_error_code
find_pa_system(type, preauth)
    int			type;
    krb5_preauth_ops	**preauth;
{
    krb5_preauth_ops *ap = preauth_systems;
    
    while ((ap->type != -1) && (ap->type != type))
	ap++;
    if (ap->type == -1)
	return(KRB5_PREAUTH_BAD_TYPE);
    *preauth = ap;
    return 0;
} 


/*
 * kdc/kdc_preauth.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
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
 * Preauthentication routines for the KDC.
 */

#include "k5-int.h"
#include "kdc_util.h"
#include "extern.h"
#include <stdio.h>

typedef krb5_error_code (*verify_proc)
    KRB5_PROTOTYPE((krb5_context, krb5_db_entry *client,
		    krb5_kdc_req *request,
		    krb5_enc_tkt_part * enc_tkt_reply, krb5_pa_data *data));

typedef krb5_error_code (*edata_proc)
    KRB5_PROTOTYPE((krb5_context, krb5_kdc_req *request,
		    krb5_db_entry *client, krb5_db_entry *server,
		    krb5_pa_data *data));

typedef krb5_error_code (*return_proc)
    KRB5_PROTOTYPE((krb5_context, krb5_pa_data * padata, 
		    krb5_db_entry *client,
		    krb5_kdc_req *request, krb5_kdc_rep *reply,
		    krb5_key_data *client_key,
		    krb5_keyblock *encrypting_key,
		    krb5_pa_data **send_pa));

typedef struct _krb5_preauth_systems {
    int		type;
    int		flags;
    edata_proc	get_edata;
    verify_proc	verify_padata;
    return_proc return_padata;
} krb5_preauth_systems;

static krb5_error_code verify_enc_timestamp
    KRB5_PROTOTYPE((krb5_context, krb5_db_entry *client,
		    krb5_kdc_req *request,
		    krb5_enc_tkt_part * enc_tkt_reply, krb5_pa_data *data));

static krb5_error_code get_etype_info
    KRB5_PROTOTYPE((krb5_context, krb5_kdc_req *request,
		    krb5_db_entry *client, krb5_db_entry *server,
		    krb5_pa_data *data));
static krb5_error_code return_pw_salt
    KRB5_PROTOTYPE((krb5_context, krb5_pa_data * padata, 
		    krb5_db_entry *client,
		    krb5_kdc_req *request, krb5_kdc_rep *reply,
		    krb5_key_data *client_key,
		    krb5_keyblock *encrypting_key,
		    krb5_pa_data **send_pa));

/*
 * Preauth property flags
 */
#define PA_HARDWARE	0x00000001
#define PA_REQUIRED	0x00000002
#define PA_SUFFICIENT	0x00000004

static krb5_preauth_systems preauth_systems[] = {
    {
        KRB5_PADATA_ENC_TIMESTAMP,
        0,
        0,
	verify_enc_timestamp,
	0
    },
    {
	KRB5_PADATA_ETYPE_INFO,
	0,
	get_etype_info,
	0,
	0
    },
    {
	KRB5_PADATA_PW_SALT,
	0,
	0, 
	0,
	return_pw_salt
    },
    { -1,}
};

#define MAX_PREAUTH_SYSTEMS (sizeof(preauth_systems)/sizeof(preauth_systems[0]))

static krb5_error_code
find_pa_system(type, preauth)
    int			type;
    krb5_preauth_systems	**preauth;
{
    krb5_preauth_systems 	*ap = preauth_systems;
    
    while ((ap->type != -1) && (ap->type != type))
	ap++;
    if (ap->type == -1)
	return(KRB5_PREAUTH_BAD_TYPE);
    *preauth = ap;
    return 0;
} 

const char *missing_required_preauth(client, server, enc_tkt_reply)
    krb5_db_entry *client, *server;
    krb5_enc_tkt_part *enc_tkt_reply;
{
#if 0
    /*
     * If this is the pwchange service, and the pre-auth bit is set,
     * allow it even if the HW preauth would normally be required.
     * 
     * Sandia national labs wanted this for some strange reason... we
     * leave it disabled normally.
     */
    if (isflagset(server->attributes, KRB5_KDB_PWCHANGE_SERVICE) &&
	isflagset(enc_tkt_reply->flags, TKT_FLG_PRE_AUTH))
	return 0;
#endif
    
    if (isflagset(client->attributes, KRB5_KDB_REQUIRES_PRE_AUTH) &&
	 !isflagset(enc_tkt_reply->flags, TKT_FLG_PRE_AUTH))
	return "NEEDED_PREAUTH";
    
    if (isflagset(client->attributes, KRB5_KDB_REQUIRES_HW_AUTH) &&
	!isflagset(enc_tkt_reply->flags, TKT_FLG_HW_AUTH))
	return "NEEDED_HW_PREAUTH";

    return 0;
}

void get_preauth_hint_list(request, client, server, e_data)
    krb5_kdc_req *request;
    krb5_db_entry *client, *server;
    krb5_data *e_data;
{
    int hw_only;
    krb5_preauth_systems *ap;
    krb5_pa_data **pa_data, **pa;
    krb5_data *edat;
    krb5_error_code retval;
    
    /* Zero these out in case we need to abort */
    e_data->length = 0;
    e_data->data = 0;
    
    hw_only = isflagset(client->attributes, KRB5_KDB_REQUIRES_HW_AUTH);
    pa_data = malloc(sizeof(krb5_pa_data *) * (MAX_PREAUTH_SYSTEMS+1));
    if (pa_data == 0)
	return;
    memset(pa_data, 0, sizeof(krb5_pa_data *) * (MAX_PREAUTH_SYSTEMS+1));
    pa = pa_data;

    for (ap = preauth_systems; ap->type != -1; ap++) {
	if (hw_only && !(ap->flags & PA_HARDWARE))
	    continue;
	*pa = malloc(sizeof(krb5_pa_data));
	if (*pa == 0)
	    goto errout;
	memset(*pa, 0, sizeof(krb5_pa_data));
	(*pa)->magic = KV5M_PA_DATA;
	(*pa)->pa_type = ap->type;
	if (ap->get_edata)
	    (ap->get_edata)(kdc_context, request, client, server, *pa);
	pa++;
    }
    retval = encode_krb5_padata_sequence((const krb5_pa_data **) pa_data,
					 &edat);
    if (retval)
	goto errout;
    *e_data = *edat;
    free(edat);

errout:
    krb5_free_pa_data(kdc_context, pa_data);
    return;
}

/*
 * This routine is called to verify the preauthentication information
 * for a V5 request.
 * 	
 * Returns 0 if the pre-authentication is valid, non-zero to indicate
 * an error code of some sort.
 */

krb5_error_code
check_padata (context, client, request, enc_tkt_reply)
    krb5_context	context;
    krb5_db_entry *	client;
    krb5_kdc_req *	request;
    krb5_enc_tkt_part * enc_tkt_reply;
{
    krb5_error_code retval;
    krb5_pa_data **padata;
    krb5_preauth_systems *pa_sys;

    if (request->padata == 0)
	return 0;

    for (padata = request->padata; *padata; padata++) {
	if (find_pa_system((*padata)->pa_type, &pa_sys))
	    continue;
	if (pa_sys->verify_padata == 0)
	    continue;
	retval = pa_sys->verify_padata(context, client, request,
				       enc_tkt_reply, *padata);
	if (retval) {
	    if (pa_sys->flags & PA_REQUIRED)
		break;
	} else {
	    if (pa_sys->flags & PA_SUFFICIENT)
		break;
	}
    }
    if (retval)
	retval = KRB5KDC_ERR_PREAUTH_FAILED;
    return retval;
}

/*
 * return_padata creates any necessary preauthentication
 * structures which should be returned by the KDC to the client
 */
krb5_error_code
return_padata(context, client, request, reply,
	      client_key, encrypting_key)
    krb5_context	context;
    krb5_db_entry *	client;
    krb5_kdc_req *	request;
    krb5_kdc_rep *	reply;
    krb5_key_data *	client_key;
    krb5_keyblock *	encrypting_key;
{
    krb5_error_code		retval;
    krb5_pa_data **		padata;
    krb5_pa_data **		send_pa_list;
    krb5_pa_data **		send_pa;
    krb5_pa_data *		pa = 0;
    krb5_preauth_systems *	ap;
    int 			size;

    for (ap = preauth_systems; ap->type != -1; ap++) {
	if (ap->return_padata)
	    size++;
    }

    if ((send_pa_list = malloc((size+1) * sizeof(krb5_pa_data *))) == NULL)
	return ENOMEM;

    send_pa = send_pa_list;
    *send_pa = 0;
    
    for (ap = preauth_systems; ap->type != -1; ap++) {
	if (ap->return_padata == 0)
	    continue;
	pa = 0;
	if (request->padata) {
	    for (padata = request->padata; *padata; padata++) {
		if ((*padata)->pa_type == ap->type) {
		    pa = *padata;
		    break;
		}
	    }
	}
	if ((retval = ap->return_padata(context, pa, client, request, reply,
					client_key, encrypting_key, send_pa)))
	    goto cleanup;

	if (*send_pa)
	    send_pa++;
	*send_pa = 0;
    }
    
    retval = 0;

    if (send_pa_list[0]) {
	reply->padata = send_pa_list;
	send_pa_list = 0;
    }
    
cleanup:
    if (send_pa_list)
	krb5_free_pa_data(context, send_pa_list);
    return (retval);
}

static krb5_error_code
verify_enc_timestamp(context, client, request, enc_tkt_reply, pa)
    krb5_context	context;
    krb5_db_entry *	client;
    krb5_kdc_req *	request;
    krb5_enc_tkt_part * enc_tkt_reply;
    krb5_pa_data *	pa;
{
    krb5_pa_enc_ts *		pa_enc = 0;
    krb5_error_code		retval;
    krb5_data			scratch;
    krb5_data			enc_ts_data;
    krb5_enc_data 		*enc_data = 0;
    krb5_keyblock		key;
    krb5_key_data *		client_key;
    krb5_int32			start;
    krb5_timestamp		timenow;
    
    enc_ts_data.data = 0;
    scratch.data = pa->contents;
    scratch.length = pa->length;
    
    if ((retval = decode_krb5_enc_data(&scratch, &enc_data)) != 0)
	goto cleanup;

    start = 0;
    while (1) {
	if ((retval = krb5_dbe_search_enctype(context, client,
					      &start, enc_data->enctype,
					      -1, 0, &client_key)))
	    goto cleanup;

	if ((retval = krb5_dbekd_decrypt_key_data(context, &master_encblock, 
						  client_key, &key, NULL)))
	    goto cleanup;
	key.enctype = enc_data->enctype;

	retval = krb5_decrypt_data(context, &key, 0, enc_data, &enc_ts_data);
	memset((char *)key.contents, 0, key.length);
	krb5_xfree(key.contents);

	if (retval == 0)
	    break;
    }

    if ((retval = decode_krb5_pa_enc_ts(&enc_ts_data, &pa_enc)) != 0)
	goto cleanup;

    if ((retval = krb5_timeofday(context, &timenow)) != 0)
	goto cleanup;
    
    if (labs(timenow - pa_enc->patimestamp) > context->clockskew) {
	retval = KRB5KRB_AP_ERR_SKEW;
	goto cleanup;
    }

    setflag(enc_tkt_reply->flags, TKT_FLG_PRE_AUTH);

    retval = 0;
    
cleanup:
    if (enc_data) {
	if (enc_data->ciphertext.data)
	    krb5_xfree(enc_data->ciphertext.data);
	free(enc_data);
    }
    if (enc_ts_data.data)
	krb5_xfree(enc_ts_data.data);
    if (pa_enc)
	krb5_xfree(pa_enc);
    return retval;
}

/*
 * This function returns the etype information for a particular
 * client, to be passed back in the preauth list in the KRB_ERROR
 * message.
 */
static krb5_error_code
get_etype_info(context, request, client, server, pa_data)
    krb5_context 	context;
    krb5_kdc_req *	request;
    krb5_db_entry *	client;
    krb5_db_entry *	server;
    krb5_pa_data *	pa_data;
{
    krb5_etype_info_entry **	entry = 0;
    krb5_key_data		*client_key;
    krb5_error_code		retval;
    krb5_data			salt;
    krb5_data *			scratch;
    krb5_enctype		db_etype;
    int 			i = 0;
    int 			start = 0;

    salt.data = 0;

    entry = malloc((client->n_key_data * 2) * sizeof(krb5_etype_info_entry *));
    if (entry == NULL)
	return ENOMEM;
    entry[0] = NULL;

    while (1) {
	retval = krb5_dbe_search_enctype(context, client, &start, -1,
					 -1, 0, &client_key);
	if (retval == ENOENT)
	    break;
	if (retval)
	    goto cleanup;
	db_etype = client_key->key_data_type[0];
	if (db_etype == ENCTYPE_DES_CBC_MD4 || db_etype == ENCTYPE_DES_CBC_MD5)
	    db_etype = ENCTYPE_DES_CBC_CRC;
	
	while (1) {
	    if ((entry[i] = malloc(sizeof(krb5_etype_info_entry))) == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }
	    entry[i+1] = 0;
	    entry[i]->magic = KV5M_ETYPE_INFO_ENTRY;
	    entry[i]->etype = db_etype;
	    entry[i]->length = -1;
	    entry[i]->salt = 0;
	    retval = get_salt_from_key(context, request->client,
				       client_key, &salt);
	    if (retval)
		goto cleanup;
	    if (salt.length >= 0) {
		entry[i]->length = salt.length;
		entry[i]->salt = salt.data;
		salt.data = 0;
	    }
	    i++;
	    /*
	     * If we have a DES_CRC key, it can also be used as a
	     * DES_MD5 key.
	     */
	    if (db_etype == ENCTYPE_DES_CBC_CRC)
		db_etype = ENCTYPE_DES_CBC_MD5;
	    else
		break;
	}
    }
    retval = encode_krb5_etype_info((const krb5_etype_info_entry **) entry,
				    &scratch);
    if (retval)
	goto cleanup;
    pa_data->contents = scratch->data;
    pa_data->length = scratch->length;

    retval = 0;

cleanup:
    if (entry)
	krb5_free_etype_info(context, entry);
    if (salt.data)
	krb5_xfree(salt.data);
    return retval;
}

static krb5_error_code
return_pw_salt(context, in_padata, client, request, reply, client_key,
	       encrypting_key, send_pa)
    krb5_context	context;
    krb5_pa_data *	in_padata;
    krb5_db_entry *	client;
    krb5_kdc_req *	request;
    krb5_kdc_rep *	reply;
    krb5_key_data *	client_key;
    krb5_keyblock *	encrypting_key;
    krb5_pa_data **	send_pa;
{
    krb5_error_code	retval;
    krb5_pa_data *	padata;
    krb5_data *		scratch;
    krb5_data		salt_data;
    
    if (client_key->key_data_ver == 1 ||
	client_key->key_data_type[1] == KRB5_KDB_SALTTYPE_NORMAL)
	return 0;

    if ((padata = malloc(sizeof(krb5_pa_data))) == NULL)
	return ENOMEM;
    padata->magic = KV5M_PA_DATA;
    padata->pa_type = KRB5_PADATA_PW_SALT;
    
    switch (client_key->key_data_type[1]) {
    case KRB5_KDB_SALTTYPE_V4:
	/* send an empty (V4) salt */
	padata->contents = 0;
	padata->length = 0;
	break;
    case KRB5_KDB_SALTTYPE_NOREALM:
	if ((retval = krb5_principal2salt_norealm(kdc_context, 
						   request->client,
						   &salt_data)))
	    goto cleanup;
	padata->contents = (krb5_octet *)salt_data.data;
	padata->length = salt_data.length;
	break;
    case KRB5_KDB_SALTTYPE_ONLYREALM:
	scratch = krb5_princ_realm(kdc_context, request->client);
	if ((padata->contents = malloc(scratch->length)) == NULL) {
	    retval = ENOMEM;
	    goto cleanup;
	}
	memcpy(padata->contents, scratch->data, scratch->length);
	padata->length = scratch->length;
	break;
    case KRB5_KDB_SALTTYPE_SPECIAL:
	if ((padata->contents = malloc(client_key->key_data_length[1]))
	    == NULL) {
	    retval = ENOMEM;
	    goto cleanup;
	}
	memcpy(padata->contents, client_key->key_data_contents[1],
	       client_key->key_data_length[1]);
	padata->length = client_key->key_data_length[1];
	break;
    default:
	free(padata);
	return 0;
    }

    *send_pa = padata;
    return 0;
    
cleanup:
    free(padata);
    return retval;
}

    


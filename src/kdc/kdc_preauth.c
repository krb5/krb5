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

typedef krb5_error_code (verify_proc)
    KRB5_PROTOTYPE((krb5_context, krb5_db_entry *client,
		    krb5_kdc_req *request,
		    krb5_enc_tkt_part * enc_tkt_reply, krb5_pa_data *data));

typedef krb5_error_code (edata_proc)
    KRB5_PROTOTYPE((krb5_context, krb5_db_entry *client, krb5_pa_data *data));

typedef struct _krb5_preauth_systems {
    int		type;
    int		flags;
    edata_proc	*get_edata;
    verify_proc	*verify;
} krb5_preauth_systems;

static verify_proc verify_enc_timestamp;

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

krb5_error_code
krb5_decrypt_data(context, key, ivec, enc_data, data)
    krb5_context	context;
    krb5_keyblock *	key;
    krb5_pointer	ivec;
    krb5_enc_data *	enc_data;
    krb5_data *		data;
{
    krb5_error_code	retval;
    krb5_encrypt_block	eblock;

    krb5_use_enctype(context, &eblock, key->enctype);
    data->length = enc_data->ciphertext.length;
    if (!(data->data = malloc(data->length)))
	return ENOMEM;

    if ((retval = krb5_process_key(context, &eblock, key)) != 0)
	goto cleanup;

    if ((retval = krb5_decrypt(context,
			       (krb5_pointer) enc_data->ciphertext.data,
			       (krb5_pointer) data->data,
			       enc_data->ciphertext.length, &eblock, ivec))) {
    	krb5_finish_key(context, &eblock);
        goto cleanup;
    }
    (void) krb5_finish_key(context, &eblock);

    return 0;

cleanup:
    if (data->data) {
	free(data->data);
	data->data = 0;
    }
    return retval;
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

void get_preauth_hint_list(client, server, e_data)
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
	    (ap->get_edata)(kdc_context, client, *pa);
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
	if (pa_sys->verify == 0)
	    continue;
	retval = pa_sys->verify(context, client, request,
				enc_tkt_reply, *padata);
	if (retval) {
	    if (pa_sys->flags & PA_REQUIRED)
		break;
	} else {
	    if (pa_sys->flags & PA_SUFFICIENT)
		break;
	}
    }
    return retval;
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

	retval = krb5_decrypt_data(context, key, 0, enc_data, &enc_ts_data);
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


#if 0			

	setflag(enc_tkt_reply.flags, TKT_FLG_PRE_AUTH);
	/*
	 * If pa_type is one in which additional hardware authentication
	 * was performed set TKT_FLG_HW_AUTH too.
	 */
	if (pa_flags & KRB5_PREAUTH_FLAGS_HARDWARE)
            setflag(enc_tkt_reply.flags, TKT_FLG_HW_AUTH);

#endif

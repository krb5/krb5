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

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
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

/* SAM preauth support */
static krb5_error_code verify_sam_response
    KRB5_PROTOTYPE((krb5_context, krb5_db_entry *client,
		    krb5_kdc_req *request,
		    krb5_enc_tkt_part * enc_tkt_reply, krb5_pa_data *data));

static krb5_error_code get_sam_edata
    KRB5_PROTOTYPE((krb5_context, krb5_kdc_req *request,
		    krb5_db_entry *client, krb5_db_entry *server,
		    krb5_pa_data *data));
/*
 * Preauth property flags
 */
#define PA_HARDWARE	0x00000001
#define PA_REQUIRED	0x00000002
#define PA_SUFFICIENT	0x00000004
	/* Not really a padata, so don't include it in the etype list*/
#define PA_PSEUDO	0x00000008 

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
	PA_PSEUDO,		/* Don't include this in the error list */
	0, 
	0,
	return_pw_salt
    },
    {
	KRB5_PADATA_SAM_RESPONSE,
	0,
	0,
	verify_sam_response,
	0
    },
    {
	KRB5_PADATA_SAM_CHALLENGE,
	PA_HARDWARE,		/* causes get_preauth_hint_list to use this */
	get_sam_edata,
	0,
	0
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
	if (ap->flags & PA_PSEUDO)
	    continue;
	*pa = malloc(sizeof(krb5_pa_data));
	if (*pa == 0)
	    goto errout;
	memset(*pa, 0, sizeof(krb5_pa_data));
	(*pa)->magic = KV5M_PA_DATA;
	(*pa)->pa_type = ap->type;
	if (ap->get_edata) {
	  retval = (ap->get_edata)(kdc_context, request, client, server, *pa);
	  if (retval) {
	    /* just failed on this type, continue */
	    free(*pa);
	    *pa = 0;
	    continue;
	  }
	}
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
    krb5_error_code retval = 0;
    krb5_pa_data **padata;
    krb5_preauth_systems *pa_sys;
    int			pa_ok = 0, pa_found = 0;

    if (request->padata == 0)
	return 0;

    for (padata = request->padata; *padata; padata++) {
	if (find_pa_system((*padata)->pa_type, &pa_sys))
	    continue;
	if (pa_sys->verify_padata == 0)
	    continue;
	pa_found++;
	retval = pa_sys->verify_padata(context, client, request,
				       enc_tkt_reply, *padata);
	if (retval) {
	    com_err("krb5kdc", retval, "pa verify failure");
	    if (pa_sys->flags & PA_REQUIRED) {
		pa_ok = 0;
		break;
	    }
	} else {
	    pa_ok = 1;
	    if (pa_sys->flags & PA_SUFFICIENT) 
		break;
	}
    }
    if (pa_ok)
	return 0;

    /* pa system was not found, but principal doesn't require preauth */
    if (!pa_found &&
        !isflagset(client->attributes, KRB5_KDB_REQUIRES_PRE_AUTH) &&
        !isflagset(client->attributes, KRB5_KDB_REQUIRES_HW_AUTH))
       return 0;

    if (!pa_found)
	com_err("krb5kdc", retval, "no valid preauth type found");
    return KRB5KDC_ERR_PREAUTH_FAILED;
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
    int 			size = 0;

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
    
    scratch.data = pa->contents;
    scratch.length = pa->length;

    enc_ts_data.data = 0;
    
    if ((retval = decode_krb5_enc_data(&scratch, &enc_data)) != 0)
	goto cleanup;

    enc_ts_data.length = enc_data->ciphertext.length;
    if ((enc_ts_data.data = (char *) malloc(enc_ts_data.length)) == NULL)
	goto cleanup;

    start = 0;
    while (1) {
	if ((retval = krb5_dbe_search_enctype(context, client,
					      &start, enc_data->enctype,
					      -1, 0, &client_key)))
	    goto cleanup;

	if ((retval = krb5_dbekd_decrypt_key_data(context, &master_keyblock, 
						  client_key, &key, NULL)))
	    goto cleanup;

	key.enctype = enc_data->enctype;

	retval = krb5_c_decrypt(context, &key, KRB5_KEYUSAGE_AS_REQ_PA_ENC_TS,
				0, enc_data, &enc_ts_data);
	krb5_free_keyblock_contents(context, &key);
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
	krb5_free_data_contents(context, &enc_data->ciphertext);
	free(enc_data);
    }
    krb5_free_data_contents(context, &enc_ts_data);
    if (pa_enc)
	free(pa_enc);
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

    entry = malloc((client->n_key_data * 2 + 1) * sizeof(krb5_etype_info_entry *));
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
    free(scratch);

    retval = 0;

cleanup:
    if (entry)
	krb5_free_etype_info(context, entry);
    if (salt.data)
	free(salt.data);
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
    case KRB5_KDB_SALTTYPE_AFS3:
	/* send an AFS style realm-based salt */
	/* for now, just pass the realm back and let the client
	   do the work. In the future, add a kdc configuration
	   variable that specifies the old cell name. */
	padata->pa_type = KRB5_PADATA_AFS3_SALT;
	/* it would be just like ONLYREALM, but we need to pass the 0 */
	scratch = krb5_princ_realm(kdc_context, request->client);
	if ((padata->contents = malloc(scratch->length+1)) == NULL) {
	    retval = ENOMEM;
	    goto cleanup;
	}
	memcpy(padata->contents, scratch->data, scratch->length);
	padata->length = scratch->length+1;
	padata->contents[scratch->length] = 0;
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

    
static struct {
  char* name;
  int   sam_type;
} *sam_ptr, sam_inst_map[] = {
  "SNK4", PA_SAM_TYPE_DIGI_PATH,
  "SECURID", PA_SAM_TYPE_SECURID,
  "GRAIL", PA_SAM_TYPE_GRAIL,
  0, 0
};

static krb5_error_code
get_sam_edata(context, request, client, server, pa_data)
    krb5_context 	context;
    krb5_kdc_req *	request;
    krb5_db_entry *	client;
    krb5_db_entry *	server;
    krb5_pa_data *	pa_data;
{
    krb5_error_code		retval;
    krb5_sam_challenge		sc;
    krb5_predicted_sam_response	psr;
    krb5_data *			scratch;
    int 			i = 0;
    krb5_keyblock encrypting_key;
    char response[9];
    char inputblock[8];
    krb5_data predict_response;

    /* Given the client name we can figure out what type of preauth
       they need. The spec is currently for querying the database for
       names that match the types of preauth used. Later we should
       make this mapping show up in kdc.conf. In the meantime, we
       hardcode the following:
		/SNK4 -- Digital Pathways SNK/4 preauth.
		/GRAIL -- experimental preauth
       The first one found is used. See sam_inst_map above.

       For SNK4 in particular, the key in the database is the key for
       the device; kadmin needs a special interface for it.
     */

    {
      int npr = 1;
      krb5_boolean more;
      krb5_db_entry assoc;
      krb5_key_data  *assoc_key;
      krb5_principal newp;
      int probeslot;

      sc.sam_type = 0;

      retval = krb5_copy_principal(kdc_context, request->client, &newp);
      if (retval) {
	com_err("krb5kdc", retval, "copying client name for preauth probe");
	return retval;
      }

      probeslot = krb5_princ_size(context, newp)++;
      krb5_princ_name(kdc_context, newp) = 
	realloc(krb5_princ_name(kdc_context, newp),
		krb5_princ_size(context, newp) * sizeof(krb5_data));

      for(sam_ptr = sam_inst_map; sam_ptr->name; sam_ptr++) {
	krb5_princ_component(kdc_context,newp,probeslot)->data = sam_ptr->name;
	krb5_princ_component(kdc_context,newp,probeslot)->length = 
	  strlen(sam_ptr->name);
	npr = 1;
	retval = krb5_db_get_principal(kdc_context, newp, &assoc, &npr, &more);
	if(!retval && npr) {
	  sc.sam_type = sam_ptr->sam_type;
	  break;
	}
      }

      krb5_princ_component(kdc_context,newp,probeslot)->data = 0;
      krb5_princ_component(kdc_context,newp,probeslot)->length = 0;
      krb5_princ_size(context, newp)--;

      krb5_free_principal(kdc_context, newp);

      /* if sc.sam_type is set, it worked */
      if (sc.sam_type) {
	/* so use assoc to get the key out! */
	{
	  /* here's what do_tgs_req does */
	  retval = krb5_dbe_find_enctype(kdc_context, &assoc,
					 ENCTYPE_DES_CBC_RAW,
					 KRB5_KDB_SALTTYPE_NORMAL,
					 0,		/* Get highest kvno */
					 &assoc_key);
	  if (retval) {
	    char *sname;
	    krb5_unparse_name(kdc_context, request->client, &sname);
	    com_err("krb5kdc", retval, 
		    "snk4 finding the enctype and key <%s>", sname);
	    free(sname);
	    return retval;
	  }
	  /* convert server.key into a real key */
	  retval = krb5_dbekd_decrypt_key_data(kdc_context,
					       &master_keyblock, 
					       assoc_key, &encrypting_key,
					       NULL);
	  if (retval) {
	    com_err("krb5kdc", retval, 
		    "snk4 pulling out key entry");
	    return retval;
	  }
	  /* now we can use encrypting_key... */
	}
      } else {
	/* SAM is not an option - so don't return as hint */
	return KRB5_PREAUTH_BAD_TYPE;
      }
    }
    sc.magic = KV5M_SAM_CHALLENGE;
    sc.sam_flags = KRB5_SAM_USE_SAD_AS_KEY;

    switch (sc.sam_type) {
    case PA_SAM_TYPE_GRAIL:
      sc.sam_type_name.data = "Experimental System";
      sc.sam_type_name.length = strlen(sc.sam_type_name.data);
      sc.sam_challenge_label.data = "experimental challenge label";
      sc.sam_challenge_label.length = strlen(sc.sam_challenge_label.data);
      sc.sam_challenge.data = "12345";
      sc.sam_challenge.length = strlen(sc.sam_challenge.data);

      psr.magic = KV5M_PREDICTED_SAM_RESPONSE;
      /* string2key on sc.sam_challenge goes in here */
      /* eblock is just to set the enctype */
      {
	const krb5_enctype type = ENCTYPE_DES_CBC_MD5;

	if ((retval = krb5_c_string_to_key(context, type, &sc.sam_challenge,
					   0 /* salt */, &psr.sam_key)))
	    goto cleanup;

	if ((retval = encode_krb5_predicted_sam_response(&psr, &scratch)))
	    goto cleanup;
	
	{
	    size_t enclen;
	    krb5_enc_data tmpdata;

	    if ((retval = krb5_c_encrypt_length(context,
						master_keyblock.enctype,
						scratch->length, &enclen)))
		goto cleanup;

	    if ((tmpdata.ciphertext.data = (char *) malloc(enclen)) == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }
	    tmpdata.ciphertext.length = enclen;

	    if ((retval = krb5_c_encrypt(context, &master_keyblock,
					 /* XXX */ 0, 0, scratch, &tmpdata)))
		goto cleanup;

	    sc.sam_track_id = tmpdata.ciphertext;
	}
      }

      sc.sam_response_prompt.data = "response prompt";
      sc.sam_response_prompt.length = strlen(sc.sam_response_prompt.data);
      sc.sam_pk_for_sad.length = 0;
      sc.sam_nonce = 0;
      /* Generate checksum */
      /*krb5_checksum_size(context, ctype)*/
      /*krb5_calculate_checksum(context,ctype,in,in_length,seed,
	seed_length,outcksum) */
      /*krb5_verify_checksum(context,ctype,cksum,in,in_length,seed,
	seed_length) */
      sc.sam_cksum.contents = (krb5_octet *)
	malloc(krb5_checksum_size(context, CKSUMTYPE_RSA_MD5_DES));
      if (sc.sam_cksum.contents == NULL) return(ENOMEM);

      retval = krb5_calculate_checksum(context, CKSUMTYPE_RSA_MD5_DES,
				       sc.sam_challenge.data,
				       sc.sam_challenge.length,
				       psr.sam_key.contents, /* key */
				       psr.sam_key.length, /* key length */
				       &sc.sam_cksum);
      if (retval) { free(sc.sam_cksum.contents); return(retval); }
      
      retval = encode_krb5_sam_challenge(&sc, &scratch);
      if (retval) goto cleanup;
      pa_data->magic = KV5M_PA_DATA;
      pa_data->pa_type = KRB5_PADATA_SAM_CHALLENGE;
      pa_data->contents = scratch->data;
      pa_data->length = scratch->length;
      
      retval = 0;
      break;
    case PA_SAM_TYPE_DIGI_PATH:
      sc.sam_type_name.data = "Digital Pathways";
      sc.sam_type_name.length = strlen(sc.sam_type_name.data);
#if 1
      sc.sam_challenge_label.data = "Enter the following on your keypad";
      sc.sam_challenge_label.length = strlen(sc.sam_challenge_label.data);
#endif
      /* generate digit string, take it mod 1000000 (six digits.) */
      {
	int j;
	krb5_keyblock session_key;
	char outputblock[8];
	int i;

	session_key.contents = 0;

	memset(inputblock, 0, 8);

	retval = krb5_c_make_random_key(kdc_context, ENCTYPE_DES_CBC_CRC,
					&session_key);

	if (retval) {
	  /* random key failed */
	  com_err("krb5kdc", retval,"generating random challenge for preauth");
	  return retval;
	}
	/* now session_key has a key which we can pick bits out of */
	/* we need six decimal digits. Grab 6 bytes, div 2, mod 10 each. */
	if (session_key.length != 8) {
	  com_err("krb5kdc", retval = KRB5KDC_ERR_ETYPE_NOSUPP,
		  "keytype didn't match code expectations");
	  return retval;
	}
	for(i = 0; i<6; i++) {
	  inputblock[i] = '0' + ((session_key.contents[i]/2) % 10);
	}
	if (session_key.contents)
	  krb5_free_keyblock_contents(kdc_context, &session_key);

	/* retval = krb5_finish_key(kdc_context, &eblock); */
	/* now we have inputblock containing the 8 byte input to DES... */
	sc.sam_challenge.data = inputblock;
	sc.sam_challenge.length = 6;

	encrypting_key.enctype = ENCTYPE_DES_CBC_RAW;

	if (retval) {
	  com_err("krb5kdc", retval, "snk4 processing key");
	}

	{
	    krb5_data plain;
	    krb5_enc_data cipher;

	    plain.length = 8;
	    plain.data = inputblock;

	    /* XXX I know this is enough because of the fixed raw enctype.
	       if it's not, the underlying code will return a reasonable
	       error, which should never happen */
	    cipher.ciphertext.length = 8;
	    cipher.ciphertext.data = outputblock;

	    if ((retval = krb5_c_encrypt(kdc_context, &encrypting_key,
					 /* XXX */ 0, 0, &plain, &cipher))) {
		com_err("krb5kdc", retval, "snk4 response generation failed");
		return retval;
	    }
	}

	/* now output block is the raw bits of the response; convert it
	   to display form */
	for (j=0; j<4; j++) {
	  char n[2];
	  int k;
	  n[0] = outputblock[j] & 0xf;
	  n[1] = (outputblock[j]>>4) & 0xf;
	  for (k=0; k<2; k++) {
	    if(n[k] > 9) n[k] = ((n[k]-1)>>2);
	    /* This is equivalent to:
	       if(n[k]>=0xa && n[k]<=0xc) n[k] = 2;
	       if(n[k]>=0xd && n[k]<=0xf) n[k] = 3;
	       */
	  }
	  /* for v4, we keygen: *(j+(char*)&key1) = (n[1]<<4) | n[0]; */
	  /* for v5, we just generate a string */
	  response[2*j+0] = '0' + n[1];
	  response[2*j+1] = '0' + n[0];
	  /* and now, response has what we work with. */
	}
	response[8] = 0;
	predict_response.data = response;
	predict_response.length = 8;
#if 0				/* for debugging, hack the output too! */
sc.sam_challenge_label.data = response;
sc.sam_challenge_label.length = strlen(sc.sam_challenge_label.data);
#endif
      }

      psr.magic = KV5M_PREDICTED_SAM_RESPONSE;
      /* string2key on sc.sam_challenge goes in here */
      /* eblock is just to set the enctype */
      {
	retval = krb5_c_string_to_key(context, ENCTYPE_DES_CBC_MD5,
				      &predict_response, 0 /* salt */,
				      &psr.sam_key);
	if (retval) goto cleanup;

	retval = encode_krb5_predicted_sam_response(&psr, &scratch);
	if (retval) goto cleanup;
	
	{
	    size_t enclen;
	    krb5_enc_data tmpdata;

	    if ((retval = krb5_c_encrypt_length(context,
						master_keyblock.enctype,
						scratch->length, &enclen)))
		goto cleanup;

	    if ((tmpdata.ciphertext.data = (char *) malloc(enclen)) == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }
	    tmpdata.ciphertext.length = enclen;

	    if ((retval = krb5_c_encrypt(context, &master_keyblock,
					 /* XXX */ 0, 0, scratch, &tmpdata)))
		goto cleanup;

	    sc.sam_track_id = tmpdata.ciphertext;
	}
	if (retval) goto cleanup;
      }

      sc.sam_response_prompt.data = "Enter the displayed response";
      sc.sam_response_prompt.length = strlen(sc.sam_response_prompt.data);
      sc.sam_pk_for_sad.length = 0;
      sc.sam_nonce = 0;
      /* Generate checksum */
      /*krb5_checksum_size(context, ctype)*/
      /*krb5_calculate_checksum(context,ctype,in,in_length,seed,
	seed_length,outcksum) */
      /*krb5_verify_checksum(context,ctype,cksum,in,in_length,seed,
	seed_length) */
      sc.sam_cksum.contents = (krb5_octet *)
	malloc(krb5_checksum_size(context, CKSUMTYPE_RSA_MD5_DES));
      if (sc.sam_cksum.contents == NULL) return(ENOMEM);

      retval = krb5_calculate_checksum(context, CKSUMTYPE_RSA_MD5_DES,
				       sc.sam_challenge.data,
				       sc.sam_challenge.length,
				       psr.sam_key.contents, /* key */
				       psr.sam_key.length, /* key length */
				       &sc.sam_cksum);
      if (retval) { free(sc.sam_cksum.contents); return(retval); }
      
      retval = encode_krb5_sam_challenge(&sc, &scratch);
      if (retval) goto cleanup;
      pa_data->magic = KV5M_PA_DATA;
      pa_data->pa_type = KRB5_PADATA_SAM_CHALLENGE;
      pa_data->contents = scratch->data;
      pa_data->length = scratch->length;
      
      retval = 0;
      break;
    }

cleanup:
    krb5_free_keyblock_contents(context, &encrypting_key);
    return retval;
}

static krb5_error_code
verify_sam_response(context, client, request, enc_tkt_reply, pa)
    krb5_context	context;
    krb5_db_entry *	client;
    krb5_kdc_req *	request;
    krb5_enc_tkt_part * enc_tkt_reply;
    krb5_pa_data *	pa;
{
    krb5_error_code		retval;
    krb5_data			scratch;
    krb5_sam_response		*sr = 0;
    krb5_predicted_sam_response	*psr = 0;
    krb5_enc_sam_response_enc	*esre = 0;
    krb5_timestamp		timenow;

    scratch.data = pa->contents;
    scratch.length = pa->length;
    
    if ((retval = decode_krb5_sam_response(&scratch, &sr))) {
	scratch.data = 0;
	com_err("krb5kdc", retval, "decode_krb5_sam_response failed");
	goto cleanup;
    }

    {
      krb5_enc_data tmpdata;

      tmpdata.enctype = ENCTYPE_UNKNOWN;
      tmpdata.ciphertext = sr->sam_track_id;

      scratch.length = tmpdata.ciphertext.length;
      if ((scratch.data = (char *) malloc(scratch.length)) == NULL) {
	  retval = ENOMEM;
	  goto cleanup;
      }

      if ((retval = krb5_c_decrypt(context, &master_keyblock, /* XXX */ 0, 0,
				   &tmpdata, &scratch))) {
	  com_err("krb5kdc", retval, "decrypt track_id failed");
	  goto cleanup;
      }
    }

    if ((retval = decode_krb5_predicted_sam_response(&scratch, &psr))) {
	com_err("krb5kdc", retval,
		"decode_krb5_predicted_sam_response failed");
	goto cleanup;
    }

    {
	free(scratch.data);
	scratch.length = sr->sam_enc_nonce_or_ts.ciphertext.length;
	if ((scratch.data = (char *) malloc(scratch.length)) == NULL) {
	    retval = ENOMEM;
	    goto cleanup;
	}

	if ((retval = krb5_c_decrypt(context, &psr->sam_key, /* XXX */ 0,
				     0, &sr->sam_enc_nonce_or_ts, &scratch))) {
	    com_err("krb5kdc", retval, "decrypt nonce_or_ts failed");
	    goto cleanup;
	}
    }

    if ((retval = decode_krb5_enc_sam_response_enc(&scratch, &esre))) {
	com_err("krb5kdc", retval, "decode_krb5_enc_sam_response_enc failed");
	goto cleanup;
    }

    if (esre->sam_timestamp != sr->sam_patimestamp) {
      retval = KRB5KDC_ERR_PREAUTH_FAILED;
      goto cleanup;
    }

    if ((retval = krb5_timeofday(context, &timenow)))
	goto cleanup;
    
    if (labs(timenow - sr->sam_patimestamp) > context->clockskew) {
	retval = KRB5KRB_AP_ERR_SKEW;
	goto cleanup;
    }

    setflag(enc_tkt_reply->flags, TKT_FLG_HW_AUTH);

  cleanup:
    if (retval)
	com_err("krb5kdc", retval, "sam verify failure");
    if (scratch.data) free(scratch.data);
    if (sr) free(sr);
    if (psr) free(psr);
    if (esre) free(esre);

    return retval;
}

/*
 * Copyright 1995 by the Massachusetts Institute of Technology.  All
 * Rights Reserved.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
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

typedef krb5_error_code (*pa_function)(krb5_context,
				       krb5_kdc_req *request,
				       krb5_pa_data *in_padata,
				       krb5_pa_data **out_padata,
				       krb5_data *salt,
				       krb5_keyblock *as_key,
				       krb5_prompter_fct prompter_fct,
				       void *prompter_data,
				       krb5_gic_get_as_key_fct gak_fct,
				       void *gak_data);
				 
typedef struct _pa_types_t {
    krb5_preauthtype type;
    pa_function fct;
    int flags;
} pa_types_t;

#define PA_REAL 0x0001
#define PA_INFO 0x0002

static
krb5_error_code pa_salt(krb5_context context,
			krb5_kdc_req *request,
			krb5_pa_data *in_padata,
			krb5_pa_data **out_padata,
			krb5_data *salt,
			krb5_keyblock *as_key,
			krb5_prompter_fct prompter, void *prompter_data,
			krb5_gic_get_as_key_fct gak_fct, void *gak_data)
{
    krb5_error_code ret;
    krb5_data tmp;

    /* screw the abstraction.  If there was a *reasonable* copy_data,
       I'd use it.  But I'm inside the library, which is the twilight
       zone of source code, so I can do anything. */

    tmp.length = in_padata->length;
    if (tmp.length) {
	if ((tmp.data = malloc(tmp.length)) == NULL)
	    return ENOMEM;
	memcpy(tmp.data, in_padata->contents, tmp.length);
    } else {
	tmp.data = NULL;
    }

    *salt = tmp;

    /* assume that no other salt was allocated */

    if (in_padata->pa_type == KRB5_PADATA_AFS3_SALT)
	salt->length = -1;

    return(0);
}

static
krb5_error_code pa_enc_timestamp(krb5_context context,
				 krb5_kdc_req *request,
				 krb5_pa_data *in_padata,
				 krb5_pa_data **out_padata,
				 krb5_data *salt,
				 krb5_keyblock *as_key,
				 krb5_prompter_fct prompter,
				 void *prompter_data,
				 krb5_gic_get_as_key_fct gak_fct,
				 void *gak_data)
{
    krb5_error_code ret;
    krb5_pa_enc_ts pa_enc;
    krb5_data *tmp;
    krb5_enc_data enc_data;
    krb5_pa_data *pa;
   
    /*
     * We need to use the password as part or all of the key.
     * If as_key contains info, it should be the users pass phrase.
     * If not, get the password before issuing the challenge.
     */
    if (as_key->length == 0) {
       if (ret = ((*gak_fct)(context, request->client,
			     request->ktype[0], prompter, prompter_data,
			     salt, as_key, gak_data)))
           return(ret);
    }

    /* now get the time of day, and encrypt it accordingly */

    if (ret = krb5_us_timeofday(context, &pa_enc.patimestamp, &pa_enc.pausec))
	return(ret);

    if (ret = encode_krb5_pa_enc_ts(&pa_enc, &tmp))
	return(ret);

    ret = krb5_encrypt_helper(context, as_key,
			      KRB5_KEYUSAGE_AS_REQ_PA_ENC_TS,
			      tmp, &enc_data);

    krb5_free_data(context, tmp);

    if (ret) {
	krb5_xfree(enc_data.ciphertext.data);
	return(ret);
    }

    ret = encode_krb5_enc_data(&enc_data, &tmp);

    krb5_xfree(enc_data.ciphertext.data);

    if (ret)
	return(ret);

    if ((pa = (krb5_pa_data *) malloc(sizeof(krb5_pa_data))) == NULL) {
	krb5_free_data(context, tmp);
	return(ENOMEM);
    }

    pa->magic = KV5M_PA_DATA;
    pa->pa_type = KRB5_PADATA_ENC_TIMESTAMP;
    pa->length = tmp->length;
    pa->contents = (krb5_octet *) tmp->data;

    *out_padata = pa;

    krb5_xfree(tmp);

    return(0);
}

static 
char *sam_challenge_banner(sam_type)
     krb5_int32 sam_type;
{
    char *label;

    switch (sam_type) {
    case PA_SAM_TYPE_ENIGMA:	/* Enigma Logic */
	label = "Challenge for Enigma Logic mechanism";
	break;
    case PA_SAM_TYPE_DIGI_PATH: /*  Digital Pathways */
    case PA_SAM_TYPE_DIGI_PATH_HEX: /*  Digital Pathways */
	label = "Challenge for Digital Pathways mechanism";
	break;
    case PA_SAM_TYPE_ACTIVCARD_DEC: /*  Digital Pathways */
    case PA_SAM_TYPE_ACTIVCARD_HEX: /*  Digital Pathways */
	label = "Challenge for Activcard mechanism";
	break;
    case PA_SAM_TYPE_SKEY_K0:	/*  S/key where  KDC has key 0 */
	label = "Challenge for Enhanced S/Key mechanism";
	break;
    case PA_SAM_TYPE_SKEY:	/*  Traditional S/Key */
	label = "Challenge for Traditional S/Key mechanism";
	break;
    case PA_SAM_TYPE_SECURID:	/*  Security Dynamics */
	label = "Challenge for Security Dynamics mechanism";
	break;
    case PA_SAM_TYPE_SECURID_PREDICT:	/* predictive Security Dynamics */
	label = "Challenge for Security Dynamics mechanism";
	break;
    default:
	label = "Challenge from authentication server";
	break;
    }

    return(label);
}

/* this macro expands to the int,ptr necessary for "%.*s" in an sprintf */

#define SAMDATA(kdata, str, maxsize) \
	(kdata.length)? \
	((((kdata.length)<=(maxsize))?(kdata.length):(strlen(str)))): \
	strlen(str), \
	(kdata.length)? \
	((((kdata.length)<=(maxsize))?(kdata.data):(str))):(str)

/* XXX Danger! This code is not in sync with the kerberos-password-02
   draft.  This draft cannot be implemented as written.  This code is
   compatible with earlier versions of mit krb5 and cygnus kerbnet. */

static
krb5_error_code pa_sam(krb5_context context,
		       krb5_kdc_req *request,
		       krb5_pa_data *in_padata,
		       krb5_pa_data **out_padata,
		       krb5_data *salt,
		       krb5_keyblock *as_key,
		       krb5_prompter_fct prompter,
		       void *prompter_data,
		       krb5_gic_get_as_key_fct gak_fct,
		       void *gak_data)
{
    krb5_error_code		ret;
    krb5_data			tmpsam;
    char			name[100], banner[100];
    char			prompt[100], response[100];
    krb5_data			response_data;
    krb5_prompt			kprompt;
    krb5_data			defsalt;
    krb5_sam_challenge		*sam_challenge = 0;
    krb5_sam_response		sam_response;
    /* these two get encrypted and stuffed in to sam_response */
    krb5_enc_sam_response_enc	enc_sam_response_enc;
    krb5_keyblock *		sam_use_key = 0;
    krb5_data *			scratch;
    krb5_pa_data *		pa;

    tmpsam.length = in_padata->length;
    tmpsam.data = (char *) in_padata->contents;
    if (ret = decode_krb5_sam_challenge(&tmpsam, &sam_challenge))
	return(ret);

    if (sam_challenge->sam_flags & KRB5_SAM_MUST_PK_ENCRYPT_SAD) {
	krb5_xfree(sam_challenge);
	return(KRB5_SAM_UNSUPPORTED);
    }

    sprintf(name, "%.*s",
	    SAMDATA(sam_challenge->sam_type_name, "SAM Authentication",
		    sizeof(name) - 1));

    sprintf(banner, "%.*s",
	    SAMDATA(sam_challenge->sam_challenge_label,
		    sam_challenge_banner(sam_challenge->sam_type),
		    sizeof(banner)-1));

    /* sprintf(prompt, "Challenge is [%s], %s: ", challenge, prompt); */
    sprintf(prompt, "%s%.*s%s%.*s",
	    sam_challenge->sam_challenge.length?"Challenge is [":"",
	    SAMDATA(sam_challenge->sam_challenge, "", 20),
	    sam_challenge->sam_challenge.length?"], ":"",
	    SAMDATA(sam_challenge->sam_response_prompt, "passcode", 55));

    response_data.data = response;
    response_data.length = sizeof(response);

    kprompt.prompt = prompt;
    kprompt.hidden = sam_challenge->sam_challenge.length?0:1;
    kprompt.reply = &response_data;

    if (ret = ((*prompter)(context, prompter_data, name,
			   banner, 1, &kprompt))) {
	krb5_xfree(sam_challenge);
	return(ret);
    }

    enc_sam_response_enc.sam_nonce = sam_challenge->sam_nonce;
    if (sam_challenge->sam_flags & KRB5_SAM_SEND_ENCRYPTED_SAD) {
	enc_sam_response_enc.sam_passcode = response_data;
    } else if (sam_challenge->sam_flags & KRB5_SAM_USE_SAD_AS_KEY) {
	if (sam_challenge->sam_nonce == 0) {
	    if (ret = krb5_us_timeofday(context, 
					&enc_sam_response_enc.sam_timestamp,
					&enc_sam_response_enc.sam_usec)) {
		krb5_xfree(sam_challenge);
		return(ret);
	    }

	    sam_response.sam_patimestamp = enc_sam_response_enc.sam_timestamp;
	}

	/* process the key as password */

	if (as_key->length) {
	    krb5_free_keyblock_contents(context, as_key);
	    as_key->length = 0;
	}

#if 0
	if ((salt->length == -1) && (salt->data == NULL)) {
	    if (ret = krb5_principal2salt(context, request->client,
					  &defsalt)) {
		krb5_xfree(sam_challenge);
		return(ret);
	    }

	    salt = &defsalt;
	} else {
	    defsalt.length = 0;
	}
#else
	defsalt.length = 0;
	salt = NULL;
#endif
	    
	/* XXX the server uses this fixed enctype, so we will, too. */

	ret = krb5_c_string_to_key(context, ENCTYPE_DES_CBC_MD5,
				   &response_data, salt, as_key);

	if (defsalt.length)
	    krb5_xfree(defsalt.data);

	if (ret) {
	    krb5_xfree(sam_challenge);
	    return(ret);
	}

	enc_sam_response_enc.sam_passcode.length = 0;
    }

    /* copy things from the challenge */
    sam_response.sam_nonce = sam_challenge->sam_nonce;
    sam_response.sam_flags = sam_challenge->sam_flags;
    sam_response.sam_track_id = sam_challenge->sam_track_id;
    sam_response.sam_type = sam_challenge->sam_type;
    sam_response.magic = KV5M_SAM_RESPONSE;

    krb5_xfree(sam_challenge);

    /* encode the encoded part of the response */
    if (ret = encode_krb5_enc_sam_response_enc(&enc_sam_response_enc,
					       &scratch))
	return(ret);

    ret = krb5_encrypt_data(context, as_key, 0, scratch,
			    &sam_response.sam_enc_nonce_or_ts);

    krb5_free_data(context, scratch);

    if (ret)
	return(ret);

    /* sam_enc_key is reserved for future use */
    sam_response.sam_enc_key.ciphertext.length = 0;

    if ((pa = malloc(sizeof(krb5_pa_data))) == NULL)
	return(ENOMEM);

    if (ret = encode_krb5_sam_response(&sam_response, &scratch)) {
	free(pa);
	return(ret);
    }

    pa->magic = KV5M_PA_DATA;
    pa->pa_type = KRB5_PADATA_SAM_RESPONSE;
    pa->length = scratch->length;
    pa->contents = (krb5_octet *) scratch->data;

    *out_padata = pa;

    return(0);
}

static pa_types_t pa_types[] = {
    {
	KRB5_PADATA_PW_SALT,
	pa_salt,
	PA_INFO,
    },
    {
	KRB5_PADATA_AFS3_SALT,
	pa_salt,
	PA_INFO,
    },
    {
	KRB5_PADATA_ENC_TIMESTAMP,
	pa_enc_timestamp,
	PA_REAL,
    },
    {
	KRB5_PADATA_SAM_CHALLENGE,
	pa_sam,
	PA_REAL,
    },
    {
	-1,
	NULL,
	0,
    },
};

krb5_error_code
krb5_do_preauth(krb5_context context,
		krb5_kdc_req *request,
		krb5_pa_data **in_padata, krb5_pa_data ***out_padata,
		krb5_data *salt,
		krb5_keyblock *as_key,
		krb5_prompter_fct prompter, void *prompter_data,
		krb5_gic_get_as_key_fct gak_fct, void *gak_data)
{
    int h, i, j, out_pa_list_size;
    krb5_pa_data *out_pa, **out_pa_list;
    krb5_data scratch;
    krb5_etype_info etype_info = NULL;
    krb5_error_code ret;
    static int paorder[] = { PA_INFO, PA_REAL };
    int realdone;

    if (in_padata == NULL) {
	*out_padata = NULL;
	return(0);
    }

    out_pa_list = NULL;
    out_pa_list_size = 0;

    /* first do all the informational preauths, then the first real one */

    for (h=0; h<(sizeof(paorder)/sizeof(paorder[0])); h++) {
	realdone = 0;
	for (i=0; in_padata[i] && !realdone; i++) {
	    /*
	     * This is really gross, but is necessary to prevent
	     * lossge when talking to a 1.0.x KDC, which returns an
	     * erroneous PA-PW-SALT when it returns a KRB-ERROR
	     * requiring additional preauth.
	     */
	    switch (in_padata[i]->pa_type) {
	    case KRB5_PADATA_ETYPE_INFO:
		if (etype_info)
		    continue;
		scratch.length = in_padata[i]->length;
		scratch.data = (char *) in_padata[i]->contents;
		ret = decode_krb5_etype_info(&scratch, &etype_info);
		if (ret) {
		    if (out_pa_list) {
			out_pa_list[out_pa_list_size++] = NULL;
			krb5_free_pa_data(context, out_pa_list);
		    }
		    return ret;
		}
		salt->data = (char *) etype_info[0]->salt;
		salt->length = etype_info[0]->length;
		break;
	    case KRB5_PADATA_PW_SALT:
	    case KRB5_PADATA_AFS3_SALT:
		if (etype_info)
		    continue;
		break;
	    default:
		;
	    }
	    for (j=0; pa_types[j].type >= 0; j++) {
		if ((in_padata[i]->pa_type == pa_types[j].type) &&
		    (pa_types[j].flags & paorder[h])) {
		    out_pa = NULL;

		    if (ret = ((*pa_types[j].fct)(context, request,
						  in_padata[i], &out_pa,
						  salt, as_key,
						  prompter, prompter_data,
						  gak_fct, gak_data))) {
			if (out_pa_list) {
			    out_pa_list[out_pa_list_size++] = NULL;
			    krb5_free_pa_data(context, out_pa_list);
			}
			if (etype_info)
			    krb5_free_etype_info(context, etype_info);
			return(ret);
		    }

		    if (out_pa) {
			if (out_pa_list == NULL) {
			    if ((out_pa_list =
				 (krb5_pa_data **)
				 malloc(2*sizeof(krb5_pa_data *)))
				== NULL)
				return(ENOMEM);
			} else {
			    if ((out_pa_list =
				 (krb5_pa_data **)
				 realloc(out_pa_list,
					 (out_pa_list_size+2)*
					 sizeof(krb5_pa_data *)))
				== NULL)
				/* XXX this will leak the pointers which
				   have already been allocated.  oh well. */
				return(ENOMEM);
			}
			
			out_pa_list[out_pa_list_size++] = out_pa;
		    }
		    if (h == PA_REAL)
			realdone = 1;
		}
	    }
	}
    }

    if (out_pa_list)
	out_pa_list[out_pa_list_size++] = NULL;

    *out_padata = out_pa_list;

    return(0);
}

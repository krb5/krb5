/*
 * COPYRIGHT (C) 2006,2007
 * THE REGENTS OF THE UNIVERSITY OF MICHIGAN
 * ALL RIGHTS RESERVED
 *
 * Permission is granted to use, copy, create derivative works
 * and redistribute this software and such derivative works
 * for any purpose, so long as the name of The University of
 * Michigan is not used in any advertising or publicity
 * pertaining to the use of distribution of this software
 * without specific, written prior authorization.  If the
 * above copyright notice or any other identification of the
 * University of Michigan is included in any copy of any
 * portion of this software, then the disclaimer below must
 * also be included.
 *
 * THIS SOFTWARE IS PROVIDED AS IS, WITHOUT REPRESENTATION
 * FROM THE UNIVERSITY OF MICHIGAN AS TO ITS FITNESS FOR ANY
 * PURPOSE, AND WITHOUT WARRANTY BY THE UNIVERSITY OF
 * MICHIGAN OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING
 * WITHOUT LIMITATION THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
 * REGENTS OF THE UNIVERSITY OF MICHIGAN SHALL NOT BE LIABLE
 * FOR ANY DAMAGES, INCLUDING SPECIAL, INDIRECT, INCIDENTAL, OR
 * CONSEQUENTIAL DAMAGES, WITH RESPECT TO ANY CLAIM ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OF THE SOFTWARE, EVEN
 * IF IT HAS BEEN OR IS HEREAFTER ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGES.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "pkinit.h"

static krb5_error_code
pkinit_server_get_edata(krb5_context context,
			krb5_kdc_req * request,
			struct _krb5_db_entry_new * client,
			struct _krb5_db_entry_new * server,
			preauth_get_entry_data_proc server_get_entry_data,
			void *pa_plugin_context,
			krb5_pa_data * data);

static krb5_error_code
pkinit_server_verify_padata(krb5_context context,
			    struct _krb5_db_entry_new * client,
			    krb5_data *req_pkt,
			    krb5_kdc_req * request,
			    krb5_enc_tkt_part * enc_tkt_reply,
			    krb5_pa_data * data,
			    preauth_get_entry_data_proc server_get_entry_data,
			    void *pa_plugin_context,
			    void **pa_request_context,
			    krb5_data **e_data,
			    krb5_authdata ***authz_data);

static krb5_error_code
pkinit_server_return_padata(krb5_context context,
			    krb5_pa_data * padata,
			    struct _krb5_db_entry_new * client,
			    krb5_data *req_pkt,
			    krb5_kdc_req * request,
			    krb5_kdc_rep * reply,
			    struct _krb5_key_data * client_key,
			    krb5_keyblock * encrypting_key,
			    krb5_pa_data ** send_pa,
			    preauth_get_entry_data_proc server_get_entry_data,
			    void *pa_plugin_context,
			    void **pa_request_context);

static int pkinit_server_get_flags
	(krb5_context kcontext, krb5_preauthtype patype);

static krb5_error_code pkinit_init_kdc_req_context
	(krb5_context, void **blob);

static void pkinit_fini_kdc_req_context
	(krb5_context context, void *blob);

static int pkinit_server_plugin_init_realm
	(krb5_context context, const char *realmname,
	 pkinit_kdc_context *pplgctx);

static void pkinit_server_plugin_fini_realm
	(krb5_context context, pkinit_kdc_context plgctx);

static int pkinit_server_plugin_init
	(krb5_context context, void **blob, const char **realmnames);

static void pkinit_server_plugin_fini
	(krb5_context context, void *blob);

static pkinit_kdc_context pkinit_find_realm_context
	(krb5_context context, void *pa_plugin_context, krb5_principal princ);

static krb5_error_code
pkinit_create_edata(krb5_context context,
		    pkinit_plg_crypto_context plg_cryptoctx,
		    pkinit_req_crypto_context req_cryptoctx,
		    pkinit_identity_crypto_context id_cryptoctx,
		    pkinit_plg_opts *opts,
		    krb5_error_code err_code,
		    krb5_data **e_data)
{
    krb5_error_code retval = KRB5KRB_ERR_GENERIC;

    pkiDebug("pkinit_create_edata: creating edata for error %d (%s)\n",
	     err_code, error_message(err_code));
    switch(err_code) {
	case KRB5KDC_ERR_CANT_VERIFY_CERTIFICATE:
	    retval = pkinit_create_td_trusted_certifiers(context,
		plg_cryptoctx, req_cryptoctx, id_cryptoctx, e_data);
	    break;
	case KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED:
	    retval = pkinit_create_td_dh_parameters(context, plg_cryptoctx,
		req_cryptoctx, id_cryptoctx, opts, e_data);
	    break;
	case KRB5KDC_ERR_INVALID_CERTIFICATE:
	case KRB5KDC_ERR_REVOKED_CERTIFICATE:
	    retval = pkinit_create_td_invalid_certificate(context,
		plg_cryptoctx, req_cryptoctx, id_cryptoctx, e_data);
	    break;
	default:
	    pkiDebug("no edata needed for error %d (%s)\n",
		     err_code, error_message(err_code));
	    retval = 0;
	    goto cleanup;
    }

cleanup:

    return retval;
}

static krb5_error_code
pkinit_server_get_edata(krb5_context context,
			krb5_kdc_req * request,
			struct _krb5_db_entry_new * client,
			struct _krb5_db_entry_new * server,
			preauth_get_entry_data_proc server_get_entry_data,
			void *pa_plugin_context,
			krb5_pa_data * data)
{
    krb5_error_code retval = 0;
    pkinit_kdc_context plgctx = NULL;

    pkiDebug("pkinit_get_edata: entered!\n");

    /*
     * If we don't have a realm context for the given realm,
     * don't tell the client that we support pkinit! 
     */
    plgctx = pkinit_find_realm_context(context, pa_plugin_context,
				       request->server);
    if (plgctx == NULL)
	retval = EINVAL;

    return retval;
}

static krb5_error_code
pkinit_server_verify_padata(krb5_context context,
			    struct _krb5_db_entry_new * client,
			    krb5_data *req_pkt,
			    krb5_kdc_req * request,
			    krb5_enc_tkt_part * enc_tkt_reply,
			    krb5_pa_data * data,
			    preauth_get_entry_data_proc server_get_entry_data,
			    void *pa_plugin_context,
			    void **pa_request_context,
			    krb5_data **e_data,
			    krb5_authdata ***authz_data)
{
    krb5_error_code retval = 0;	
    krb5_octet_data authp_data = {0, 0, NULL}, krb5_authz = {0, 0, NULL};
    krb5_pa_pk_as_req *reqp = NULL;
    krb5_pa_pk_as_req_draft9 *reqp9 = NULL;
    krb5_auth_pack *auth_pack = NULL;
    krb5_auth_pack_draft9 *auth_pack9 = NULL;
    pkinit_kdc_context plgctx = NULL;
    pkinit_kdc_req_context reqctx;
    krb5_preauthtype pa_type;
    krb5_principal tmp_client;
    krb5_checksum cksum = {0, 0, 0, NULL};
    krb5_data *der_req = NULL;
    int valid_eku = 0, valid_san = 0;
    krb5_authdata **my_authz_data = NULL;
    krb5_kdc_req *tmp_as_req = NULL;
    krb5_data k5data;

    pkiDebug("pkinit_verify_padata: entered!\n");

    if (data == NULL || data->length <= 0 || data->contents == NULL)
	return 0;

    if (pa_plugin_context == NULL || e_data == NULL)
	return EINVAL;

    plgctx = pkinit_find_realm_context(context, pa_plugin_context,
				       request->server);
    if (plgctx == NULL)
	return 0;

#ifdef DEBUG_ASN1
    print_buffer_bin(data->contents, data->length, "/tmp/kdc_as_req");
#endif
    /* create a per-request context */
    retval = pkinit_init_kdc_req_context(context, (void **)&reqctx);
    if (retval)
	goto cleanup;
    reqctx->pa_type = data->pa_type;

    PADATA_TO_KRB5DATA(data, &k5data);

    switch ((int)data->pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    pkiDebug("processing KRB5_PADATA_PK_AS_REQ\n");
	    pa_type = (int)data->pa_type;
	    retval = k5int_decode_krb5_pa_pk_as_req(&k5data, &reqp);
	    if (retval) {
		pkiDebug("decode_krb5_pa_pk_as_req failed\n");
		goto cleanup;
	    }

	    retval = cms_signeddata_verify(context, plgctx->cryptoctx,
		reqctx->cryptoctx, plgctx->idctx, CMS_SIGN_CLIENT,
		plgctx->opts->require_crl_checking,
		reqp->signedAuthPack.data, reqp->signedAuthPack.length,
		&authp_data.data, &authp_data.length, &krb5_authz.data, 
		&krb5_authz.length);
	    break;
	case KRB5_PADATA_PK_AS_REP_OLD:
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    pkiDebug("processing KRB5_PADATA_PK_AS_REQ_OLD\n");
	    pa_type = KRB5_PADATA_PK_AS_REQ_OLD;
	    retval = k5int_decode_krb5_pa_pk_as_req_draft9(&k5data, &reqp9);
	    if (retval) {
		pkiDebug("decode_krb5_pa_pk_as_req_draft9 failed\n");
		goto cleanup;
	    }

	    retval = cms_signeddata_verify(context, plgctx->cryptoctx,
		reqctx->cryptoctx, plgctx->idctx, CMS_SIGN_DRAFT9,
		plgctx->opts->require_crl_checking,
		reqp9->signedAuthPack.data, reqp9->signedAuthPack.length,
		&authp_data.data, &authp_data.length, &krb5_authz.data, 
		&krb5_authz.length);
	    break;
	default:
	    pkiDebug("unrecognized pa_type = %d\n", data->pa_type);
	    retval = EINVAL;
	    goto cleanup;
    }
    if (retval) {
	pkiDebug("pkcs7_signeddata_verify failed\n");
	goto cleanup;
    }

    retval = verify_id_pkinit_san(context, plgctx->cryptoctx, reqctx->cryptoctx,
	plgctx->idctx, data->pa_type, plgctx->opts->allow_upn, &tmp_client,
	NULL, &valid_san);
    if (retval)
	goto cleanup;
    if (!valid_san) {
	pkiDebug("failed to verify id-pkinit-san\n");
	retval = KRB5KDC_ERR_CLIENT_NOT_TRUSTED;
	goto cleanup;
    } else {
	if (tmp_client != NULL) {
	    retval = krb5_principal_compare(context, request->client,
					    tmp_client);
	    krb5_free_principal(context, tmp_client);
	    if (!retval) {
		pkiDebug("identity in the certificate does not match "
			 "the requested principal\n");
		retval = KRB5KDC_ERR_CLIENT_NAME_MISMATCH;
		goto cleanup;
	    }
	} else {
	    pkiDebug("didn't find Kerberos identity in certificate\n");
	    retval = KRB5KDC_ERR_CLIENT_NOT_TRUSTED;
	    goto cleanup;
	}
    }

    retval = verify_id_pkinit_eku(context, plgctx->cryptoctx, reqctx->cryptoctx,
	plgctx->idctx, data->pa_type, plgctx->opts->require_eku, &valid_eku);
    if (retval)
	goto cleanup;
    if (!valid_eku) {
	pkiDebug("failed to verify id-pkinit-KPClientAuth\n");
	retval = KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE;
	goto cleanup;
    }

#ifdef DEBUG_ASN1
    print_buffer_bin(authp_data.data, authp_data.length, "/tmp/kdc_auth_pack");
#endif

    OCTETDATA_TO_KRB5DATA(&authp_data, &k5data);
    switch ((int)data->pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    retval = k5int_decode_krb5_auth_pack(&k5data, &auth_pack);
	    if (retval) {
		pkiDebug("failed to decode krb5_auth_pack\n");
		goto cleanup;
	    }

	    /* check dh parameters */
	    if (auth_pack->clientPublicValue != NULL) {	
		retval = server_check_dh(context, plgctx->cryptoctx,
		    reqctx->cryptoctx, plgctx->idctx,
		    &auth_pack->clientPublicValue->algorithm.parameters,
		    plgctx->opts->dh_min_bits);

		if (retval) {
		    pkiDebug("bad dh parameters\n");
		    goto cleanup;
		}
	    }
	    /*
	     * The KDC may have modified the request after decoding it.
	     * We need to compute the checksum on the data that
	     * came from the client.  Therefore, we use the original
	     * packet contents.
	     */
	    retval = decode_krb5_as_req(req_pkt, &tmp_as_req); 
	    if (retval) {
		pkiDebug("decode_krb5_as_req returned %d\n", (int)retval);
		goto cleanup;
	    }
		
	    retval = encode_krb5_kdc_req_body(tmp_as_req, &der_req);
	    if (retval) {
		pkiDebug("encode_krb5_kdc_req_body returned %d\n", (int) retval);
		goto cleanup;
	    }
	    retval = krb5_c_make_checksum(context, CKSUMTYPE_NIST_SHA, NULL,
					  0, der_req, &cksum);
	    if (retval) {
		pkiDebug("unable to calculate AS REQ checksum\n");
		goto cleanup;
	    }
	    if (cksum.length != auth_pack->pkAuthenticator.paChecksum.length ||
		memcmp(cksum.contents,
		       auth_pack->pkAuthenticator.paChecksum.contents,
		       cksum.length)) {
		pkiDebug("failed to match the checksum\n");
#ifdef DEBUG_CKSUM
		pkiDebug("calculating checksum on buf size (%d)\n",
			 req_pkt->length);
		print_buffer(req_pkt->data, req_pkt->length);
		pkiDebug("received checksum type=%d size=%d ",
			auth_pack->pkAuthenticator.paChecksum.checksum_type,
			auth_pack->pkAuthenticator.paChecksum.length);
		print_buffer(auth_pack->pkAuthenticator.paChecksum.contents,
			     auth_pack->pkAuthenticator.paChecksum.length);
		pkiDebug("expected checksum type=%d size=%d ",
			 cksum.checksum_type, cksum.length);
		print_buffer(cksum.contents, cksum.length);
#endif

		retval = KRB5KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED;
		goto cleanup;
	    }

	    /* check if kdcPkId present and match KDC's subjectIdentifier */
	    if (reqp->kdcPkId.data != NULL) {
		int valid_kdcPkId = 0;
		retval = pkinit_check_kdc_pkid(context, plgctx->cryptoctx,
		    reqctx->cryptoctx, plgctx->idctx,
		    reqp->kdcPkId.data, reqp->kdcPkId.length, &valid_kdcPkId);
		if (retval)
		    goto cleanup;
		if (!valid_kdcPkId)
		    pkiDebug("kdcPkId in AS_REQ does not match KDC's cert"
			     "RFC says to ignore and proceed\n");

	    }
	    /* remember the decoded auth_pack for verify_padata routine */
	    reqctx->rcv_auth_pack = auth_pack;
	    auth_pack = NULL;
	    break;
	case KRB5_PADATA_PK_AS_REP_OLD:
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    retval = k5int_decode_krb5_auth_pack_draft9(&k5data, &auth_pack9);
	    if (retval) {
		pkiDebug("failed to decode krb5_auth_pack_draft9\n");
		goto cleanup;
	    }
	    if (auth_pack9->clientPublicValue != NULL) {	
		retval = server_check_dh(context, plgctx->cryptoctx,
		    reqctx->cryptoctx, plgctx->idctx,
		    &auth_pack9->clientPublicValue->algorithm.parameters,
		    plgctx->opts->dh_min_bits);

		if (retval) {
		    pkiDebug("bad dh parameters\n");
		    goto cleanup;
		}
	    }
	    /* remember the decoded auth_pack for verify_padata routine */
	    reqctx->rcv_auth_pack9 = auth_pack9;
	    auth_pack9 = NULL;
	    break;
    }

    /* return authorization data to be included in the ticket */
    my_authz_data = malloc(2 * sizeof(*my_authz_data));
    if (my_authz_data == NULL) {
	retval = ENOMEM;
	pkiDebug("Couldn't allocate krb5_authdata ptr array\n");
	goto cleanup;
    }
    my_authz_data[1] = NULL;
    my_authz_data[0] = malloc(sizeof(krb5_authdata));
    if (my_authz_data[0] == NULL) {
	retval = ENOMEM;
	pkiDebug("Couldn't allocate krb5_authdata\n");
	free(my_authz_data);
	goto cleanup;
    }
    my_authz_data[0]->magic = KV5M_AUTHDATA;
    my_authz_data[0]->ad_type = 1;
    my_authz_data[0]->contents = krb5_authz.data;
    krb5_authz.data = NULL; /* Don't free during cleanup! */
    my_authz_data[0]->length = krb5_authz.length;
    *authz_data = my_authz_data;
    pkiDebug("Returning %d bytes of authorization data\n", krb5_authz.length);
    *authz_data = my_authz_data;

    /* remember to set the PREAUTH flag in the reply */
    enc_tkt_reply->flags |= TKT_FLG_PRE_AUTH;
    *pa_request_context = reqctx;
    reqctx = NULL;

  cleanup:
    if (retval && data->pa_type == KRB5_PADATA_PK_AS_REQ) {
	pkiDebug("pkinit_verify_padata failed: creating e-data\n");
	if (pkinit_create_edata(context, plgctx->cryptoctx, reqctx->cryptoctx,
		plgctx->idctx, plgctx->opts, retval, e_data))
	    pkiDebug("pkinit_create_edata failed\n");
    }

    switch ((int)data->pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    free_krb5_pa_pk_as_req(&reqp);
	    if (cksum.contents != NULL)
		free(cksum.contents);
	    if (der_req != NULL)
		 krb5_free_data(context, der_req);
	    break;
	case KRB5_PADATA_PK_AS_REP_OLD:
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    free_krb5_pa_pk_as_req_draft9(&reqp9);
    }
    if (tmp_as_req != NULL)
	krb5_free_kdc_req(context, tmp_as_req); 
    if (authp_data.data != NULL)
	free(authp_data.data);
    if (krb5_authz.data != NULL)
	free(krb5_authz.data);
    if (reqctx != NULL)
	pkinit_fini_kdc_req_context(context, reqctx);
    if (auth_pack != NULL) {
	if (auth_pack->clientPublicValue->algorithm.algorithm.data != NULL)
	    free(auth_pack->clientPublicValue->algorithm.algorithm.data);
	free_krb5_auth_pack(&auth_pack);
    }
    if (auth_pack9 != NULL)
	free_krb5_auth_pack_draft9(context, &auth_pack9);

    return retval;
}

static krb5_error_code
pkinit_server_return_padata(krb5_context context,
			    krb5_pa_data * padata,
			    struct _krb5_db_entry_new * client,
			    krb5_data *req_pkt,
			    krb5_kdc_req * request,
			    krb5_kdc_rep * reply,
			    struct _krb5_key_data * client_key,
			    krb5_keyblock * encrypting_key,
			    krb5_pa_data ** send_pa,
			    preauth_get_entry_data_proc server_get_entry_data,
			    void *pa_plugin_context,
			    void **pa_request_context)
{
    krb5_error_code retval = 0;
    krb5_data scratch = {0, 0, NULL};
    krb5_pa_pk_as_req *reqp = NULL;
    krb5_pa_pk_as_req_draft9 *reqp9 = NULL;
    int i = 0;

    unsigned char *subjectPublicKey = NULL;
    unsigned char *dh_pubkey = NULL, *server_key = NULL;
    unsigned int subjectPublicKey_len = 0;
    unsigned int server_key_len = 0, dh_pubkey_len = 0;

    krb5_kdc_dh_key_info dhkey_info;
    krb5_data *encoded_dhkey_info = NULL;
    krb5_pa_pk_as_rep *rep = NULL;
    krb5_pa_pk_as_rep_draft9 *rep9 = NULL;
    krb5_data *out_data = NULL;

    krb5_enctype enctype = -1;

    krb5_reply_key_pack *key_pack = NULL;
    krb5_reply_key_pack_draft9 *key_pack9 = NULL;
    krb5_data *encoded_key_pack = NULL;
    unsigned int num_types;
    krb5_cksumtype *cksum_types = NULL;

    pkinit_kdc_context plgctx;
    pkinit_kdc_req_context reqctx;

    *send_pa = NULL;
    if (padata == NULL || padata->length <= 0 || padata->contents == NULL)
	return 0;

    if (pa_request_context == NULL || *pa_request_context == NULL) {
	pkiDebug("missing request context \n");
	return EINVAL;
    }
    
    plgctx = pkinit_find_realm_context(context, pa_plugin_context,
				       request->server);
    if (plgctx == NULL) {
	pkiDebug("Unable to locate correct realm context\n");
	return ENOENT;
    }

    pkiDebug("pkinit_return_padata: entered!\n");
    reqctx = (pkinit_kdc_req_context)*pa_request_context;

    if (encrypting_key->contents) {
	free(encrypting_key->contents);
	encrypting_key->length = 0;
	encrypting_key->contents = NULL;
    }

    for(i = 0; i < request->nktypes; i++) {
	enctype = request->ktype[0];
	if (!krb5_c_valid_enctype(enctype))
	    continue;
	else {
	    pkiDebug("KDC picked etype = %d\n", enctype);
	    break;
	}
    }
    if (i == request->nktypes) {
	retval = KRB5KDC_ERR_ETYPE_NOSUPP;
	goto cleanup;
    }

    switch((int)reqctx->pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    init_krb5_pa_pk_as_rep(&rep);
	    if (rep == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }
	    /* let's assume it's RSA. we'll reset it to DH if needed */
	    rep->choice = choice_pa_pk_as_rep_encKeyPack;
	    break;
	case KRB5_PADATA_PK_AS_REP_OLD:
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    init_krb5_pa_pk_as_rep_draft9(&rep9);
	    if (rep9 == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }
	    rep9->choice = choice_pa_pk_as_rep_draft9_encKeyPack;
	    break;
	default:
	    retval = KRB5KDC_ERR_PREAUTH_FAILED;
	    goto cleanup;
    }

    if (reqctx->rcv_auth_pack != NULL &&
	    reqctx->rcv_auth_pack->clientPublicValue != NULL) {
	subjectPublicKey =
	    reqctx->rcv_auth_pack->clientPublicValue->subjectPublicKey.data;
	subjectPublicKey_len =
	    reqctx->rcv_auth_pack->clientPublicValue->subjectPublicKey.length;
	rep->choice = choice_pa_pk_as_rep_dhInfo;
    } else if (reqctx->rcv_auth_pack9 != NULL &&
		reqctx->rcv_auth_pack9->clientPublicValue != NULL) {
	subjectPublicKey =
	    reqctx->rcv_auth_pack9->clientPublicValue->subjectPublicKey.data;
	subjectPublicKey_len =
	    reqctx->rcv_auth_pack9->clientPublicValue->subjectPublicKey.length;
	rep9->choice = choice_pa_pk_as_rep_draft9_dhSignedData;
    }

    /* if this DH, then process finish computing DH key */
    if (rep != NULL && (rep->choice == choice_pa_pk_as_rep_dhInfo ||
	    rep->choice == choice_pa_pk_as_rep_draft9_dhSignedData)) {
	pkiDebug("received DH key delivery AS REQ\n");
	retval = server_process_dh(context, plgctx->cryptoctx,
	    reqctx->cryptoctx, plgctx->idctx, subjectPublicKey,
	    subjectPublicKey_len, &dh_pubkey, &dh_pubkey_len, 
	    &server_key, &server_key_len);
	if (retval) {
	    pkiDebug("failed to process/create dh paramters\n");
	    goto cleanup;
	}
    }
	
    if ((rep9 != NULL &&
	    rep9->choice == choice_pa_pk_as_rep_draft9_dhSignedData) ||
	(rep != NULL && rep->choice == choice_pa_pk_as_rep_dhInfo)) {
	retval = pkinit_octetstring2key(context, enctype, server_key,
					server_key_len, encrypting_key);
	if (retval) {
	    pkiDebug("pkinit_octetstring2key failed: %s\n",
		     error_message(retval));
	    goto cleanup;
	}

	dhkey_info.subjectPublicKey.length = dh_pubkey_len;
	dhkey_info.subjectPublicKey.data = dh_pubkey;
	dhkey_info.nonce = request->nonce;
	dhkey_info.dhKeyExpiration = 0;

	retval = k5int_encode_krb5_kdc_dh_key_info(&dhkey_info,
						   &encoded_dhkey_info);
	if (retval) {
	    pkiDebug("encode_krb5_kdc_dh_key_info failed\n");
	    goto cleanup;
	}
#ifdef DEBUG_ASN1
	print_buffer_bin((unsigned char *)encoded_dhkey_info->data,
			 encoded_dhkey_info->length,
			 "/tmp/kdc_dh_key_info");
#endif

	switch ((int)padata->pa_type) {
	    case KRB5_PADATA_PK_AS_REQ:
		retval = cms_signeddata_create(context, plgctx->cryptoctx,
		    reqctx->cryptoctx, plgctx->idctx, CMS_SIGN_SERVER, 1,
		    (unsigned char *)encoded_dhkey_info->data,
		    encoded_dhkey_info->length,
		    &rep->u.dh_Info.dhSignedData.data,
		    &rep->u.dh_Info.dhSignedData.length);
		if (retval) {
		    pkiDebug("failed to create pkcs7 signed data\n");
		    goto cleanup;
		}
		break;
	    case KRB5_PADATA_PK_AS_REP_OLD:
	    case KRB5_PADATA_PK_AS_REQ_OLD:
		retval = cms_signeddata_create(context, plgctx->cryptoctx,
		    reqctx->cryptoctx, plgctx->idctx, CMS_SIGN_DRAFT9, 1,
		    (unsigned char *)encoded_dhkey_info->data,
		    encoded_dhkey_info->length,
		    &rep9->u.dhSignedData.data,
		    &rep9->u.dhSignedData.length);
		if (retval) {
		    pkiDebug("failed to create pkcs7 signed data\n");
		    goto cleanup;
		}
		break;
	}
    } else {
	pkiDebug("received RSA key delivery AS REQ\n");

	retval = krb5_c_make_random_key(context, enctype, encrypting_key);
	if (retval) {
	    pkiDebug("unable to make a session key\n");
	    goto cleanup;
	}

	switch ((int)padata->pa_type) {
	    case KRB5_PADATA_PK_AS_REQ:
		init_krb5_reply_key_pack(&key_pack);
		if (key_pack == NULL) {
		    retval = ENOMEM;
		    goto cleanup;
		}
		/* retrieve checksums for a given enctype of the reply key */
		retval = krb5_c_keyed_checksum_types(context,
		    encrypting_key->enctype, &num_types, &cksum_types);
		if (retval)
		    goto cleanup;

		/* pick the first of acceptable enctypes for the checksum */
		retval = krb5_c_make_checksum(context, cksum_types[0],
		    encrypting_key, KRB5_KEYUSAGE_TGS_REQ_AUTH_CKSUM,
		    req_pkt, &key_pack->asChecksum);
		if (retval) {
		    pkiDebug("unable to calculate AS REQ checksum\n");
		    goto cleanup;
		}
#ifdef DEBUG_CKSUM
		pkiDebug("calculating checksum on buf size = %d\n",
			req_pkt->length);
		print_buffer(req_pkt->data, req_pkt->length);
		pkiDebug("checksum size = %d\n",
			key_pack->asChecksum.length);
		print_buffer(key_pack->asChecksum.contents,
			     key_pack->asChecksum.length);
		pkiDebug("encrypting key (%d)\n", encrypting_key->length);
		print_buffer(encrypting_key->contents, encrypting_key->length);
#endif

		krb5_copy_keyblock_contents(context, encrypting_key,
					    &key_pack->replyKey);

		retval = k5int_encode_krb5_reply_key_pack(key_pack,
						    &encoded_key_pack);
		if (retval) {
		    pkiDebug("failed to encode reply_key_pack\n");
		    goto cleanup;
		}

		init_krb5_pa_pk_as_rep(&rep);
		if (rep == NULL) {
		    retval = ENOMEM;
		    goto cleanup;
		}
		rep->choice = choice_pa_pk_as_rep_encKeyPack;
		retval = cms_envelopeddata_create(context, plgctx->cryptoctx,
		    reqctx->cryptoctx, plgctx->idctx, padata->pa_type, 1, 
		    (unsigned char *)encoded_key_pack->data,
		    encoded_key_pack->length,
		    &rep->u.encKeyPack.data, &rep->u.encKeyPack.length);
		break;
	    case KRB5_PADATA_PK_AS_REP_OLD:
	    case KRB5_PADATA_PK_AS_REQ_OLD:
		init_krb5_reply_key_pack_draft9(&key_pack9);
		if (key_pack9 == NULL) {
		    retval = ENOMEM;
		    goto cleanup;
		}
		key_pack9->nonce = reqctx->rcv_auth_pack9->pkAuthenticator.nonce;
		krb5_copy_keyblock_contents(context, encrypting_key,
					    &key_pack9->replyKey);

		retval = k5int_encode_krb5_reply_key_pack_draft9(key_pack9,
							   &encoded_key_pack);
		if (retval) {
		    pkiDebug("failed to encode reply_key_pack\n");
		    goto cleanup;
		}
		init_krb5_pa_pk_as_rep_draft9(&rep9);
		if (rep9 == NULL) {
		    retval = ENOMEM;
		    goto cleanup;
		}
		rep9->choice = choice_pa_pk_as_rep_draft9_encKeyPack;
		retval = cms_envelopeddata_create(context, plgctx->cryptoctx,
		    reqctx->cryptoctx, plgctx->idctx, padata->pa_type, 1, 
		    (unsigned char *)encoded_key_pack->data,
		    encoded_key_pack->length,
		    &rep9->u.encKeyPack.data, &rep9->u.encKeyPack.length);
		break;
	}
	if (retval) {
	    pkiDebug("failed to create pkcs7 enveloped data: %s\n", error_message(retval));
	    goto cleanup;
	}
#ifdef DEBUG_ASN1
	print_buffer_bin((unsigned char *)encoded_key_pack->data,
			 encoded_key_pack->length,
			 "/tmp/kdc_key_pack");
	switch ((int)padata->pa_type) {
	    case KRB5_PADATA_PK_AS_REQ:
		print_buffer_bin(rep->u.encKeyPack.data,
				 rep->u.encKeyPack.length,
				 "/tmp/kdc_enc_key_pack");
		break;
	    case KRB5_PADATA_PK_AS_REP_OLD:
	    case KRB5_PADATA_PK_AS_REQ_OLD:
		print_buffer_bin(rep9->u.encKeyPack.data,
				 rep9->u.encKeyPack.length,
				 "/tmp/kdc_enc_key_pack");
		break;
	}
#endif
    }

    switch ((int)padata->pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    retval = k5int_encode_krb5_pa_pk_as_rep(rep, &out_data);
	    break;
	case KRB5_PADATA_PK_AS_REP_OLD:
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    retval = k5int_encode_krb5_pa_pk_as_rep_draft9(rep9, &out_data);
	    break;
    }
    if (retval) {
	pkiDebug("failed to encode AS_REP\n");
	goto cleanup;
    }
#ifdef DEBUG_ASN1
    if (out_data != NULL)
	print_buffer_bin((unsigned char *)out_data->data, out_data->length,
			 "/tmp/kdc_as_rep");
#endif

    *send_pa = (krb5_pa_data *) malloc(sizeof(krb5_pa_data));
    if (*send_pa == NULL) {
	retval = ENOMEM;
	free(out_data->data);
	free(out_data);
	out_data = NULL;
	goto cleanup;
    }
    (*send_pa)->magic = KV5M_PA_DATA;
    switch ((int)padata->pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    (*send_pa)->pa_type = KRB5_PADATA_PK_AS_REP;
	    break;
	case KRB5_PADATA_PK_AS_REQ_OLD:
	case KRB5_PADATA_PK_AS_REP_OLD:
	    (*send_pa)->pa_type = KRB5_PADATA_PK_AS_REP_OLD;
	    break;
    }
    (*send_pa)->length = out_data->length;
    (*send_pa)->contents = (krb5_octet *) out_data->data;


  cleanup:
    pkinit_fini_kdc_req_context(context, reqctx);
    if (scratch.data != NULL)
	free(scratch.data);
    if (out_data != NULL)
	free(out_data);
    if (encoded_dhkey_info != NULL)
	krb5_free_data(context, encoded_dhkey_info);
    if (encoded_key_pack != NULL)
	krb5_free_data(context, encoded_key_pack);
    if (dh_pubkey != NULL)
	free(dh_pubkey);
    if (server_key != NULL)
	free(server_key);
    if (cksum_types != NULL)
	free(cksum_types);

    switch ((int)padata->pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    free_krb5_pa_pk_as_req(&reqp);
	    free_krb5_pa_pk_as_rep(&rep);
	    free_krb5_reply_key_pack(&key_pack);
	    break;
	case KRB5_PADATA_PK_AS_REP_OLD:
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    free_krb5_pa_pk_as_req_draft9(&reqp9);
	    free_krb5_pa_pk_as_rep_draft9(&rep9);
	    free_krb5_reply_key_pack_draft9(&key_pack9);
	    break;
    }

    if (retval)
	pkiDebug("pkinit_verify_padata failure");

    return retval;
}

static int
pkinit_server_get_flags(krb5_context kcontext, krb5_preauthtype patype)
{
    return PA_SUFFICIENT | PA_REPLACES_KEY;
}

static krb5_preauthtype supported_server_pa_types[] = {
    KRB5_PADATA_PK_AS_REQ,
    KRB5_PADATA_PK_AS_REQ_OLD,
    KRB5_PADATA_PK_AS_REP_OLD,
    0
};

static void
pkinit_fini_kdc_profile(krb5_context context, pkinit_kdc_context plgctx)
{
    /*
     * There is nothing currently allocated by pkinit_init_kdc_profile()
     * which needs to be freed here.
     */
}

static krb5_error_code
pkinit_init_kdc_profile(krb5_context context, pkinit_kdc_context plgctx)
{
    krb5_error_code retval;

    pkiDebug("%s: entered for realm %s\n", __FUNCTION__, plgctx->realmname);
    retval = pkinit_kdcdefault_string(context, plgctx->realmname,
				      "pkinit_identity",
				      &plgctx->idopts->identity);
    if (retval != 0 || NULL == plgctx->idopts->identity) {
	retval = EINVAL;
	krb5_set_error_message(context, retval,
			       "No pkinit_identity supplied for realm %s",
			       plgctx->realmname);
	goto errout;
    }

    retval = pkinit_kdcdefault_strings(context, plgctx->realmname,
				       "pkinit_anchors",
				       &plgctx->idopts->anchors);
    if (retval != 0 || NULL == plgctx->idopts->anchors) {
	retval = EINVAL;
	krb5_set_error_message(context, retval,
			       "No pkinit_anchors supplied for realm %s",
			       plgctx->realmname);
	goto errout;
    }

    pkinit_kdcdefault_strings(context, plgctx->realmname,
			      "pkinit_pool",
			      &plgctx->idopts->intermediates);

    pkinit_kdcdefault_strings(context, plgctx->realmname,
			      "pkinit_revoke",
			      &plgctx->idopts->crls);

    pkinit_kdcdefault_string(context, plgctx->realmname,
			     "pkinit_kdc_ocsp",
			     &plgctx->idopts->ocsp);

    pkinit_kdcdefault_string(context, plgctx->realmname,
			     "pkinit_mappings_file",
			     &plgctx->idopts->dn_mapping_file);

    pkinit_kdcdefault_boolean(context, plgctx->realmname,
			      "pkinit_principal_in_certificate",
			      1, &plgctx->opts->princ_in_cert);

    pkinit_kdcdefault_boolean(context, plgctx->realmname,
			      "pkinit_allow_proxy_certificate",
			      0, &plgctx->opts->allow_proxy_certs);

    pkinit_kdcdefault_integer(context, plgctx->realmname,
			      "pkinit_dh_min_bits",
			      0, &plgctx->opts->dh_min_bits);

    return 0;
errout:
    pkinit_fini_kdc_profile(context, plgctx);
    return retval;
}

static pkinit_kdc_context
pkinit_find_realm_context(krb5_context context, void *pa_plugin_context,
			  krb5_principal princ)
{
    int i;
    pkinit_kdc_context *realm_contexts = pa_plugin_context;

    if (pa_plugin_context == NULL)
	return NULL;

    for (i = 0; realm_contexts[i] != NULL; i++) {
	pkinit_kdc_context p = realm_contexts[i];

	if ((p->realmname_len == princ->realm.length) &&
	    (strncmp(p->realmname, princ->realm.data, p->realmname_len) == 0)) {
	    pkiDebug("%s: returning context at %p for realm '%s'\n",
		     __FUNCTION__, p, p->realmname);
	    return p;
	}
    }
    pkiDebug("%s: unable to find realm context for realm '%.*s'\n",
	     __FUNCTION__, princ->realm.length, princ->realm.data);
    return NULL;
}

static int
pkinit_server_plugin_init_realm(krb5_context context, const char *realmname,
				pkinit_kdc_context *pplgctx)
{
    krb5_error_code retval = ENOMEM;
    pkinit_kdc_context plgctx = NULL;

    *pplgctx = NULL;

    plgctx = (pkinit_kdc_context) calloc(1, sizeof(*plgctx));
    if (plgctx == NULL)
	goto errout;

    pkiDebug("%s: initializing context at %p for realm '%s'\n",
	     __FUNCTION__, plgctx, realmname);
    memset(plgctx, 0, sizeof(*plgctx));
    plgctx->magic = PKINIT_CTX_MAGIC;

    plgctx->realmname = strdup(realmname);
    if (plgctx->realmname == NULL)
	goto errout;
    plgctx->realmname_len = strlen(plgctx->realmname);

    retval = pkinit_init_plg_crypto(&plgctx->cryptoctx);
    if (retval)
	goto errout;

    retval = pkinit_init_plg_opts(&plgctx->opts);
    if (retval)
	goto errout;

    retval = pkinit_init_identity_crypto(&plgctx->idctx);
    if (retval)
	goto errout;

    retval = pkinit_init_identity_opts(&plgctx->idopts);
    if (retval)
	goto errout;

    retval = pkinit_init_kdc_profile(context, plgctx);
    if (retval)
	goto errout;

    retval = pkinit_initialize_identity(context, plgctx->idopts, plgctx->idctx);
    if (retval)
	goto errout;

    pkiDebug("%s: returning context at %p for realm '%s'\n",
	     __FUNCTION__, plgctx, realmname);
    *pplgctx = plgctx;
    retval = 0;

errout:
    if (retval)
	pkinit_server_plugin_fini_realm(context, plgctx);

    return retval;
}

static int
pkinit_server_plugin_init(krb5_context context, void **blob,
			  const char **realmnames)
{
    krb5_error_code retval = ENOMEM;
    pkinit_kdc_context plgctx, *realm_contexts = NULL;
    int i, j;
    size_t numrealms;

    retval = pkinit_accessor_init();
    if (retval)
        return retval;

    /* Determine how many realms we may need to support */
    for (i = 0; realmnames[i] != NULL; i++) {};
    numrealms = i;

    realm_contexts = (pkinit_kdc_context *)
			calloc(numrealms+1, sizeof(pkinit_kdc_context));
    if (realm_contexts == NULL)
	return ENOMEM;

    for (i = 0, j = 0; i < numrealms; i++) {
	pkiDebug("%s: processing realm '%s'\n", __FUNCTION__, realmnames[i]);
	retval = pkinit_server_plugin_init_realm(context, realmnames[i], &plgctx);
	if (retval == 0 && plgctx != NULL)
	    realm_contexts[j++] = plgctx;
    }

    if (j == 0) {
	retval = EINVAL;
	krb5_set_error_message(context, retval, "No realms configured "
			       "correctly for pkinit support");
	goto errout;
    }

    *blob = realm_contexts;
    retval = 0;
    pkiDebug("%s: returning context at %p\n", __FUNCTION__, realm_contexts);

errout:
    if (retval)
	pkinit_server_plugin_fini(context, realm_contexts);

    return retval;
}

static void
pkinit_server_plugin_fini_realm(krb5_context context, pkinit_kdc_context plgctx)
{
    if (plgctx == NULL)
	return;

    pkinit_fini_kdc_profile(context, plgctx);
    pkinit_fini_identity_opts(plgctx->idopts);
    pkinit_fini_identity_crypto(plgctx->idctx);
    pkinit_fini_plg_crypto(plgctx->cryptoctx);
    pkinit_fini_plg_opts(plgctx->opts);
    free(plgctx->realmname);
    free(plgctx);
}

static void
pkinit_server_plugin_fini(krb5_context context, void *blob)
{
    pkinit_kdc_context *realm_contexts = blob;
    int i;

    if (realm_contexts == NULL)
	return;

    for (i = 0; realm_contexts[i] != NULL; i++) {
	pkinit_server_plugin_fini_realm(context, realm_contexts[i]);
    }
    pkiDebug("%s: freeing   context at %p\n", __FUNCTION__, realm_contexts);
    free(realm_contexts);
}

static krb5_error_code pkinit_init_kdc_req_context(krb5_context context,
						   void **ctx)
{
    krb5_error_code retval = ENOMEM;
    pkinit_kdc_req_context reqctx = NULL;

    reqctx = (pkinit_kdc_req_context)malloc(sizeof(*reqctx));
    if (reqctx == NULL)
	return retval;
    memset(reqctx, 0, sizeof(*reqctx));
    reqctx->magic = PKINIT_CTX_MAGIC;

    retval = pkinit_init_req_crypto(&reqctx->cryptoctx);
    if (retval)
	goto cleanup;
    reqctx->rcv_auth_pack = NULL;
    reqctx->rcv_auth_pack9 = NULL;

    pkiDebug("%s: returning reqctx at %p\n", __FUNCTION__, reqctx);
    *ctx = reqctx;
    retval = 0;
cleanup:
    if (retval)
	pkinit_fini_kdc_req_context(context, reqctx);

    return retval;
}

static void  pkinit_fini_kdc_req_context(krb5_context context, void *ctx)
{
    pkinit_kdc_req_context reqctx = (pkinit_kdc_req_context)ctx;

    if (reqctx == NULL || reqctx->magic != PKINIT_CTX_MAGIC) {
        pkiDebug("pkinit_fini_kdc_req_context: got bad reqctx (%p)!\n", reqctx);
        return;
    }
    pkiDebug("%s: freeing   reqctx at %p\n", __FUNCTION__, reqctx);

    pkinit_fini_req_crypto(reqctx->cryptoctx);
    if (reqctx->rcv_auth_pack != NULL) {
	if (reqctx->rcv_auth_pack->clientPublicValue != NULL &&
	    reqctx->rcv_auth_pack->clientPublicValue->algorithm.algorithm.data != NULL)
		free(reqctx->rcv_auth_pack->clientPublicValue->algorithm.algorithm.data);
	free_krb5_auth_pack(&reqctx->rcv_auth_pack);
    }
    if (reqctx->rcv_auth_pack9 != NULL)
	free_krb5_auth_pack_draft9(context, &reqctx->rcv_auth_pack9);

    free(reqctx);
}

struct krb5plugin_preauth_server_ftable_v0 preauthentication_server_0 = {
    "pkinit",			/* name */
    supported_server_pa_types,	/* pa_type_list */
    pkinit_server_plugin_init,	/* (*init_proc) */
    pkinit_server_plugin_fini,	/* (*fini_proc) */
    pkinit_server_get_flags,	/* (*flags_proc) */
    pkinit_server_get_edata,	/* (*edata_proc) */
    pkinit_server_verify_padata,/* (*verify_proc) */
    pkinit_server_return_padata,/* (*return_proc) */
    NULL,			/* (*freepa_reqcontext_proc) */
};

/*
 * COPYRIGHT (C) 2006
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
#include <krb5/krb5.h>
#include <krb5/preauth_plugin.h>
#include <k5-int-pkinit.h>

#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/asn1_mac.h>
#include <openssl/sha.h>

#include "pkinit.h"

#ifdef DEBUG
#define pkiDebug(args...)       printf(args)
#else
#define pkiDebug(args...)
#endif

static krb5_error_code pkinit_server_get_edata
	(krb5_context context, krb5_kdc_req * request,
		struct _krb5_db_entry_new * client,
		struct _krb5_db_entry_new * server,
		preauth_get_entry_data_proc server_get_entry_data,
		void *pa_plugin_context,
		krb5_pa_data * data);

static krb5_error_code pkinit_server_verify_padata
	(krb5_context context, struct _krb5_db_entry_new * client,
		krb5_data *req_pkt, krb5_kdc_req * request,
		krb5_enc_tkt_part * enc_tkt_reply, krb5_pa_data * data,
		preauth_get_entry_data_proc server_get_entry_data,
		void *pa_plugin_context, void **pa_request_context,
		krb5_data **e_data);

static krb5_error_code pkinit_server_return_padata
	(krb5_context context, krb5_pa_data * padata,
		struct _krb5_db_entry_new * client, krb5_data *req_pkt,
		krb5_kdc_req * request, krb5_kdc_rep * reply,
		struct _krb5_key_data * client_key,
		krb5_keyblock * encrypting_key, krb5_pa_data ** send_pa,
		preauth_get_entry_data_proc server_get_entry_data,
		void *pa_plugin_context, void **pa_request_context);

static int pkinit_server_get_flags
	(krb5_context kcontext, krb5_preauthtype patype);

static DH *
decode_dhparams(DH ** a, unsigned char **pp, long length)
{
    ASN1_INTEGER ai, *aip = NULL;

    M_ASN1_D2I_vars(a, DH *, DH_new);

    M_ASN1_D2I_Init();
    M_ASN1_D2I_start_sequence();
    aip = &ai;
    ai.data = NULL;
    ai.length = 0;
    M_ASN1_D2I_get_x(ASN1_INTEGER, aip, d2i_ASN1_INTEGER);
    if (aip == NULL)
	return NULL;
    else {
	(*a)->p = ASN1_INTEGER_to_BN(aip, NULL);
	if ((*a)->p == NULL)
	    return NULL;
	if (ai.data != NULL) {
	    OPENSSL_free(ai.data);
	    ai.data = NULL;
	    ai.length = 0;
	}
    }
    M_ASN1_D2I_get_x(ASN1_INTEGER, aip, d2i_ASN1_INTEGER);
    if (aip == NULL)
	return NULL;
    else {
	(*a)->g = ASN1_INTEGER_to_BN(aip, NULL);
	if ((*a)->g == NULL)
	    return NULL;
	if (ai.data != NULL) {
	    OPENSSL_free(ai.data);
	    ai.data = NULL;
	    ai.length = 0;
	}

    }
    M_ASN1_D2I_get_x(ASN1_INTEGER, aip, d2i_ASN1_INTEGER);
    if (aip == NULL)
	return NULL;
    else {
	(*a)->q = ASN1_INTEGER_to_BN(aip, NULL);
	if ((*a)->q == NULL)
	    return NULL;
	if (ai.data != NULL) {
	    OPENSSL_free(ai.data);
	    ai.data = NULL;
	    ai.length = 0;
	}

    }
    M_ASN1_D2I_end_sequence();
    M_ASN1_D2I_Finish(a, DH_free, 0);

}
static int
check_dh(BIGNUM * p1, BIGNUM * p2, BIGNUM * g1, BIGNUM * q1)
{
    BIGNUM *g2 = NULL, *q2 = NULL;
    int retval = -1;

    if (!BN_cmp(p1, p2)) {
	g2 = BN_new();
	BN_set_word(g2, DH_GENERATOR_2);
	if (!BN_cmp(g1, g2)) {
	    q2 = BN_new();
	    BN_rshift1(q2, p1);
	    if (!BN_cmp(q1, q2)) {
		pkiDebug("good %d dhparams\n", BN_num_bits(p1));
		retval = 0;
	    } else
		pkiDebug("bad group 2 q dhparameter\n");
	    BN_free(q2);
	} else
	    pkiDebug("bad g dhparameter\n");
	BN_free(g2);
    } else
	pkiDebug("p is not well-known group 2 dhparameter\n");

    return retval;
}

static krb5_error_code
server_check_dh(unsigned char *dh_params, int dh_params_len)
{
    DH *dh = NULL;
    unsigned char *tmp = NULL;
    BIGNUM *p = NULL;
    krb5_error_code retval = KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED;

    tmp = dh_params;
    dh = DH_new();
    dh = decode_dhparams(&dh, &tmp, dh_params_len);
    if (dh == NULL) {
	pkiDebug("failed to decode dhparams\n");
	goto cleanup;
    }

    /* KDC SHOULD check to see if the key parameters satisfy its policy */
    /* check dhparams is group 2 */
    p = BN_bin2bn(pkinit_1024_dhprime, sizeof(pkinit_1024_dhprime), NULL);
    if (p && !check_dh(p, dh->p, dh->g, dh->q)) {
	retval = 0;
	goto cleanup;
    }
    BN_free(p);
    p = NULL;

    /* check dhparams is group 14 */
    p = BN_bin2bn(pkinit_2048_dhprime, sizeof(pkinit_2048_dhprime), NULL);
    if (p && !check_dh(p, dh->p, dh->g, dh->q)) {
	retval = 0;
	goto cleanup;
    }
    BN_free(p);
    p = NULL;

    /* check dhparams is group 16 */
    p = BN_bin2bn(pkinit_4096_dhprime, sizeof(pkinit_4096_dhprime), NULL);
    if (p && !check_dh(p, dh->p, dh->g, dh->q)) {
	retval = 0;
	goto cleanup;
    }

  cleanup:
    if (p != NULL)
	BN_free(p);
    if (dh != NULL)
	DH_free(dh);
    return retval;
}

/* kdc's dh function */
static krb5_error_code
server_process_dh(DH ** dh_server,
		  unsigned char *data,
		  int data_len,
		  unsigned char *dh_params,
		  int dh_params_len,
		  unsigned char **dh_pubkey,
		  int *dh_pubkey_len,
		  unsigned char **server_key, int *server_key_len)
{
    krb5_error_code retval = ENOMEM;
    DH *dh = NULL;
    unsigned char *p = NULL;
    ASN1_INTEGER *pub_key = NULL;

    /* unpack client's DHparams keys */
    dh = DH_new();
    p = dh_params;
    dh = decode_dhparams(&dh, &p, dh_params_len);
    if (dh == NULL)
	return KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED;

    *dh_server = DH_new();
    if (*dh_server == NULL) 
	goto cleanup;
    (*dh_server)->p = BN_dup(dh->p);
    (*dh_server)->g = BN_dup(dh->g);
    (*dh_server)->q = BN_dup(dh->q);

    /* decode client's public key */
    p = data;
    pub_key = d2i_ASN1_INTEGER(NULL, (const unsigned char **)&p, data_len);
    if (pub_key == NULL)
	goto cleanup;
    dh->pub_key = ASN1_INTEGER_to_BN(pub_key, NULL);
    if (dh->pub_key == NULL)
	goto cleanup;
    ASN1_INTEGER_free(pub_key);

    if (!DH_generate_key(*dh_server)) 
	goto cleanup;

    /* generate DH session key */
    *server_key_len = DH_size(*dh_server);
    if ((*server_key = (unsigned char *) malloc(*server_key_len)) == NULL)
	goto cleanup;
    DH_compute_key(*server_key, dh->pub_key, *dh_server);

#ifdef DEBUG_DH
    print_dh(*dh_server, "client&server's DH params\n");
    print_pubkey(dh->pub_key, "client's pub_key=");
    print_pubkey((*dh_server)->pub_key, "server's pub_key=");
    pkiDebug("server secret key=");
    print_buffer(*server_key, *server_key_len);
#endif

    /* KDC reply */
    /* pack DH public key */
    /* Diffie-Hellman public key must be ASN1 encoded as an INTEGER; this
     * encoding shall be used as the contents (the value) of the
     * subjectPublicKey component (a BIT STRING) of the SubjectPublicKeyInfo
     * data element
     */
    if ((pub_key = BN_to_ASN1_INTEGER((*dh_server)->pub_key, NULL)) == NULL)
	goto cleanup;
    *dh_pubkey_len = i2d_ASN1_INTEGER(pub_key, NULL);
    if ((p = *dh_pubkey = (unsigned char *) malloc(*dh_pubkey_len)) == NULL)
	goto cleanup;
    i2d_ASN1_INTEGER(pub_key, &p);
    if (pub_key != NULL)
	ASN1_INTEGER_free(pub_key);

    retval = 0;
    if (dh != NULL)
	DH_free(dh);
    return retval;

  cleanup:
    if (dh != NULL)
	DH_free(dh);
    if (*dh_server != NULL)
	DH_free(*dh_server);
    if (*dh_pubkey != NULL)
	free(*dh_pubkey);
    if (*server_key != NULL)
	free(*server_key);

    return retval;
}

static krb5_error_code
pkinit_create_edata(krb5_error_code err_code,
		    krb5_data **e_data) 
{
    krb5_error_code retval = KRB5KRB_ERR_GENERIC;
    STACK_OF(X509) *trusted_CAs = NULL;
    krb5_external_principal_identifier **krb5_trusted_certifiers;
    char filename[] = "/etc/grid-security/certificates/ca-bundle.crt";
    krb5_data *data = NULL;

    retval = load_trusted_certifiers(&trusted_CAs, filename);
    if (trusted_CAs) {
	retval = create_krb5_trustedCertifiers(trusted_CAs, 
					       &krb5_trusted_certifiers);
	if (retval) {
	    pkiDebug("create_krb5_trustedCertifiers failed\n");
	    goto cleanup;
	}
	retval = encode_krb5_td_trusted_certifiers(krb5_trusted_certifiers,
						   &data);
    }	
    retval = 0;
cleanup:
    if (data != NULL) {
	if (data->data != NULL)
	    free(data->data);
	free(data);
    }
    free_krb5_external_principal_identifier(&krb5_trusted_certifiers);
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
    pkiDebug("pkinit_get_edata: entered!\n");
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
			    krb5_data **e_data)
{
    krb5_error_code retval = 0;	
    krb5_data scratch;
    krb5_pa_pk_as_req *reqp = NULL;
    krb5_pa_pk_as_req_draft9 *reqp9 = NULL;
    krb5_auth_pack *auth_pack = NULL;
    krb5_auth_pack_draft9 *auth_pack9 = NULL;
    X509 *cert = NULL;
    pkinit_context *plgctx = (pkinit_context *)pa_plugin_context;
    krb5_preauthtype pa_type;
    krb5_principal tmp_client;

    pkiDebug("pkinit_verify_padata: entered!\n");

    if (data == NULL || data->length <= 0 || data->contents == NULL) 
	return 0;

    if (pa_plugin_context == NULL || e_data == NULL)
	return -1;

    scratch.data = data->contents;
    scratch.length = data->length;

#ifdef DEBUG_ASN1
    print_buffer_bin(scratch.data, scratch.length, "/tmp/kdc_as_req");
#endif

    switch ((int)data->pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    pkiDebug("processing KRB5_PADATA_PK_AS_REQ\n");
	    pa_type = (int)data->pa_type;
	    retval = decode_krb5_pa_pk_as_req(&scratch, &reqp);
	    scratch.data = NULL;
	    scratch.length = 0;
	    if (retval) {
		pkiDebug("decode_krb5_pa_pk_as_req failed\n");
		goto cleanup;
	    }

	    retval = pkcs7_signeddata_verify(reqp->signedAuthPack.data,
		reqp->signedAuthPack.length, &scratch.data, &scratch.length, 
		&cert, plgctx->id_pkinit_authData, context, plgctx);
	    break;
	case KRB5_PADATA_PK_AS_REP_OLD:
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    pkiDebug("processing KRB5_PADATA_PK_AS_REQ_OLD\n");
	    pa_type = KRB5_PADATA_PK_AS_REQ_OLD;
	    retval = decode_krb5_pa_pk_as_req_draft9(&scratch, &reqp9);
	    scratch.data = NULL;
	    scratch.length = 0;
	    if (retval) {
		pkiDebug("decode_krb5_pa_pk_as_req_draft9 failed\n");
		goto cleanup;
	    }

	    retval = pkcs7_signeddata_verify(reqp9->signedAuthPack.data,
		reqp9->signedAuthPack.length, &scratch.data, &scratch.length, 
		&cert, plgctx->id_pkinit_authData9, context, plgctx);
	    break;
	default:
	    pkiDebug("unrecognized pa_type = %d\n", data->pa_type);
	    scratch.data = NULL;
	    scratch.length = 0;
	    retval = -1;
	    goto cleanup;
    }
    if (retval) {
	pkiDebug("pkcs7_signeddata_verify failed\n");
	goto cleanup;
    }

    if (!verify_id_pkinit_san(cert, &tmp_client, context, pa_type, plgctx)) {
	pkiDebug("failed to verify id-pkinit-san\n");
	retval = KRB5KDC_ERR_CLIENT_NOT_TRUSTED;
	goto cleanup;
    } else {
	if (tmp_client != NULL) {
	    retval = krb5_principal_compare(context, request->client, tmp_client);
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

    if (!verify_id_pkinit_eku(cert, pa_type, plgctx)) {
	pkiDebug("failed to verify id-pkinit-KPClientAuth\n");
	retval = KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE;
	goto cleanup;
    }

#ifdef DEBUG_ASN1
    print_buffer_bin(scratch.data, scratch.length, "/tmp/kdc_auth_pack");
#endif
    switch ((int)data->pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    retval = decode_krb5_auth_pack(&scratch, &auth_pack);
	    if (retval) {
		pkiDebug("failed to decode krb5_auth_pack\n");
		goto cleanup;
	    }

	    if (auth_pack->clientPublicValue != NULL) {	
		retval = server_check_dh(
		    auth_pack->clientPublicValue->algorithm.parameters.data,
		    auth_pack->clientPublicValue->algorithm.parameters.length);

		if (retval) {
		    pkiDebug("bad dh parameters\n");
		    goto cleanup;
		}
	    }
	    /* check if kdcPkId present and match KDC's subjectIdentifier */
	    if (reqp->kdcPkId.data != NULL) {
		PKCS7_ISSUER_AND_SERIAL *is = NULL;
		const unsigned char *p = reqp->kdcPkId.data;
		X509 *kdc_cert = NULL;
		char *filename = NULL;
		int status = 0;

		pkiDebug("found kdcPkId in AS REQ\n");
		is = d2i_PKCS7_ISSUER_AND_SERIAL(NULL, &p, reqp->kdcPkId.length);

		get_filename(&filename, "KDC_CERT", 1);
		kdc_cert = get_cert(filename);
		status = X509_NAME_cmp(X509_get_issuer_name(kdc_cert), is->issuer);
		if (status) {
		    pkiDebug("issuer names do not match\n");
		}

		status = ASN1_INTEGER_cmp(X509_get_serialNumber(kdc_cert), is->serial);
		if (status) {
		    pkiDebug("serial numbers do not match\n");
		}

		X509_NAME_free(is->issuer);
		ASN1_INTEGER_free(is->serial);
		free(is);
		X509_free(kdc_cert);
		free(filename);
	    }
	    break;
	case KRB5_PADATA_PK_AS_REP_OLD:
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    retval = decode_krb5_auth_pack_draft9(&scratch, &auth_pack9);
	    if (retval) {
		pkiDebug("failed to decode krb5_auth_pack_draft9\n");
		goto cleanup;
	    }
	    if (auth_pack9->clientPublicValue != NULL) {	
		retval = server_check_dh(
		    auth_pack9->clientPublicValue->algorithm.parameters.data,
		    auth_pack9->clientPublicValue->algorithm.parameters.length);

		if (retval) {
		    pkiDebug("bad dh parameters\n");
		    goto cleanup;
		}
	    }
	    break;
    }

    /* remember to set the PREAUTH flag in the reply */
    enc_tkt_reply->flags |= TKT_FLG_PRE_AUTH;

  cleanup:
    if (retval) {
	pkiDebug("pkinit_verify_padata failed: creating e-data\n");
	if (pkinit_create_edata(retval, e_data)) 
	    pkiDebug("pkinit_create_edata failed\n");
    }

    switch ((int)data->pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    free_krb5_pa_pk_as_req(&reqp);
	    if (auth_pack != NULL && auth_pack->clientPublicValue != NULL &&
		auth_pack->clientPublicValue->algorithm.algorithm.data != NULL)
		free(auth_pack->clientPublicValue->algorithm.algorithm.data);
	    free_krb5_auth_pack(&auth_pack);
	    break;
	case KRB5_PADATA_PK_AS_REP_OLD:
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    free_krb5_pa_pk_as_req_draft9(&reqp9);
	    free_krb5_auth_pack_draft9(context, &auth_pack9);
    }

    if (scratch.data != NULL)
	free(scratch.data);
    if (cert != NULL)
	X509_free(cert);

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
    krb5_auth_pack *auth_pack = NULL;
    krb5_auth_pack_draft9 *auth_pack9 = NULL;
    X509 *client_cert = NULL, *kdc_cert = NULL;
    DH *dh_server = NULL;
    int protocol = -1;

    unsigned char *dh_pubkey = NULL;
    unsigned char *server_key = NULL;
    int server_key_len = 0;
    int dh_pubkey_len = 0;
    int i = 0;

    krb5_kdc_dh_key_info dhkey_info;
    krb5_data *encoded_dhkey_info = NULL;
    krb5_pa_pk_as_rep *rep = NULL;
    krb5_pa_pk_as_rep_draft9 *rep9 = NULL;
    krb5_data *out_data = NULL;

    krb5_enctype enctype = -1;
    char *filename = NULL;

    krb5_reply_key_pack *key_pack = NULL;
    krb5_reply_key_pack_draft9 *key_pack9 = NULL;
    krb5_data *encoded_key_pack = NULL;

    pkinit_context *plgctx = (pkinit_context *)pa_plugin_context;

    *send_pa = NULL;
    if (padata == NULL || padata->length <= 0 || padata->contents == NULL) 
	return 0;

    pkiDebug("pkinit_return_padata: entered!\n");

    scratch.data = padata->contents;
    scratch.length = padata->length;

    switch ((int)padata->pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    pkiDebug("processing KRB5_PADATA_PK_AS_REQ\n");
	    retval = decode_krb5_pa_pk_as_req(&scratch, &reqp);
	    if (retval) {
		pkiDebug("decode_krb5_pa_pk_as_req failed");
		goto cleanup;
	    }
	    scratch.data = NULL;
	    scratch.length = 0;

	    retval = pkcs7_signeddata_verify(reqp->signedAuthPack.data,
		reqp->signedAuthPack.length, &scratch.data, &scratch.length, 
		&client_cert, plgctx->id_pkinit_authData, context, plgctx);
	    if (retval) {
		pkiDebug("pkcs7_signeddata_verify failed\n");
		goto cleanup;
	    }
	    retval = decode_krb5_auth_pack(&scratch, &auth_pack);
	    if (retval) {
		pkiDebug("failed to decode krb5_auth_pack\n");
		goto cleanup;
	    }
	    init_krb5_pa_pk_as_rep(&rep);
	    if (rep == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }
	    break;
	case KRB5_PADATA_PK_AS_REP_OLD:
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    pkiDebug("processing KRB5_PADATA_PK_AS_REQ_OLD %d\n", padata->pa_type);
	    retval = decode_krb5_pa_pk_as_req_draft9(&scratch, &reqp9);
	    if (retval) {
		pkiDebug("decode_krb5_pa_pk_as_req_draft9 failed");
		goto cleanup;
	    }
	    scratch.data = NULL;
	    scratch.length = 0;

	    retval = pkcs7_signeddata_verify(reqp9->signedAuthPack.data,
		reqp9->signedAuthPack.length, &scratch.data, &scratch.length, 
		&client_cert, plgctx->id_pkinit_authData9, context, plgctx);
	    if (retval) {
		pkiDebug("pkcs7_signeddata_verify failed");
		goto cleanup;
	    }
	    retval = decode_krb5_auth_pack_draft9(&scratch, &auth_pack9);
	    if (retval) {
		pkiDebug("failed to decode krb5_auth_pack_draft9\n");
		goto cleanup;
	    }
	    init_krb5_pa_pk_as_rep_draft9(&rep9);
	    if (rep9 == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }
	    break;
	default:
	    pkiDebug("unrecognized pa_type = %d\n", padata->pa_type);
	    scratch.data = NULL;
	    scratch.length = 0;
	    retval = -1;
	    goto cleanup;
    }

    if (get_filename(&filename, "KDC_CERT", 1) != 0) {
	pkiDebug("failed to get kdc cert filename\n");
	retval = -1;
	goto cleanup;
    }

    kdc_cert = get_cert(filename);
    if (filename != NULL)
	free(filename);
    filename = NULL;

    if (kdc_cert == NULL) {
	pkiDebug("unable to get kdc's certificate\n");
	retval = -1;
	goto cleanup;
    }

    if (get_filename(&filename, "KDC_KEY", 1) != 0) {
	pkiDebug("failed to get kdc key filename\n");
	retval = -1;
	goto cleanup;
    }

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

    if (auth_pack != NULL && auth_pack->clientPublicValue != NULL) {

	pkiDebug("received DH key delivery AS REQ\n");

	retval = server_process_dh(&dh_server, 
	    auth_pack->clientPublicValue->subjectPublicKey.data, 
	    auth_pack->clientPublicValue->subjectPublicKey.length,
	    auth_pack->clientPublicValue->algorithm.parameters.data, 
	    auth_pack->clientPublicValue->algorithm.parameters.length,
	    &dh_pubkey, &dh_pubkey_len, &server_key, &server_key_len);
	if (retval) {
	    pkiDebug("failed to process/create dh paramters\n");
	    goto cleanup;
	}
	rep->choice = choice_pa_pk_as_rep_dhInfo;
    } else if (auth_pack9 != NULL && auth_pack9->clientPublicValue != NULL) {
	retval = server_process_dh(&dh_server, 
	    auth_pack9->clientPublicValue->subjectPublicKey.data, 
	    auth_pack9->clientPublicValue->subjectPublicKey.length,
	    auth_pack9->clientPublicValue->algorithm.parameters.data, 
	    auth_pack9->clientPublicValue->algorithm.parameters.length,
	    &dh_pubkey, &dh_pubkey_len, &server_key, &server_key_len);
	if (retval) {
	    pkiDebug("failed to process/create dh paramters\n");
	    goto cleanup;
	}
	rep9->choice = choice_pa_pk_as_rep_draft9_dhSignedData;
    } else if (auth_pack != NULL)
	rep->choice = choice_pa_pk_as_rep_encKeyPack;
    else if (auth_pack9 != NULL)
      rep9->choice = choice_pa_pk_as_rep_draft9_encKeyPack;

    if ((rep9 != NULL && rep9->choice == choice_pa_pk_as_rep_draft9_dhSignedData) ||
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

	retval = encode_krb5_kdc_dh_key_info(&dhkey_info, &encoded_dhkey_info);
	if (retval) {
	    pkiDebug("encode_krb5_kdc_dh_key_info failed\n");
	    goto cleanup;
	}

	switch ((int)padata->pa_type) {
	    case KRB5_PADATA_PK_AS_REQ:
		retval = pkcs7_signeddata_create(encoded_dhkey_info->data,
		    encoded_dhkey_info->length,
		    &rep->u.dh_Info.dhSignedData.data,
		    &rep->u.dh_Info.dhSignedData.length,
		    kdc_cert, filename, 
		    plgctx->id_pkinit_DHKeyData, context);
		if (retval) {
		    pkiDebug("failed to create pkcs7 signed data\n");
		    goto cleanup;
		}
		break;
	    case KRB5_PADATA_PK_AS_REP_OLD:
	    case KRB5_PADATA_PK_AS_REQ_OLD:
		retval = pkcs7_signeddata_create(encoded_dhkey_info->data,
		    encoded_dhkey_info->length, &rep9->u.dhSignedData.data,
		    &rep9->u.dhSignedData.length, kdc_cert, filename, 
		    plgctx->id_pkinit_authData9, context);
		if (retval) {
		    pkiDebug("failed to create pkcs7 signed data\n");
		    goto cleanup;
		}
		break;
	}
    } else {
	pkiDebug("received public key encryption delivery AS REQ\n");

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
		retval = krb5_c_make_checksum(context, 
		    CKSUMTYPE_HMAC_SHA1_96_AES256, encrypting_key, 6, req_pkt, 
		    &key_pack->asChecksum);
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
#endif

		krb5_copy_keyblock_contents(context, encrypting_key, 
					    &key_pack->replyKey);

		retval = encode_krb5_reply_key_pack(key_pack, 
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
		retval = pkcs7_envelopeddata_create(encoded_key_pack->data,
		    encoded_key_pack->length, &rep->u.encKeyPack.data,
		    &rep->u.encKeyPack.length, client_cert, kdc_cert,
		    padata->pa_type, filename, 
		    plgctx->id_pkinit_rkeyData, context);
		break;
	    case KRB5_PADATA_PK_AS_REP_OLD:
	    case KRB5_PADATA_PK_AS_REQ_OLD:
		init_krb5_reply_key_pack_draft9(&key_pack9);
		if (key_pack9 == NULL) {
		    retval = ENOMEM;
		    goto cleanup;
		}
		key_pack9->nonce = auth_pack9->pkAuthenticator.nonce;
		krb5_copy_keyblock_contents(context, encrypting_key, 
					    &key_pack9->replyKey);

		retval = encode_krb5_reply_key_pack_draft9(key_pack9, 
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
		retval = pkcs7_envelopeddata_create(encoded_key_pack->data,
		    encoded_key_pack->length, &rep9->u.encKeyPack.data,
		    &rep9->u.encKeyPack.length, client_cert, kdc_cert,
		    padata->pa_type, filename, 
		    plgctx->id_pkinit_authData9, context);
		break;
	}
	if (retval) {
	    pkiDebug("failed to create pkcs7 enveloped data\n");
	    goto cleanup;
	}
#ifdef DEBUG_ASN1
	print_buffer_bin(encoded_key_pack->data, encoded_key_pack->length, 
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
	    retval = encode_krb5_pa_pk_as_rep(rep, &out_data);
	    break;
	case KRB5_PADATA_PK_AS_REP_OLD:
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    retval = encode_krb5_pa_pk_as_rep_draft9(rep9, &out_data);
	    break;
    }
    if (retval) {
	pkiDebug("failed to encode AS_REP\n");
	goto cleanup;
    }
#ifdef DEBUG_ASN1
    print_buffer_bin(out_data->data, out_data->length, "/tmp/kdc_as_rep");
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
    if (client_cert != NULL)
	X509_free(client_cert);
    if (kdc_cert != NULL)
	X509_free(kdc_cert);
    if (scratch.data != NULL)
	free(scratch.data);
    if (out_data != NULL)
	free(out_data);
    if (encoded_dhkey_info != NULL)
	krb5_free_data(context, encoded_dhkey_info);
    if (encoded_key_pack != NULL)
	krb5_free_data(context, encoded_key_pack);
    if (dh_server != NULL)
	DH_free(dh_server);
    if (filename != NULL)
	free(filename);

    switch ((int)padata->pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    free_krb5_pa_pk_as_req(&reqp);
	    free_krb5_auth_pack(&auth_pack);
	    free_krb5_pa_pk_as_rep(&rep);
	    free_krb5_reply_key_pack(&key_pack);
	    break;
	case KRB5_PADATA_PK_AS_REP_OLD:
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    free_krb5_pa_pk_as_req_draft9(&reqp9);
	    free_krb5_auth_pack_draft9(context, &auth_pack9);
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

#if 0
static krb5_preauthtype supported_server_pa_types[] = {
    KRB5_PADATA_PK_AS_REP_OLD,
    0
};
#else
static krb5_preauthtype supported_server_pa_types[] = {
    KRB5_PADATA_PK_AS_REQ,
    KRB5_PADATA_PK_AS_REQ_OLD,
    0
};
#endif

struct krb5plugin_preauth_server_ftable_v0 preauthentication_server_0 = {
    "pkinit",			/* name */
    supported_server_pa_types,	/* pa_type_list */
    pkinit_lib_init,		/* (*init_proc) */
    pkinit_lib_fini,		/* (*fini_proc) */
    pkinit_server_get_flags,	/* (*flags_proc) */
    pkinit_server_get_edata,	/* (*edata_proc) */
    pkinit_server_verify_padata,/* (*verify_proc) */
    pkinit_server_return_padata,/* (*return_proc) */
    NULL,			/* (*freepa_reqcontext_proc) */
};

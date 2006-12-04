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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <dlfcn.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/asn1_mac.h>
#include <openssl/sha.h>
#include <openssl/asn1.h>

#ifndef WITHOUT_PKCS11
#include <opensc/pkcs11.h>
#endif

#include <krb5/preauth_plugin.h>
#include <k5-int-pkinit.h>
#include <profile.h>
#include "pkinit.h"

/* #define DEBUG */
/* #define DEBUG_DH */
#ifdef DEBUG
#define pkiDebug(args...)       printf(args)
#else
#define pkiDebug(args...)
#endif

#define MAX_CERT_SIZE	4096
#define MAX_ID_SIZE	4
#define MAX_N_OBJS	6

#define DH_PROTOCOL	0
#define RSA_PROTOCOL	1

krb5_error_code pkinit_client_process
	(krb5_context context, void *plugin_context, void *request_context,
		preauth_get_client_data_proc get_data_proc,
		struct _krb5_preauth_client_rock *rock,
		krb5_kdc_req * request, krb5_data *encoded_request_body,
		krb5_data *encoded_previous_request, krb5_pa_data *in_padata,
		krb5_prompter_fct prompter, void *prompter_data,
		preauth_get_as_key_proc gak_fct, void *gak_data,
		krb5_data * salt, krb5_data * s2kparams,
		krb5_keyblock * as_key, krb5_pa_data ** out_padata);

krb5_error_code pkinit_client_tryagain
	(krb5_context context, void *plugin_context, void *request_context,
		preauth_get_client_data_proc get_data_proc,
		struct _krb5_preauth_client_rock *rock,
		krb5_kdc_req * request, krb5_data *encoded_request_body,
		krb5_data *encoded_previous_request,
		krb5_pa_data *in_padata, krb5_error *err_reply,
		krb5_prompter_fct prompter, void *prompter_data,
		preauth_get_as_key_proc gak_fct, void *gak_data,
		krb5_data * salt, krb5_data * s2kparams,
		krb5_keyblock * as_key, krb5_pa_data ** out_padata);

void pkinit_client_req_init
	(krb5_context contex, void *plugin_context, void **request_context);

void pkinit_client_req_fini
	(krb5_context context, void *plugin_context, void *request_context);

krb5_error_code pkinit_as_req_create
	(krb5_context context, pkinit_context *plgctx,
		pkinit_req_context *reqctx, krb5_preauthtype pa_type,
		krb5_timestamp ctsec, krb5_int32 cusec, krb5_ui_4 nonce,
		const krb5_checksum * cksum, krb5_principal server,
		X509 * client_cert, STACK_OF(X509) * trusted_CAs,
		X509 *kdc_cert, krb5_data ** as_req);

krb5_error_code pkinit_as_rep_parse
	(krb5_context context, pkinit_context *plgctx,
		pkinit_req_context *reqctx, krb5_preauthtype pa_type,
		krb5_kdc_req * request, const krb5_data * as_rep,
		X509 * client_cert, krb5_keyblock * key_block,
		krb5_enctype etype, krb5_principal server, krb5_data *);

krb5_error_code pa_pkinit_parse_rep
	(krb5_context context, pkinit_context *plgctx,
		pkinit_req_context *reqcxt, krb5_kdc_req * request,
		krb5_pa_data * in_padata, krb5_pa_data ** out_padata,
		krb5_enctype etype, krb5_keyblock * as_key, krb5_data *);

static int using_pkcs11(void);

krb5_error_code pkinit_get_client_cert
	(const char *principal, char *filename, X509 ** client_cert);

krb5_error_code create_issuerAndSerial
	(X509 *cert, unsigned char **out, int *out_len);

static krb5_error_code client_create_dh
	(int, DH **, unsigned char **, int *, unsigned char **, int *);

static krb5_error_code client_process_dh
	(DH *, unsigned char *, long, unsigned char **, int *);

static krb5_error_code der_encode_data
	(unsigned char *, int, unsigned char **, long *);

static krb5_error_code der_decode_data
	(unsigned char *, long, unsigned char **, long *);

static krb5_error_code create_krb5_trustedCas
	(STACK_OF(X509) *, int flag, krb5_trusted_ca ***);

#ifndef WITHOUT_PKCS11
static krb5_error_code pkinit_open_session
	(krb5_context, krb5_prompter_fct, void *);

static void pkinit_close_session(void);
#endif

static void init_krb5_subject_pk_info(krb5_subject_pk_info **in);

static void free_krb5_kdc_dh_key_info(krb5_kdc_dh_key_info **in);
static void free_krb5_subject_pk_info(krb5_subject_pk_info **in);

krb5_error_code
pa_pkinit_gen_req(krb5_context context,
	  pkinit_context *plgctx,
	  pkinit_req_context *reqctx,
	  krb5_kdc_req * request,
	  krb5_pa_data * in_padata,
	  krb5_pa_data ** out_padata,
	  krb5_prompter_fct prompter,
	  void *prompter_data,
	  krb5_enctype * etype, 
		  krb5_keyblock * as_key)
{

    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    krb5_data *out_data = NULL;
    krb5_timestamp ctsec = 0;
    krb5_int32 cusec = 0;
    krb5_ui_4 nonce = 0;
    krb5_checksum cksum;
    X509 *client_cert = NULL;
    krb5_data *der_req = NULL;
    char *client_principal = NULL;
    char *server_principal = NULL;
    char *filename = NULL;
    STACK_OF(X509) *trusted_CAs = NULL;
    X509 *kdc_cert = NULL;
#if 0
    krb5_timestamp time_now;
#endif

    pkiDebug("pa_pkinit_gen_req: enctype = %d\n", *etype);
    cksum.contents = NULL;
    reqctx->patype = in_padata->pa_type;

    /* If we don't have a client cert, we're done */
    if (request->client == NULL) {
	pkiDebug("No request->client; aborting PKINIT\n");
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    retval = krb5_unparse_name(context, request->client, &client_principal);
    if (retval)
      goto cleanup;

    if (using_pkcs11()) {
#ifndef WITHOUT_PKCS11
	if (pkinit_open_session(context, prompter, prompter_data)) {
	    pkiDebug("can't open pkcs11 session\n");
	    return KRB5KDC_ERR_PREAUTH_FAILED;
	}
#endif
    } else {
	if (get_filename(&filename, "X509_USER_CERT", 0) != 0) {
	    pkiDebug("failed to get user's cert\n");
	    return KRB5KDC_ERR_PREAUTH_FAILED;
	}
    }

    retval = pkinit_get_client_cert(client_principal, filename, &client_cert);
    if (filename != NULL)
	free(filename);
    free(client_principal);
    if (retval) {
	pkiDebug("No client cert; aborting PKINIT\n");
	return retval;
    }

    /* look for optional CA list */
    if (get_filename(&filename, "X509_CA_BUNDLE", 1) != 0) {
	pkiDebug("didn't find trusted certifiers ca bundle file. "
		 "optional trustedCertifiers are not included in AS_REQ. "
		 "set X509_CA_BUNDLE environment variable.\n");
    } else {
	retval = load_trusted_certifiers(&trusted_CAs, filename);
	if (filename != NULL)
	    free(filename);
    }

    /* checksum of the encoded KDC-REQ-BODY */
    retval = encode_krb5_kdc_req_body(request, &der_req);
    if (retval) {
	pkiDebug("encode_krb5_kdc_req_body returned %d\n", (int) retval);
	goto cleanup;
    }

    retval = krb5_c_make_checksum(context, CKSUMTYPE_NIST_SHA, NULL, 0, 
				  der_req, &cksum);
    if (retval)
	goto cleanup;

    retval = krb5_us_timeofday(context, &ctsec, &cusec);
    if (retval)
	goto cleanup;

#if 0
    krb5_timeofday(context, &time_now);
    nonce = (krb5_int32) time_now;
#else
    /* XXX PKINIT RFC says that nonce in PKAuthenticator doesn't have be the
     * same as in the AS_REQ. However, if we pick a different nonce, then we
     * need to remember that info when AS_REP is returned. I'm choosing to
     * reuse the AS_REQ nonce.
     */
    nonce = request->nonce;
#endif
    retval = pkinit_as_req_create(context, plgctx, reqctx, in_padata->pa_type, 
				ctsec, cusec, nonce, &cksum, request->server,
				client_cert, trusted_CAs, kdc_cert, &out_data);
    if (retval || !out_data->length) {
	pkiDebug("error %d on pkinit_as_req_create; aborting PKINIT\n",
		 (int) retval);
	goto cleanup;
    }
    *out_padata = (krb5_pa_data *) malloc(sizeof(krb5_pa_data));
    if (*out_padata == NULL) {
	retval = ENOMEM;
	free(out_data->data);
	free(out_data);
	goto cleanup;
    }
    (*out_padata)->magic = KV5M_PA_DATA;
#if 1
    if (in_padata->pa_type == KRB5_PADATA_PK_AS_REQ_OLD)
	(*out_padata)->pa_type = KRB5_PADATA_PK_AS_REP_OLD;
    else (*out_padata)->pa_type = in_padata->pa_type;
#else
    (*out_padata)->pa_type = in_padata->pa_type;
#endif
    (*out_padata)->length = out_data->length;
    (*out_padata)->contents = (krb5_octet *) out_data->data;

    retval = 0;

  cleanup:
    if (client_cert != NULL)
	X509_free(client_cert);

    if (der_req != NULL)
	krb5_free_data(context, der_req);

    if (server_principal != NULL)
	free(server_principal);

    if (trusted_CAs != NULL)
	sk_X509_pop_free(trusted_CAs, X509_free);

    if (kdc_cert != NULL)
	X509_free(kdc_cert);

    if (out_data != NULL)
	free(out_data);

    return retval;
}

krb5_error_code
pkinit_as_req_create(krb5_context context,
		     pkinit_context *plgctx,
		     pkinit_req_context *reqctx,
		     krb5_preauthtype pa_type,
		     krb5_timestamp ctsec,
		     krb5_int32 cusec,
		     krb5_ui_4 nonce,
		     const krb5_checksum * cksum,
		     krb5_principal server,
		     X509 * cert,
		     STACK_OF(X509) * trusted_CAs,
		     X509 * kdc_cert, 
		     krb5_data ** as_req)
{
    krb5_error_code retval = ENOMEM;
    krb5_subject_pk_info *info = NULL;
    krb5_data *coded_auth_pack = NULL;
    krb5_auth_pack *auth_pack = NULL;
    krb5_pa_pk_as_req *req = NULL;
    krb5_auth_pack_draft9 *auth_pack9 = NULL;
    krb5_pa_pk_as_req_draft9 *req9 = NULL;
    int protocol = DH_PROTOCOL;
    char *filename = NULL;
#ifdef KDC_CERT
    X509 *kdc_cert = NULL;
    char *kdc_filename = NULL;
#endif

    pkiDebug("pkinit_as_req_create pa_type = %d\n", pa_type);

    /* Create the authpack */
    switch((int)pa_type) {
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    protocol = RSA_PROTOCOL;
	    init_krb5_auth_pack_draft9(&auth_pack9);
	    if (auth_pack9 == NULL) 
		goto cleanup;
	    auth_pack9->pkAuthenticator.ctime = ctsec;
	    auth_pack9->pkAuthenticator.cusec = cusec;
	    auth_pack9->pkAuthenticator.nonce = nonce;
	    auth_pack9->pkAuthenticator.kdcName = server;
	    auth_pack9->pkAuthenticator.kdcRealm.magic = 0;
	    auth_pack9->pkAuthenticator.kdcRealm.data = server->realm.data;
	    auth_pack9->pkAuthenticator.kdcRealm.length = server->realm.length;
	    free(cksum->contents);
	    break;
	case KRB5_PADATA_PK_AS_REQ:
	    init_krb5_subject_pk_info(&info);
	    if (info == NULL) 
		goto cleanup;
	    init_krb5_auth_pack(&auth_pack);
	    if (auth_pack == NULL) 
		goto cleanup;
	    auth_pack->pkAuthenticator.ctime = ctsec;
	    auth_pack->pkAuthenticator.cusec = cusec;
	    auth_pack->pkAuthenticator.nonce = nonce;
	    auth_pack->pkAuthenticator.paChecksum = *cksum;
	    auth_pack->supportedCMSTypes = NULL;
	    auth_pack->clientDHNonce.length = 0;
	    auth_pack->clientPublicValue = info;
	    break;
	default: 
	    pkiDebug("as_req: unrecognized pa_type = %d\n",
		    (int)pa_type);
	    retval = -1;
	    goto cleanup;
    }

    switch(protocol) {
	case DH_PROTOCOL:
	    pkiDebug("as_req: DH key transport algorithm\n");
	    info->algorithm.algorithm = dh_oid;

	    /* create client-side DH keys */
	    if ((retval = client_create_dh(reqctx->dh_size,
		    &reqctx->dh, &info->algorithm.parameters.data,
		    &info->algorithm.parameters.length,
		    &info->subjectPublicKey.data, 
		    &info->subjectPublicKey.length)) != 0) {
		pkiDebug("failed to create dh parameters\n");
		goto cleanup;
	    }
	    break;
	case RSA_PROTOCOL:
	    pkiDebug("as_req: RSA key transport algorithm\n");
	    switch((int)pa_type) {
		case KRB5_PADATA_PK_AS_REQ_OLD:
		    auth_pack9->clientPublicValue = NULL;
		    break;
		case KRB5_PADATA_PK_AS_REQ:
		    free_krb5_subject_pk_info(&info);
		    auth_pack->clientPublicValue = NULL;
		    break;
	    }
	    break;
	default:
	    pkiDebug("as_req: unknown key transport protocol %d\n",
		    protocol);
	    retval = -1;
	    goto cleanup;
    }

    /* Encode the authpack */
    switch((int)pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    retval = encode_krb5_auth_pack(auth_pack, &coded_auth_pack); 
	    break;
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    retval = encode_krb5_auth_pack_draft9(auth_pack9, &coded_auth_pack);
	    break;
    }
    if (retval) {
	pkiDebug("failed to encode the AuthPack %d\n", retval);
	goto cleanup;
    }
#ifdef DEBUG_ASN1
    print_buffer_bin(coded_auth_pack->data, coded_auth_pack->length, "/tmp/client_auth_pack");
#endif

    if (!using_pkcs11() && get_filename(&filename, "X509_USER_KEY", 0) != 0) {
	pkiDebug("failed to get user key filename\n");
	retval = -1;
	goto cleanup;
    }

    /* create PKCS7 object from authpack */
    switch((int)pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    init_krb5_pa_pk_as_req(&req);
	    if (req == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }
	    retval = pkcs7_signeddata_create(coded_auth_pack->data,
	       coded_auth_pack->length, &req->signedAuthPack.data,
	       &req->signedAuthPack.length, cert, filename, 
	       plgctx->id_pkinit_authData, context);
	    break;
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    init_krb5_pa_pk_as_req_draft9(&req9);
	    if (req9 == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }
	    retval = pkcs7_signeddata_create(coded_auth_pack->data,
	       coded_auth_pack->length, &req9->signedAuthPack.data, 
	       &req9->signedAuthPack.length, cert, filename,
	       plgctx->id_pkinit_authData9, context);
	    break;
    }
    krb5_free_data(context, coded_auth_pack);
    if (filename != NULL)
	free(filename);
    if (retval) {
	pkiDebug("failed to create pkcs7 signed data\n");
	goto cleanup;
    }

    /* create a list of trusted CAs */
#ifdef KDC_CERT
    get_filename(&kdc_filename, "KDC_CERT", 1);
    if (kdc_filename == NULL)
	goto cleanup;
    kdc_cert = get_cert(kdc_filename);
#endif

    switch((int)pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
#if 0
	    if (trusted_CAs) {
		create_krb5_trustedCertifiers(trusted_CAs, 
		    &req->trustedCertifiers);
	    }
#endif
#ifdef KDC_CERT
	    retval = create_issuerAndSerial(kdc_cert, &req->kdcPkId.data,
					  &req->kdcPkId.length);
	    if (retval)
		goto cleanup;
#endif
	    /* Encode the as-req */
	    retval = encode_krb5_pa_pk_as_req(req, as_req);
	    break;
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    if (trusted_CAs) {
#if 0
		create_krb5_trustedCas(trusted_CAs, 1, &req9->trustedCertifiers);
#endif
	    }
#ifdef KDC_CERT
	    retval = create_issuerAndSerial(kdc_cert, &req9->kdcCert.data,
					  &req9->kdcCert.length);
	    if (retval)
		goto cleanup;
#endif
	    /* Encode the as-req */
	    retval = encode_krb5_pa_pk_as_req_draft9(req9, as_req);
	    break;
    }
#ifdef DEBUG_ASN1
    print_buffer_bin((*as_req)->data, (*as_req)->length, "/tmp/client_as_req");
#endif

cleanup:
    switch((int)pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    free_krb5_auth_pack(&auth_pack);
	    free_krb5_pa_pk_as_req(&req);
	    break;
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    free_krb5_pa_pk_as_req_draft9(&req9);
	    free(auth_pack9);
	    break;
    }
	

    pkiDebug("pkinit_as_req_create retval=%d\n", (int) retval);

    return retval;
}

static krb5_error_code
create_krb5_trustedCas(STACK_OF(X509) * sk,
		       int flag,
		       krb5_trusted_ca *** ids)
{
    krb5_error_code retval = ENOMEM;
    int i = 0, len = 0, sk_size = sk_X509_num(sk);
    krb5_trusted_ca **krb5_cas = NULL;
    X509 *x = NULL;
    char buf[256];
    X509_NAME *xn = NULL;
    unsigned char *p = NULL;
    PKCS7_ISSUER_AND_SERIAL *is = NULL;

    *ids = NULL;
    krb5_cas = malloc((sk_size + 1) * sizeof(krb5_trusted_ca *));
    if (krb5_cas == NULL)
	return ENOMEM;
    krb5_cas[sk_size] = NULL;

    for (i = 0; i < sk_size; i++) {
	krb5_cas[i] = malloc(sizeof(krb5_trusted_ca));
	if (krb5_cas[i] == NULL) 
	    goto cleanup;
	x = sk_X509_value(sk, i);

	X509_NAME_oneline(X509_get_subject_name(x), buf, 256);
	pkiDebug("#%d cert= %s\n", i, buf);

	switch (flag) {
	    case choice_trusted_cas_principalName:
		krb5_cas[i]->choice = choice_trusted_cas_principalName;
		break;
	    case choice_trusted_cas_caName:
		krb5_cas[i]->choice = choice_trusted_cas_caName;
		krb5_cas[i]->u.caName.data = NULL;
		krb5_cas[i]->u.caName.length = 0;
		xn = X509_get_subject_name(x);
		len = i2d_X509_NAME(xn, NULL);
		if ((p = krb5_cas[i]->u.caName.data = 
		    malloc((size_t) len)) == NULL) 
		    goto cleanup;
		i2d_X509_NAME(xn, &p);
		krb5_cas[i]->u.caName.length = len;
		break;
	    case choice_trusted_cas_issuerAndSerial:
		krb5_cas[i]->choice = choice_trusted_cas_issuerAndSerial;
		krb5_cas[i]->u.issuerAndSerial.data = NULL;
		krb5_cas[i]->u.issuerAndSerial.length = 0;
		is = PKCS7_ISSUER_AND_SERIAL_new();
		X509_NAME_set(&is->issuer, X509_get_issuer_name(x));
		M_ASN1_INTEGER_free(is->serial);
		is->serial = M_ASN1_INTEGER_dup(X509_get_serialNumber(x));
		len = i2d_PKCS7_ISSUER_AND_SERIAL(is, NULL);
		if ((p = krb5_cas[i]->u.issuerAndSerial.data =
		    malloc((size_t) len)) == NULL) 
		    goto cleanup;
		i2d_PKCS7_ISSUER_AND_SERIAL(is, &p);
		krb5_cas[i]->u.issuerAndSerial.length = len;
		if (is != NULL) {
		    if (is->issuer != NULL)
			X509_NAME_free(is->issuer);
		    if (is->serial != NULL)
			ASN1_INTEGER_free(is->serial);
		    free(is);
		}
		break;
	    default: break;
	}
    }
    retval = 0;
    *ids = krb5_cas;
cleanup:
    if (retval) 
	free_krb5_trusted_ca(&krb5_cas);

    return retval;
}


krb5_error_code
pa_pkinit_parse_rep(krb5_context context,
		    pkinit_context *plgctx,
		    pkinit_req_context *reqctx,
		    krb5_kdc_req * request,
		    krb5_pa_data * in_padata,
		    krb5_pa_data ** out_padata,
		    krb5_enctype etype, 
		    krb5_keyblock * as_key,
		    krb5_data *encoded_request) 
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    krb5_data asRep;
    X509 *client_cert = NULL;
    char *princ_name = NULL;
    char *filename = NULL;

    /*
     * One way or the other - success or failure - no other PA systems can
     * work if the server sent us a PKINIT reply, since only we know how to
     * decrypt the key.
     */
    *out_padata = NULL;
    if ((in_padata == NULL) || (in_padata->length == 0)) {
	pkiDebug("pa_pkinit_parse_rep: no in_padata\n");
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    /* If we don't have a client cert, we're done */
    if (request->client == NULL) {
	pkiDebug("No request->client; aborting PKINIT\n");
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    pkiDebug("pa_pkinit_parse_rep: enctype = %d\n", etype);
    retval = krb5_unparse_name(context, request->client, &princ_name);
    if (retval)
	return retval;

    if (!using_pkcs11() && get_filename(&filename, "X509_USER_CERT", 0) != 0) {
	pkiDebug("failed to get user's cert\n");
	retval = -1;
	goto cleanup;
    }
    retval = pkinit_get_client_cert(princ_name, filename, &client_cert);
    if (filename != NULL)
	free(filename);
    if (retval) {
	pkiDebug("No client cert; aborting PKINIT\n");
	goto cleanup;
    }

    asRep.data = (char *) in_padata->contents;
    asRep.length = in_padata->length;

    retval =
	pkinit_as_rep_parse(context, plgctx, reqctx, in_padata->pa_type, 
			    request, &asRep, client_cert, as_key, 
			    etype, request->server, encoded_request);
    if (retval) {
	pkiDebug("pkinit_as_rep_parse returned %d\n", (int) retval);
	goto cleanup;
    }

    retval = 0;

cleanup:
    if (princ_name)
	free(princ_name);
    if (client_cert != NULL)
	X509_free(client_cert);

    return retval;
}

/*
 * Parse PA-PK-AS-REP message. Optionally evaluates the message's certificate chain.
 * Optionally returns various components.
 */
krb5_error_code
pkinit_as_rep_parse(krb5_context context,
		    pkinit_context *plgctx,
  		    pkinit_req_context *reqctx,
		    krb5_preauthtype pa_type,
		    krb5_kdc_req * request,
		    const krb5_data * as_rep,
		    X509 * client_cert,
		    krb5_keyblock * key_block,
		    krb5_enctype etype,
		    krb5_principal server,
		    krb5_data *encoded_request)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    krb5_pa_pk_as_rep *kdc_reply = NULL;
    krb5_kdc_dh_key_info *kdc_dh = NULL;
    krb5_reply_key_pack *key_pack = NULL;
    krb5_reply_key_pack_draft9 *key_pack9 = NULL;
    krb5_data dh_data = { 0, 0, NULL };
    X509 *kdc_cert = NULL;
    unsigned char *client_key = NULL, *data_der = NULL;
    int client_key_len = 0;
    long der_len = 0;
    char *filename = NULL;
    krb5_checksum cksum = {0, 0, 0, NULL};
    int i = 0;
    krb5_principal tmp_server;

    assert((as_rep != NULL) && (key_block != NULL));

#ifdef DEBUG_ASN1
    print_buffer_bin(as_rep->data, as_rep->length, "/tmp/client_as_rep");
#endif

    if ((retval = decode_krb5_pa_pk_as_rep(as_rep, &kdc_reply))) {
	pkiDebug("decode_krb5_as_rep failed %d\n", retval);
	return retval;
    }

    switch(kdc_reply->choice) {
	case choice_pa_pk_as_rep_dhInfo:
	    pkiDebug("as_rep: DH key transport algorithm\n");
	    if ((retval = pkcs7_signeddata_verify(
		    kdc_reply->u.dh_Info.dhSignedData.data,
		    kdc_reply->u.dh_Info.dhSignedData.length,
		    &dh_data.data, &dh_data.length, &kdc_cert,
		    plgctx->id_pkinit_DHKeyData, context, plgctx)) != 0) {
		pkiDebug("failed to verify pkcs7 signed data\n");
		goto cleanup;
	    }

	    break;
	case choice_pa_pk_as_rep_encKeyPack:
	    pkiDebug("as_rep: RSA key transport algorithm\n");
	    if (!using_pkcs11() && get_filename(&filename, "X509_USER_KEY", 0) != 0) {
		pkiDebug("failed to get client's key filename\n");
		goto cleanup;
	    }
	    if ((retval = pkcs7_envelopeddata_verify(
		    kdc_reply->u.encKeyPack.data,
		    kdc_reply->u.encKeyPack.length,
		    &dh_data.data, &dh_data.length, client_cert, filename, 
		    pa_type, plgctx, &kdc_cert, context)) != 0) {
		pkiDebug("failed to verify pkcs7 enveloped data\n");
		goto cleanup;
	    }
	    if (filename != NULL)
		free(filename);
	    break;
	default:
	    pkiDebug("unknown as_rep type %d\n", kdc_reply->choice);
	    retval = -1;
	    goto cleanup;
    }
    
    if (reqctx->require_san) {
	if (!verify_id_pkinit_san(kdc_cert, &tmp_server, context, pa_type, 
				  plgctx)) {
	    pkiDebug("failed to verify id-pkinit-san\n");
	    retval = KRB5KDC_ERR_KDC_NOT_TRUSTED;
	    goto cleanup;
	} else {
	    if (pa_type == KRB5_PADATA_PK_AS_REP && tmp_server != NULL) {
		retval = krb5_principal_compare(context, server, tmp_server);
		krb5_free_principal(context, tmp_server);
		if (!retval) {
		    pkiDebug("identity in the certificate does not match "
			    "the requested principal\n");
		    retval = KRB5KDC_ERR_KDC_NAME_MISMATCH;
		    goto cleanup;
		}
	    } else if (pa_type == KRB5_PADATA_PK_AS_REP_OLD) {
		if (reqctx->require_hostname_match) {
		    /* XXX  should this be tied with require_san? */
		    pkiDebug("XXX need to check dnsName against KDC's hostname\n");
		    retval = KRB5KDC_ERR_KDC_NOT_TRUSTED;
		    goto cleanup;
		} else {
		    pkiDebug("config options says skip hostname check\n");
		}
	    }
	}
    } else {
	pkiDebug("config option says not to check for SAN\n");
    }

    if (!verify_id_pkinit_eku(plgctx, kdc_cert, pa_type, reqctx->require_eku)) {
	pkiDebug("failed to verify id-pkinit-KPKdc\n");
	retval = KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE;
	goto cleanup;
    }

    switch(kdc_reply->choice) {
	case choice_pa_pk_as_rep_dhInfo:
#ifdef DEBUG_ASN1
	    print_buffer_bin(dh_data.data, dh_data.length, "/tmp/client_dh_key");
#endif
	    if ((retval = decode_krb5_kdc_dh_key_info(&dh_data,
						    &kdc_dh)) != 0) {
		pkiDebug("failed to decode kdc_dh_key_info\n");
		goto cleanup;
	    }

	    if (der_decode_data(kdc_dh->subjectPublicKey.data,
				kdc_dh->subjectPublicKey.length,
				&data_der, &der_len) != 0) {
		pkiDebug("failed to decode subjectPublicKey\n");
		retval = -1;
		goto cleanup;
	    }

	    /* client after KDC reply */
	    if ((retval = client_process_dh(reqctx->dh, data_der,
					  der_len, &client_key,
					  &client_key_len)) != 0) {
		pkiDebug("failed to process dh params\n");
		goto cleanup;
	    }

	    retval = pkinit_octetstring2key(context, etype, client_key,
					  client_key_len, key_block);
	    if (retval) {
		pkiDebug("failed to create key pkinit_octetstring2key %s\n",
			 error_message(retval));
		goto cleanup;
	    }

	    break;
	case choice_pa_pk_as_rep_encKeyPack:
#ifdef DEBUG_ASN1
	    print_buffer_bin(dh_data.data, dh_data.length, "/tmp/client_key_pack");
#endif
	    if ((retval = decode_krb5_reply_key_pack(&dh_data, 
		    &key_pack)) != 0) {
		pkiDebug("failed to decode reply_key_pack\n");
		if (pa_type == KRB5_PADATA_PK_AS_REP)
		    goto cleanup;
		else {
		    if ((retval = 
			decode_krb5_reply_key_pack_draft9(&dh_data, 
							  &key_pack9)) != 0) {
			pkiDebug("failed to decode reply_key_pack_draft9\n");
			goto cleanup;
		    }
		    pkiDebug("decode reply_key_pack_draft9\n");
		    if (key_pack9->nonce != request->nonce) {
			pkiDebug("nonce in AS_REP=%d doesn't match AS_REQ=%d\n", key_pack9->nonce, request->nonce);
			retval = -1;
			goto cleanup;
		    }
		    krb5_copy_keyblock_contents(context, &key_pack9->replyKey,
						key_block);
		    break;
		}
	    }
	    /* this is hack but windows sends back sha1 checksum
	     * with checksum type of 14. mit has no 14 checksum type
	     */
	    if (key_pack->asChecksum.checksum_type == 14)
		key_pack->asChecksum.checksum_type = CKSUMTYPE_NIST_SHA;
	    retval = krb5_c_make_checksum(context, 
		key_pack->asChecksum.checksum_type,
		&key_pack->replyKey, KRB5_KEYUSAGE_TGS_REQ_AUTH_CKSUM, 
		encoded_request, &cksum);
	    if (retval) {
		pkiDebug("failed to make a checksum\n");
		goto cleanup;
	    }

	    if ((cksum.length != key_pack->asChecksum.length) ||
		memcmp(cksum.contents, key_pack->asChecksum.contents,
			cksum.length)) {
		pkiDebug("failed to match the checksums\n");
#ifdef DEBUG_CKSUM
	    pkiDebug("calculating checksum on buf size (%d)\n", encoded_request->length);
	    print_buffer(encoded_request->data, encoded_request->length);
	    pkiDebug("encrypting key (%d)\n", key_pack->replyKey.length);
	    print_buffer(key_pack->replyKey.contents, key_pack->replyKey.length);
		pkiDebug("received checksum type=%d size=%d ", key_pack->asChecksum.checksum_type, key_pack->asChecksum.length);
		print_buffer(key_pack->asChecksum.contents, key_pack->asChecksum.length);
		pkiDebug("expected checksum type=%d size=%d ", cksum.checksum_type, cksum.length);
		print_buffer(cksum.contents, cksum.length);
#endif
		goto cleanup;
	    } else
		pkiDebug("checksums match\n");

	    krb5_copy_keyblock_contents(context, &key_pack->replyKey, key_block);

	    break;
	default:
	    pkiDebug("unknow as_rep type %d\n", kdc_reply->choice);
	    goto cleanup;
    }

    retval = 0;

cleanup:
    if (dh_data.data != NULL)
	free(dh_data.data);
    if (data_der != NULL)
	free(data_der);
    if (client_key != NULL)
	free(client_key);
    if (kdc_cert != NULL)
	X509_free(kdc_cert);
    free_krb5_kdc_dh_key_info(&kdc_dh);
    free_krb5_pa_pk_as_rep(&kdc_reply);
   
    if (key_pack != NULL) {
	free_krb5_reply_key_pack(&key_pack);
	if (cksum.contents != NULL)
	    free(cksum.contents);
    } else if (key_pack9 != NULL)
	free_krb5_reply_key_pack_draft9(&key_pack9);

    pkiDebug("pkinit_as_rep_parse retval=%d\n", (int) retval);
    return retval;
}

void
pkinit_client_profile(krb5_context context,
		      pkinit_context *plgctx,
		      pkinit_req_context *reqctx,
		      krb5_kdc_req *request)
{
    profile_t profile;
    krb5_error_code retval;
    char *realmname = NULL;

    if (request->server && request->server->realm.length) {
	realmname = malloc(request->server->realm.length + 1);
	if (NULL != realmname) {
	    memcpy(realmname, request->server->realm.data,
		   request->server->realm.length);
	    realmname[request->server->realm.length] = '\0';
	}
    }
    if (NULL == realmname)
	return;

    retval = krb5_get_profile(context, &profile);
    if (retval) {
	free(realmname);
	return;
    }

    profile_get_boolean(profile, "realms", realmname,
			"pkinit_win2k",
			reqctx->win2k_target, &reqctx->win2k_target);
    profile_get_boolean(profile, "realms", realmname,
			"pkinit_win2k_require_binding",
			reqctx->win2k_require_cksum,
			&reqctx->win2k_require_cksum);

    profile_get_boolean(profile, "realms", realmname,
			"pkinit_require_eku",
			reqctx->require_eku, &reqctx->require_eku);
    profile_get_boolean(profile, "realms", realmname,
			"pkinit_require_krbtgt_otherName",
			reqctx->require_san, &reqctx->require_san);
    profile_get_boolean(profile, "realms", realmname,
			"pkinit_require_hostname_match",
			reqctx->require_hostname_match,
			&reqctx->require_hostname_match);
    free(realmname);
    profile_release(profile);
}

krb5_error_code
pkinit_client_process(krb5_context context,
		      void *plugin_context,
		      void *request_context,
		      preauth_get_client_data_proc get_data_proc,
		      struct _krb5_preauth_client_rock *rock,
		      krb5_kdc_req *request,
		      krb5_data *encoded_request_body,
		      krb5_data *encoded_previous_request,
		      krb5_pa_data *in_padata,
		      krb5_prompter_fct prompter,
		      void *prompter_data,
		      preauth_get_as_key_proc gak_fct,
		      void *gak_data,
		      krb5_data *salt,
		      krb5_data *s2kparams,
		      krb5_keyblock *as_key,
		      krb5_pa_data **out_padata)
{
    krb5_error_code r = -1;
    krb5_enctype enctype = -1;
    krb5_data *cdata;
    pkinit_context *plgctx = (pkinit_context *)plugin_context;
    pkinit_req_context *reqctx = (pkinit_req_context *)request_context;

    /*
     * Get enctype of reply, if available.  It won't be available
     * if we were called to handle a request, so just ignore the
     * error in that case.  We check below that we have it if we
     * really need it.
     */
    r = (*get_data_proc)(context, rock, krb5plugin_preauth_client_get_etype,
			 &cdata);
    if (r != 0 && r != ENOENT)
	return r;
    if (r == 0) {
	enctype = *((krb5_enctype *)cdata->data);
	(*get_data_proc)(context, rock, krb5plugin_preauth_client_free_etype,
			 &cdata);
    }
    pkinit_client_profile(context, plgctx, reqctx, request);
    switch ((int) in_padata->pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    pkiDebug("processing KRB5_PADATA_PK_AS_REQ\n");
	    r = pa_pkinit_gen_req(context, plgctx, reqctx, request, in_padata, 
				  out_padata, prompter, prompter_data, &enctype, as_key);
	    break;

	case KRB5_PADATA_PK_AS_REP:
	    pkiDebug("processing KRB5_PADATA_PK_AS_REP\n");
	    if (enctype == -1)
		return EINVAL;	/* XXX */
	    r = pa_pkinit_parse_rep(context, plgctx, reqctx,
				    request, in_padata, out_padata, enctype, 
				    as_key, encoded_previous_request);
	    break;
	case KRB5_PADATA_PK_AS_REP_OLD:
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    if (in_padata->length == 0) {
		pkiDebug("processing KRB5_PADATA_PK_AS_REQ_OLD\n");
		in_padata->pa_type = KRB5_PADATA_PK_AS_REQ_OLD;
		r = pa_pkinit_gen_req(context, plgctx, reqctx, request,
				      in_padata, out_padata, prompter, prompter_data,
				      &enctype, as_key);
	    } else {
		pkiDebug("processing KRB5_PADATA_PK_AS_REP_OLD\n");
		if (enctype == -1)
		    return EINVAL;  /* XXX */
		in_padata->pa_type = KRB5_PADATA_PK_AS_REP_OLD;
		r = pa_pkinit_parse_rep(context, plgctx, reqctx,
					request, in_padata, out_padata, 
					enctype, as_key, encoded_previous_request);
	    }
	    break;
	default:
	    pkiDebug("unrecognized patype = %d for PKINIT\n", 
		    in_padata->pa_type);
    }
    return r;
}

static krb5_error_code
pkinit_decode_td_dh_params(krb5_data *data,
			   pkinit_context *plgctx, 
			   pkinit_req_context *reqctx)
{
    krb5_error_code retval = ENOMEM;
    krb5_algorithm_identifier **algId = NULL;
    int i = 0, ok = 0, free_dh = 1;

    retval = decode_krb5_td_dh_parameters(data, &algId);
    if (retval) {
	pkiDebug("decode_krb5_td_dh_parameters failed\n");
	goto cleanup;
    }
    while (algId[i] != NULL) {
	DH *dh = NULL;
	unsigned char *tmp = NULL;
	int dh_prime_bits = 0, dh_err = 0;

	if (algId[i]->algorithm.length != dh_oid.length ||
	    memcmp(algId[i]->algorithm.data, dh_oid.data, dh_oid.length))
	    goto cleanup;
	tmp = algId[i]->parameters.data;  
	dh = DH_new();
	dh = pkinit_decode_dh_params(&dh, &tmp, algId[i]->parameters.length);
	dh_prime_bits = BN_num_bits(dh->p);
	pkiDebug("client sent %d DH bits server prefers %d DH bits\n",
		 reqctx->dh_size, dh_prime_bits);
	switch(dh_prime_bits) {
	    case 1024:
		if (!pkinit_check_dh_params(plgctx->dh_1024->p, dh->p, dh->g, 
			dh->q)) {
		    reqctx->dh_size = 1024;
		    ok = 1;
		}
		break;
	    case 2048:
		if (!pkinit_check_dh_params(plgctx->dh_2048->p, dh->p, dh->g,
			dh->q)) {
		    reqctx->dh_size = 2048;
		    ok = 1;
		}
		break;
	    case 4096:
		if (!pkinit_check_dh_params(plgctx->dh_4096->p, dh->p, dh->g,
			dh->q)) {
		    reqctx->dh_size = 4096;
		    ok = 1;
		}
		break;
	    default:
		break;
	}
	if (!ok) { 
	    DH_check(dh, &retval);
	    if (retval != 0) 
		pkiDebug("DH parameter provided by server is bad\n");
	    else
		free_dh = 0;
	}
	DH_free(dh);
	if (ok)	{
	    if (free_dh) {
		if (reqctx->dh != NULL)
		    DH_free(reqctx->dh);
		reqctx->dh = NULL;
	    }
	    break;
	}
	i++;
    }
    if (ok) 
	retval = 0;
cleanup:
    if (algId != NULL)
	free_krb5_algorithm_identifier(&algId);

    return retval; 
}

krb5_error_code
pkinit_client_tryagain(krb5_context context,
		       void *plugin_context,
		       void *request_context,
		       preauth_get_client_data_proc get_data_proc,
		       struct _krb5_preauth_client_rock *rock,
		       krb5_kdc_req *request,
		       krb5_data *encoded_request_body,
		       krb5_data *encoded_previous_request,
		       krb5_pa_data *in_padata,
		       krb5_error *err_reply,
		       krb5_prompter_fct prompter,
		       void *prompter_data,
		       preauth_get_as_key_proc gak_fct,
		       void *gak_data,
		       krb5_data *salt,
		       krb5_data *s2kparams,
		       krb5_keyblock *as_key,
		       krb5_pa_data **out_padata)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    krb5_typed_data **typed_data = NULL;
    krb5_data scratch;
    pkinit_context *plgctx = (pkinit_context *)plugin_context;
    pkinit_req_context *reqctx = (pkinit_req_context *)request_context;
    krb5_external_principal_identifier **krb5_trusted_certifiers = NULL;
    int i = 0, do_again = 0;
    const unsigned char *p;
    STACK_OF(X509_NAME) *sk_xn = NULL;
    X509_NAME *xn = NULL;
    STACK_OF(PKCS7_ISSUER_AND_SERIAL) *sk_is = NULL;
    PKCS7_ISSUER_AND_SERIAL *is = NULL;
    STACK_OF(ASN1_OCTET_STRING) *sk_id = NULL;
    ASN1_OCTET_STRING *id = NULL;

    if (reqctx->patype != in_padata->pa_type)
	return retval;

    pkiDebug("%s: DUMMY version called!\n", __FUNCTION__);
#ifdef DEBUG_ASN1
    print_buffer_bin(err_reply->e_data.data, err_reply->e_data.length, "/tmp/client_edata");
#endif
    retval = decode_krb5_typed_data(&err_reply->e_data, &typed_data);
    if (retval) {
	pkiDebug("decode_krb5_typed_data failed\n");
	goto cleanup;
    }
#ifdef DEBUG_ASN1
    print_buffer_bin(typed_data[0]->data, typed_data[0]->length, "/tmp/client_typed_data");
#endif
    scratch.data = typed_data[0]->data;
    scratch.length = typed_data[0]->length;


    switch(typed_data[0]->type) {
	case TD_TRUSTED_CERTIFIERS:
	case TD_INVALID_CERTIFICATES:
	    sk_xn = sk_X509_NAME_new_null();
	    if (typed_data[0]->type == TD_TRUSTED_CERTIFIERS)
		pkiDebug("trusted certifiers\n");
	    else
		pkiDebug("invalid certificate\n");
	    retval = decode_krb5_td_trusted_certifiers(&scratch, &krb5_trusted_certifiers);
	    if (retval) {
		pkiDebug("failed to decode sequence of trusted certifiers\n");
		goto cleanup;
	    }
	    while(krb5_trusted_certifiers[i] != NULL) {
		if (krb5_trusted_certifiers[i]->subjectName.data != NULL) {
		    p = krb5_trusted_certifiers[i]->subjectName.data;
		    xn = d2i_X509_NAME(NULL, &p, krb5_trusted_certifiers[i]->subjectName.length);
		    if (xn == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    } else {
			char buf[256];
			X509_NAME_oneline(xn, buf, 256);
			if (typed_data[0]->type == TD_TRUSTED_CERTIFIERS)
			    pkiDebug("#%d cert = %s is trusted by kdc\n", i, buf);
			else
			    pkiDebug("#%d cert = %s is invalid\n", i, buf);
			sk_X509_NAME_push(sk_xn, xn);
		    }
		}
		if (krb5_trusted_certifiers[i]->issuerAndSerialNumber.data != NULL) {
		    p = krb5_trusted_certifiers[i]->issuerAndSerialNumber.data;
		    is = d2i_PKCS7_ISSUER_AND_SERIAL(NULL, &p, krb5_trusted_certifiers[i]->issuerAndSerialNumber.length);
		    if (is == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    } else {
			char buf[256];
			X509_NAME_oneline(is->issuer, buf, 256);
			if (typed_data[0]->type == TD_TRUSTED_CERTIFIERS)
			    pkiDebug("#%d issuer = %s serial = %ld is trusted bu kdc\n", i, buf, ASN1_INTEGER_get(is->serial));
			else
			    pkiDebug("#%d issuer = %s serial = %ld is invalid\n", i, buf, ASN1_INTEGER_get(is->serial));
		    }
		    PKCS7_ISSUER_AND_SERIAL_free(is);
		}
		if (krb5_trusted_certifiers[i]->subjectKeyIdentifier.data != NULL) {
		    p = krb5_trusted_certifiers[i]->subjectKeyIdentifier.data;
		    id = d2i_ASN1_OCTET_STRING(NULL, &p, krb5_trusted_certifiers[i]->subjectKeyIdentifier.length);
		    if (id == NULL) {
			retval = ENOMEM;
			goto cleanup;
		    } else {
			/* XXX */
		    }
		    ASN1_OCTET_STRING_free(id);
		}
		i++;
	    }
	    break;
	case TD_DH_PARAMETERS:
	    pkiDebug("dh parameters\n");
	    retval = pkinit_init_dh_params(context, plgctx);
	    if (retval)
		goto cleanup;
	    retval = pkinit_decode_td_dh_params(&scratch, plgctx, reqctx);
	    if (!retval) 
		do_again = 1;
	    pkinit_fini_dh_params(context, plgctx);
	    break;
	default:
	    break;
    }

    if (do_again) {
	krb5_enctype enctype = -1;
	if (reqctx->dh) {
	    DH_free(reqctx->dh);
	    reqctx->dh = NULL;
	}
	retval = pa_pkinit_gen_req(context, plgctx, reqctx, request, in_padata,
	    out_padata, prompter, prompter_data, &enctype, as_key);
	if (retval)
	    goto cleanup;
    }
	
    retval = 0;
cleanup:
    if (sk_xn != NULL) 
	sk_X509_NAME_pop_free(sk_xn, X509_NAME_free);

    if (krb5_trusted_certifiers != NULL)
	free_krb5_external_principal_identifier(&krb5_trusted_certifiers);

    if (typed_data != NULL)
	free_krb5_typed_data(&typed_data);

    return retval;
}

#define PKINIT_REQ_CTX_MAGIC 0xdeadbeef
void
pkinit_client_req_init(krb5_context context,
		       void *plugin_context,
		       void **request_context)
{

    pkinit_req_context *reqctx;
    pkinit_context *plgctx = (pkinit_context *)plugin_context;

    *request_context = NULL;

    reqctx = (pkinit_req_context *) malloc(sizeof(*reqctx));
    if (reqctx == NULL)
	return;

    reqctx->magic = PKINIT_REQ_CTX_MAGIC;
    reqctx->dh = NULL;
    reqctx->dh_size = 1024;
    reqctx->require_eku = plgctx->require_eku;
    reqctx->require_san = plgctx->require_san;
    reqctx->require_hostname_match = 0;
    reqctx->allow_upn = plgctx->allow_upn;
    reqctx->require_crl_checking = plgctx->require_crl_checking;

    *request_context = (void *) reqctx;
    pkiDebug("%s: returning reqctx at %p\n", __FUNCTION__, reqctx);
    return;
}

void
pkinit_client_req_fini(krb5_context context,
		      void *plugin_context,
		      void *request_context)
{
    pkinit_req_context *reqctx = (pkinit_req_context *)request_context;

    pkiDebug("%s: received reqctx at %p\n", __FUNCTION__, reqctx);
#ifndef WITHOUT_PKCS11
    pkinit_close_session();
#endif
    if (reqctx != NULL) {
	if (reqctx->magic != PKINIT_REQ_CTX_MAGIC) {
	    pkiDebug("%s: Bad magic value (%x) in req ctx\n",
		    __FUNCTION__, reqctx->magic);
	    return;
	}
	if (reqctx->dh != NULL) {
	    DH_free(reqctx->dh);
	}
	free(reqctx);
    }
    return;
}

static int
using_pkcs11(void)
{
#ifdef WITHOUT_PKCS11
    return 0;
#else
    return (getenv("PKCS11") != NULL);
#endif
}

#ifndef WITHOUT_PKCS11

static char *module_name = "opensc-pkcs11.so";
static void *module = NULL;
static unsigned int slotid = 0;
static CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
static CK_FUNCTION_LIST_PTR p11 = NULL;
static CK_BYTE cert_id[MAX_ID_SIZE];
static int cert_id_len;

void *
C_LoadModule(const char *modname, CK_FUNCTION_LIST_PTR_PTR p11p)
{
    void *handle;
    CK_RV (*getflist)(CK_FUNCTION_LIST_PTR_PTR);

    pkiDebug("loading module \"%s\"... ", modname);
    handle = dlopen(modname, RTLD_NOW);
    getflist = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR)) dlsym(handle, "C_GetFunctionList");
    if (getflist == NULL || (*getflist)(p11p) != CKR_OK) {
	dlclose(handle);
	pkiDebug("failed\n");
	return NULL;
    }
    pkiDebug("ok\n");
    return handle;
}

CK_RV
C_UnloadModule(void *handle)
{
    dlclose(handle);
    return CKR_OK;
}

static krb5_error_code
pkinit_open_session(krb5_context context,
		    krb5_prompter_fct prompter,
		    void *prompter_data)
{
    int r;
    char *s;
    char pin[32];
    char custom_module_name[100];
    krb5_data response_data;
    krb5_prompt kprompt;
    krb5_prompt_type prompt_type;

    if (module != NULL)
	return 0;

    /* Temporary pending use of krb5.conf */
    if ((s = getenv("PKCS11")) != NULL && strlen(s) > 0) {
	if (sscanf(s, "%99[^:]:%d", custom_module_name, &slotid) < 2)
	    slotid = atoi(s);
	else
	    module_name = custom_module_name;
    }

    /* Load module, init, and open session */
    module = C_LoadModule(module_name, &p11);
    if (module == NULL) {
	pkiDebug("fail C_LoadModule\n");
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    if ((r = p11->C_Initialize(NULL)) != CKR_OK) {
	pkiDebug("fail C_Initialize %x\n", r);
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    pkiDebug("opening slot %d\n", slotid);
    if ((r = p11->C_OpenSession(slotid, CKF_SERIAL_SESSION, NULL, NULL, &session)) !=
	CKR_OK) {
	pkiDebug("fail C_OpenSession %x\n", r);
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    response_data.data = pin;
    response_data.length = sizeof(pin);

    kprompt.prompt = "PIN";
    kprompt.hidden = 1;
    kprompt.reply = &response_data;
    prompt_type = KRB5_PROMPT_TYPE_PREAUTH;

    /* PROMPTER_INVOCATION */
    krb5int_set_prompt_types(context, &prompt_type);
    if ((r = ((*prompter)(context, prompter_data, NULL, NULL, 1, &kprompt)))) {
	krb5int_set_prompt_types(context, 0);
	return r;
    }
    krb5int_set_prompt_types(context, 0);

    if ((r = p11->C_Login(session, CKU_USER, (u_char *) pin, response_data.length)) != CKR_OK) {
	pkiDebug("fail C_Login %x\n", r);
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    return 0;
}

static void
pkinit_close_session(void)
{
    if (p11) {
	if (session) {
	    p11->C_CloseSession(session);
	    session = CK_INVALID_HANDLE;
	}
	p11->C_Finalize(NULL_PTR);
	p11 = NULL;
    }
    if (module) {
	C_UnloadModule(module);
	module = NULL;
    }
}
#endif

krb5_error_code
pkinit_get_client_cert(const char *principal,
		       char *filename, 
		       X509 ** client_cert)
{
#ifndef WITHOUT_PKCS11
    CK_OBJECT_CLASS cls;
    CK_OBJECT_HANDLE objs[MAX_N_OBJS];
    CK_ATTRIBUTE attrs[2];
    CK_ULONG count;
    CK_CERTIFICATE_TYPE certtype;
    krb5_octet cert[MAX_CERT_SIZE];
    const unsigned char *cp;
    int r;
#endif

    if (!using_pkcs11()) {
	if ((*client_cert = get_cert(filename)) == NULL)
	    return KRB5KDC_ERR_PREAUTH_FAILED;
	else
	    return 0;
    }

#ifndef WITHOUT_PKCS11
    if (principal == NULL) {
	return KRB5_PRINC_NOMATCH;
    }

    pkiDebug("Reading cert for '%s' from card\n", principal);

    cls = CKO_CERTIFICATE;
    attrs[0].type = CKA_CLASS;
    attrs[0].pValue = &cls;
    attrs[0].ulValueLen = sizeof cls;

    certtype = CKC_X_509;
    attrs[1].type = CKA_CERTIFICATE_TYPE;
    attrs[1].pValue = &certtype;
    attrs[1].ulValueLen = sizeof certtype;

    if (p11->C_FindObjectsInit(session, attrs, 2) != CKR_OK) {
	pkiDebug("fail C_FindObjectsInit\n");
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    /* Look for x.509 cert */
    if ((r = p11->C_FindObjects(session, objs, 6, &count)) != CKR_OK
	|| count <= 0) {
	pkiDebug("can't find any certs %x\n", r);
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    p11->C_FindObjectsFinal(session);
    pkiDebug("found %d certs\n", (int) count);

    /*
     * Read the cert and id off the card.
     * I can't find any way to reliably get the size before doing the read.
     */
    attrs[0].type = CKA_VALUE;
    attrs[0].pValue = cert;
    attrs[0].ulValueLen = sizeof cert;

    attrs[1].type = CKA_ID;
    attrs[1].pValue = cert_id;
    attrs[1].ulValueLen = sizeof cert_id;

    /* Just take the first one. */
    if ((r = p11->C_GetAttributeValue(session, objs[0], attrs, 2)) != CKR_OK) {
	pkiDebug("fail C_GetAttributeValue %x\n", r);
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    pkiDebug("cert size %d id %d\n", (int) attrs[0].ulValueLen, (int) cert_id[0]);
    cert_id_len = attrs[1].ulValueLen;
    cp = (unsigned char *) cert;
    *client_cert = d2i_X509(NULL, &cp, (int) attrs[0].ulValueLen);
    if (*client_cert == NULL)
	return KRB5KDC_ERR_PREAUTH_FAILED;
#endif
    return 0;
}

#ifndef WITHOUT_PKCS11
krb5_error_code
pkinit_find_private_key(CK_ATTRIBUTE_TYPE usage, CK_OBJECT_HANDLE *objp)
{
    CK_OBJECT_CLASS cls;
    CK_OBJECT_HANDLE objs[MAX_N_OBJS];
    CK_ATTRIBUTE attrs[4];
    CK_ULONG count;
    CK_BBOOL bool;
    CK_KEY_TYPE keytype;
    int r;

    /*
     * Look for a key that's:
     * 1. private
     * 2. capable of the specified operation (usually signing or decrypting)
     * 3. RSA (this may be wrong but it's all we can do for now)
     * 4. matches the id of the cert we chose
     *
     * pkcs11 says the id of the key doesn't have to match that of the cert, but
     * I can't figure out any other way to decide which key to use.
     */

    cls = CKO_PRIVATE_KEY;
    attrs[0].type = CKA_CLASS;
    attrs[0].pValue = &cls;
    attrs[0].ulValueLen = sizeof cls;

    bool = TRUE;
    attrs[1].type = usage;
    attrs[1].pValue = &bool;
    attrs[1].ulValueLen = sizeof bool;

    keytype = CKK_RSA;
    attrs[2].type = CKA_KEY_TYPE;
    attrs[2].pValue = &keytype;
    attrs[2].ulValueLen = sizeof keytype;

    attrs[3].type = CKA_ID;
    attrs[3].pValue = cert_id;
    attrs[3].ulValueLen = cert_id_len;

    if (p11->C_FindObjectsInit(session, attrs, 4) != CKR_OK) {
	pkiDebug("krb5_pkinit_sign_data: fail C_FindObjectsInit\n");
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    r = p11->C_FindObjects(session, objs, 6, &count);
    p11->C_FindObjectsFinal(session);
    pkiDebug("found %d private keys %x\n", (int) count, (int) r);
    if (r != CKR_OK || count < 1)
	return KRB5KDC_ERR_PREAUTH_FAILED;
    *objp = objs[0];
    return 0;
}
#endif

krb5_error_code
pkinit_decode_data(unsigned char *data,
		   int data_len,
		   unsigned char **decoded_data,
		   int *decoded_data_len, 
		   char *filename,
		   X509 *cert)
{
#ifndef WITHOUT_PKCS11
    CK_OBJECT_HANDLE obj;
    CK_ULONG len;
    CK_MECHANISM mech;
    unsigned char txtbuf[4096], *cp;
    int r;
#endif

    if (!using_pkcs11()) {
	if (decode_data(decoded_data, decoded_data_len, data, data_len, 
			filename, cert) <= 0) {
	    pkiDebug("failed to decode data\n");
	    return KRB5KDC_ERR_PREAUTH_FAILED;
	}
	return 0;
    }

#ifndef WITHOUT_PKCS11
    pkinit_find_private_key(CKA_DECRYPT, &obj);

    mech.mechanism = CKM_RSA_PKCS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    if ((r = p11->C_DecryptInit(session, &mech, obj)) != CKR_OK) {
	pkiDebug("fail C_DecryptInit %x\n", (int) r);
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    len = sizeof txtbuf;
    pkiDebug("decrypt %d -> %d\n", (int) data_len, (int) len);
    if ((r = p11->C_Decrypt(session, (krb5_octet *) data, (u_int) data_len, txtbuf, &len)) !=
	CKR_OK) {
	pkiDebug("fail C_Decrypt %x\n", (int) r);
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    pkiDebug("txt size %d\n", (int) len);
    cp = malloc(len);
    if (cp == NULL)
	return ENOMEM;
    memcpy(cp, txtbuf, len);
    *decoded_data_len = len;
    *decoded_data = cp;
    return 0;
#endif
}

krb5_error_code
pkinit_sign_data(unsigned char *data,
		int data_len,
		unsigned char **sig,
		int *sig_len, 
		char *filename)
{
#ifndef WITHOUT_PKCS11
    CK_OBJECT_HANDLE obj;
    CK_ULONG len;
    CK_MECHANISM mech;
    unsigned char sigbuf[1024], *cp;
    int r;
#endif

    if (!using_pkcs11()) {
	if (create_signature(sig, sig_len, data, data_len, filename) != 0) {
	    pkiDebug("failed to create the signature\n");
	    return KRB5KDC_ERR_PREAUTH_FAILED;
	}
	return 0;
    }

#ifndef WITHOUT_PKCS11
    pkinit_find_private_key(CKA_SIGN, &obj);

    mech.mechanism = CKM_SHA1_RSA_PKCS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    if ((r = p11->C_SignInit(session, &mech, obj)) != CKR_OK) {
	pkiDebug("fail C_SignInit %x\n", (int) r);
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    len = sizeof sigbuf;
    pkiDebug("signing %d -> %d\n", (int) data_len, (int) len);
    if ((r = p11->C_Sign(session, (krb5_octet *) data, (u_int) data_len, sigbuf, &len)) !=
	CKR_OK) {
	pkiDebug("fail C_Sign %x\n", (int) r);
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    pkiDebug("sig size %d\n", (int) len);
    cp = malloc(len);
    if (cp == NULL)
	return ENOMEM;
    memcpy(cp, sigbuf, len);
    *sig_len = len;
    *sig = cp;
    return 0;
#endif
}

static krb5_error_code
client_create_dh(int dh_size,
		 DH ** dh_client,
		 unsigned char **dh_params,
		 int *dh_params_len,
		 unsigned char **dh_pubkey, 
		 int *dh_pubkey_len)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    unsigned char *buf = NULL;
    int dh_err = 0;
    ASN1_INTEGER *pub_key = NULL;

    if (*dh_client == NULL) {
	if ((*dh_client = DH_new()) == NULL)
	    goto cleanup;
	if (((*dh_client)->g = BN_new()) == NULL ||
	    ((*dh_client)->q = BN_new()) == NULL)
	    goto cleanup;

	switch(dh_size) {
	    case 1024:
		pkiDebug("client uses 1024 DH keys\n");
		(*dh_client)->p = get_rfc2409_prime_1024(NULL);
		break;
	    case 2048:
		pkiDebug("client uses 2048 DH keys\n");
		(*dh_client)->p = BN_bin2bn(pkinit_2048_dhprime,
		    sizeof(pkinit_2048_dhprime), NULL);
		break;
	    case 4096:
		pkiDebug("client uses 4096 DH keys\n");
		(*dh_client)->p = BN_bin2bn(pkinit_4096_dhprime,
		    sizeof(pkinit_4096_dhprime), NULL);
		break;
	    default:
		goto cleanup;
	}

	BN_set_word(((*dh_client)->g), DH_GENERATOR_2);
	BN_rshift1((*dh_client)->q, (*dh_client)->p);
    }

    DH_generate_key(*dh_client);
    DH_check(*dh_client, &dh_err);
    if (dh_err != 0) {
	pkiDebug("Warning: dh_check failed with %d\n", dh_err);
	if (dh_err & DH_CHECK_P_NOT_PRIME)
	    pkiDebug("p value is not prime\n");
	if (dh_err & DH_CHECK_P_NOT_SAFE_PRIME)
	    pkiDebug("p value is not a safe prime\n");
	if (dh_err & DH_UNABLE_TO_CHECK_GENERATOR)
	    pkiDebug("unable to check the generator value\n");
	if (dh_err & DH_NOT_SUITABLE_GENERATOR)
	    pkiDebug("the g value is not a generator\n");
    }
#ifdef DEBUG_DH
    print_dh(*dh_client, "client's DH params\n");
    print_pubkey((*dh_client)->pub_key, "client's pub_key=");
#endif

    DH_check_pub_key(*dh_client, (*dh_client)->pub_key, &dh_err);
    if (dh_err != 0) {
	pkiDebug("dh_check_pub_key failed with %d\n", dh_err);
	goto cleanup;
    }

    /* pack DHparams */
    /* aglo: usually we could just call i2d_DHparams to encode DH params
     * however, PKINIT requires RFC3279 encoding and openssl does pkcs#3.
     */
    retval = pkinit_encode_dh_params((*dh_client)->p, (*dh_client)->g, 
	(*dh_client)->q, dh_params, dh_params_len);
    if (retval)
	goto cleanup;

    /* pack DH public key */
    /* Diffie-Hellman public key must be ASN1 encoded as an INTEGER; this
     * encoding shall be used as the contents (the value) of the
     * subjectPublicKey component (a BIT STRING) of the SubjectPublicKeyInfo
     * data element
     */
    if ((pub_key = BN_to_ASN1_INTEGER((*dh_client)->pub_key, NULL)) == NULL)
	goto cleanup;
    *dh_pubkey_len = i2d_ASN1_INTEGER(pub_key, NULL);
    if ((buf = *dh_pubkey = (unsigned char *) malloc((size_t) *dh_pubkey_len)) == NULL) {
	retval  = ENOMEM;
	goto cleanup;
    }
    i2d_ASN1_INTEGER(pub_key, &buf);

    if (pub_key != NULL)
	ASN1_INTEGER_free(pub_key);

    retval = 0;
    return retval;

  cleanup:
    if (*dh_client != NULL)
	DH_free(*dh_client);
    *dh_client = NULL;
    if (*dh_params != NULL)
	free(*dh_params);
    *dh_params = NULL;
    if (*dh_pubkey != NULL)
	free(*dh_pubkey);
    *dh_pubkey = NULL;
    if (pub_key != NULL)
	ASN1_INTEGER_free(pub_key);

    return retval;
}

static krb5_error_code
client_process_dh(DH * dh_client,
		  unsigned char *data,
		  long data_len,
		  unsigned char **client_key, int *client_key_len)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    BIGNUM *server_pub_key = NULL;
    ASN1_INTEGER *pub_key = NULL;
    const unsigned char *p = data;

    *client_key_len = DH_size(dh_client);
    if ((*client_key = (unsigned char *) 
	    malloc((size_t) *client_key_len)) == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    if ((pub_key = d2i_ASN1_INTEGER(NULL, &p, data_len)) == NULL)
	goto cleanup;
    if ((server_pub_key = ASN1_INTEGER_to_BN(pub_key, NULL)) == NULL)
	goto cleanup;

    DH_compute_key(*client_key, server_pub_key, dh_client);
#ifdef DEBUG_DH
    print_pubkey(server_pub_key, "server's pub_key=");
    pkiDebug("client secret key (%d)= ", *client_key_len);
    print_buffer(*client_key, *client_key_len);
#endif

    retval = 0;
    if (server_pub_key != NULL)
	BN_free(server_pub_key);
    if (pub_key != NULL)
	ASN1_INTEGER_free(pub_key);

    return retval;

  cleanup:
    if (*client_key != NULL)
	free(*client_key);
    if (pub_key != NULL)
	ASN1_INTEGER_free(pub_key);
    return retval;
}

static krb5_error_code
der_encode_data(unsigned char *data,
		int data_len, unsigned char **out, long *out_len)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    ASN1_OCTET_STRING *s = NULL;
    unsigned char *p = NULL;

    if ((s = ASN1_OCTET_STRING_new()) == NULL)
	goto cleanup;
    if (!ASN1_STRING_set(s, data, data_len))
	goto cleanup;
    *out_len = i2d_ASN1_OCTET_STRING(s, NULL);
    if ((p = *out = (unsigned char *) malloc((size_t) *out_len)) == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    i2d_ASN1_OCTET_STRING(s, &p);

    retval = 0;
  cleanup:
    if (s != NULL)
	ASN1_OCTET_STRING_free(s);

    return retval;
}

static krb5_error_code
der_decode_data(unsigned char *data,
		long data_len, unsigned char **out, long *out_len)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    ASN1_OCTET_STRING *s = NULL;
    const unsigned char *p = data;

    if ((s = d2i_ASN1_BIT_STRING(NULL, &p, data_len)) == NULL)
	goto cleanup;
    *out_len = s->length;
    if ((*out = (unsigned char *) malloc((size_t) *out_len + 1)) == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    memcpy(*out, s->data, (size_t) s->length);
    (*out)[s->length] = '\0';

    retval = 0;
  cleanup:
    if (s != NULL)
	ASN1_OCTET_STRING_free(s);

    return retval;
}



krb5_error_code
create_issuerAndSerial(X509 *cert, 
		       unsigned char **out,
		       int *out_len)
{
    unsigned char *p = NULL;
    PKCS7_ISSUER_AND_SERIAL *is = NULL;
    int len = 0;
    krb5_error_code retval = ENOMEM;

    is = PKCS7_ISSUER_AND_SERIAL_new();
    X509_NAME_set(&is->issuer, X509_get_issuer_name(cert));
    M_ASN1_INTEGER_free(is->serial);
    is->serial = M_ASN1_INTEGER_dup(X509_get_serialNumber(cert));
    len = i2d_PKCS7_ISSUER_AND_SERIAL(is, NULL);
    if ((p = *out = malloc((size_t) len)) == NULL) 
	goto cleanup;
    i2d_PKCS7_ISSUER_AND_SERIAL(is, &p);
    *out_len = len;
    retval = 0;

cleanup:
    X509_NAME_free(is->issuer);
    ASN1_INTEGER_free(is->serial);
    free(is);

    return retval;
}

static void
init_krb5_subject_pk_info(krb5_subject_pk_info **in) 
{
    (*in) = malloc(sizeof(krb5_subject_pk_info));
    if ((*in) == NULL) return;
    (*in)->algorithm.parameters.data = NULL;
    (*in)->algorithm.parameters.length = 0;
    (*in)->subjectPublicKey.data = NULL;
    (*in)->subjectPublicKey.length = 0;
}

static void
free_krb5_subject_pk_info(krb5_subject_pk_info **in) 
{
    if ((*in) == NULL) return;
    if ((*in)->algorithm.parameters.data != NULL)
	free((*in)->algorithm.parameters.data);
    if ((*in)->subjectPublicKey.data != NULL)
	free((*in)->subjectPublicKey.data);
    free(*in);
}

static void 
free_krb5_kdc_dh_key_info(krb5_kdc_dh_key_info **in)
{
    if (*in == NULL) return;
    if ((*in)->subjectPublicKey.data != NULL)
	free((*in)->subjectPublicKey.data);
    free(*in);
}

static int
pkinit_client_get_flags(krb5_context kcontext, krb5_preauthtype patype)
{
#if 0
    switch (patype) {
    case KRB5_PADATA_PK_AS_REP:
    case KRB5_PADATA_PK_AS_REP_OLD:
	return PA_INFO;
	break;
    case KRB5_PADATA_PK_AS_REQ:
    case KRB5_PADATA_PK_AS_REQ_OLD:
	return PA_REAL;
	break;
    }
    return 0;
#else
    return PA_REAL;
#endif
}

static krb5_preauthtype supported_client_pa_types[] = {
    KRB5_PADATA_PK_AS_REP,
    KRB5_PADATA_PK_AS_REQ,
    KRB5_PADATA_PK_AS_REP_OLD,
    KRB5_PADATA_PK_AS_REQ_OLD,
    0
};

void
pkinit_fini_client_profile(krb5_context context, pkinit_context *plgctx)
{
    /* This should clean up anything allocated in pkinit_init_client_profile */
}

static krb5_error_code
pkinit_init_client_profile(krb5_context context, pkinit_context *plgctx)
{
    profile_t profile;
    krb5_error_code retval;

#if 0
    /*
     * These may not even be necessary!
     */
    retval = krb5_get_profile(context, &profile);
    if (retval) {
	krb5_set_error_message(context, retval,
			       "Could not get profile handle");
	goto errout;
    }
    profile_get_boolean(profile, "libdefaults", NULL,
			"pkinit_win2k",
			plgctx->win2k_target, &plgctx->win2k_target);
    profile_get_boolean(profile, "libdefaults", NULL,
			"pkinit_win2k_require_binding",
			plgctx->win2k_require_cksum,
			&plgctx->win2k_require_cksum);

    profile_get_boolean(profile, "libdefaults", NULL,
			"pkinit_require_eku",
			plgctx->require_eku, &plgctx->require_eku);
    profile_get_boolean(profile, "libdefaults", NULL,
			"pkinit_require_krbtgt_otherName",
			plgctx->require_san, &plgctx->require_san);
    profile_get_boolean(profile, "libdefaults", NULL,
			"pkinit_require_hostname_match",
			plgctx->require_hostname_match,
			&plgctx->require_hostname_match);
    profile_release(profile);
    /* set plgctx defaults for:
       - pkinit_anchors
       - pkinit_pool
       - pkinit_revoke
     */
#endif

    return 0;
}

static int pkinit_client_plugin_init(krb5_context context, void **blob)
{
    krb5_error_code retval;
    pkinit_context *plgctx;

    retval = pkinit_lib_init(context, blob);
    plgctx = *blob;

    if (0 == retval) 
	retval = pkinit_init_client_profile(context, plgctx);

errout:
    return retval;
}

static void
pkinit_client_plugin_fini(krb5_context context, void *blob)
{
    pkinit_context *plgctx = (pkinit_context *)blob;

    pkinit_fini_client_profile(context, plgctx);
    pkinit_lib_fini(context, blob);
}

struct krb5plugin_preauth_client_ftable_v0 preauthentication_client_0 = {
    "pkinit",			/* name */
    supported_client_pa_types,	/* pa_type_list */
    NULL,			/* enctype_list */
    pkinit_client_plugin_init,	/* (*init) */
    pkinit_client_plugin_fini,	/* (*fini) */
    pkinit_client_get_flags,	/* (*flags) */
    pkinit_client_req_init,     /* (*client_req_init) */
    pkinit_client_req_fini,     /* (*client_req_fini) */
    pkinit_client_process,	/* (*process) */
    pkinit_client_tryagain,	/* (*tryagain) */
};

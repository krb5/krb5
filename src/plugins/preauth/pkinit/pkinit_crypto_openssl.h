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

#ifndef _PKINIT_CRYPTO_OPENSSL_H
#define _PKINIT_CRYPTO_OPENSSL_H

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/obj_mac.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/asn1_mac.h>
#include <openssl/sha.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>

#include "pkinit.h"

#ifndef WITHOUT_PKCS11
#include <opensc/pkcs11.h>
#endif

#define PKCS11_MODNAME "opensc-pkcs11.so"
#define PK_SIGLEN_GUESS 1000
#define PK_NOSLOT 999999

struct _pkinit_identity_crypto_context {
    STACK_OF(X509) *my_certs;   /* available user certs */
    int cert_index;             /* cert to use out of available certs*/
    EVP_PKEY *my_key;           /* available user keys if in filesystem */
    STACK_OF(X509) *trustedCAs; /* available trusted ca certs */
    STACK_OF(X509) *intermediateCAs;   /* available intermediate ca certs */
    STACK_OF(X509_CRL) *revoked;    /* available crls */
    int pkcs11_method;
    krb5_prompter_fct prompter;
    void *prompter_data;
    char *cert_filename;
    char *key_filename;
#ifndef WITHOUT_PKCS11
    char *p11_module_name;
    void *p11_module;
    CK_SLOT_ID slotid;
    char *token_label;
    CK_SESSION_HANDLE session;
    CK_FUNCTION_LIST_PTR p11;
    CK_BYTE_PTR cert_id;
    int cert_id_len;
    char *cert_label;
    CK_MECHANISM_TYPE mech;
#endif
};

struct _pkinit_plg_crypto_context {
    DH *dh_1024;
    DH *dh_2048;
    DH *dh_4096;
    ASN1_OBJECT *id_pkinit_authData;
    ASN1_OBJECT *id_pkinit_authData9;
    ASN1_OBJECT *id_pkinit_DHKeyData;
    ASN1_OBJECT *id_pkinit_rkeyData;
    ASN1_OBJECT *id_pkinit_san;
    ASN1_OBJECT *id_pkinit_san9;
    ASN1_OBJECT *id_pkinit_KPClientAuth;
    ASN1_OBJECT *id_pkinit_KPKdc;
    ASN1_OBJECT *id_ms_kp_sc_logon;
    ASN1_OBJECT *id_kp_serverAuth;
};

struct _pkinit_req_crypto_context {
    X509 *received_cert;
    DH *dh;
};

static void openssl_init(void);

static krb5_error_code pkinit_init_pkinit_oids(pkinit_plg_crypto_context );
static void pkinit_fini_pkinit_oids(pkinit_plg_crypto_context );

static krb5_error_code pkinit_init_dh_params(pkinit_plg_crypto_context );
static void pkinit_fini_dh_params(pkinit_plg_crypto_context );

static krb5_error_code pkinit_init_certs(pkinit_identity_crypto_context ctx);
static void pkinit_fini_certs(pkinit_identity_crypto_context ctx);

static krb5_error_code pkinit_init_pkcs11(pkinit_identity_crypto_context ctx);
static void pkinit_fini_pkcs11(pkinit_identity_crypto_context ctx);

static krb5_error_code pkinit_encode_dh_params
	(BIGNUM *, BIGNUM *, BIGNUM *, unsigned char **, unsigned int *);
static DH *pkinit_decode_dh_params
	(DH **, unsigned char **, unsigned int );
static int pkinit_check_dh_params
	(BIGNUM * p1, BIGNUM * p2, BIGNUM * g1, BIGNUM * q1);

static krb5_error_code pkinit_sign_data
	(krb5_context context, pkinit_identity_crypto_context cryptoctx,
		unsigned char *data, unsigned int data_len,
		unsigned char **sig, unsigned int *sig_len);

static krb5_error_code create_signature
	(unsigned char **, unsigned int *, unsigned char *, unsigned int,
		EVP_PKEY *pkey);

static krb5_error_code pkinit_decode_data
	(krb5_context context, pkinit_identity_crypto_context cryptoctx,
		unsigned char *data, unsigned int data_len,
		unsigned char **decoded, unsigned int *decoded_len);

static krb5_error_code decode_data
	(unsigned char **, unsigned int *, unsigned char *, unsigned int,
		EVP_PKEY *pkey, X509 *cert);

#ifdef DEBUG_DH
static void print_dh(DH *, char *);
static void print_pubkey(BIGNUM *, char *);
#endif

static krb5_error_code get_filename(char **, char *, int);
static X509 *get_cert(char *filename);
static EVP_PKEY *get_key(char *filename);

static int prepare_enc_data
	(unsigned char *indata, int indata_len, unsigned char **outdata,
		int *outdata_len);

static int openssl_callback (int, X509_STORE_CTX *);
static int openssl_callback_ignore_crls (int, X509_STORE_CTX *);

static int pkcs7_decrypt
	(krb5_context context, pkinit_identity_crypto_context id_cryptoctx,
		PKCS7 *p7, BIO *bio);

static BIO * pkcs7_dataDecode
	(krb5_context context, pkinit_identity_crypto_context id_cryptoctx,
		PKCS7 *p7);

static ASN1_OBJECT * pkinit_pkcs7type2oid
	(pkinit_plg_crypto_context plg_cryptoctx, int pkcs7_type);

static krb5_error_code pkinit_create_sequence_of_principal_identifiers
	(krb5_context context, pkinit_plg_crypto_context plg_cryptoctx,
		pkinit_req_crypto_context req_cryptoctx,
		pkinit_identity_crypto_context id_cryptoctx,
		int type, krb5_data **out_data);

#ifndef WITHOUT_PKCS11
static krb5_error_code pkinit_find_private_key
	(pkinit_identity_crypto_context, CK_ATTRIBUTE_TYPE usage,
		CK_OBJECT_HANDLE *objp);
static krb5_error_code pkinit_login
	(krb5_context context, pkinit_identity_crypto_context id_cryptoctx,
		CK_TOKEN_INFO *tip);
static krb5_error_code pkinit_open_session
	(krb5_context context, pkinit_identity_crypto_context id_cryptoctx);
static void * pkinit_C_LoadModule(const char *modname, CK_FUNCTION_LIST_PTR_PTR p11p);
static CK_RV pkinit_C_UnloadModule(void *handle);
#ifdef SILLYDECRYPT
CK_RV pkinit_C_Decrypt
	(pkinit_identity_crypto_context id_cryptoctx,
		CK_BYTE_PTR pEncryptedData, CK_ULONG  ulEncryptedDataLen,
		CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
#endif
static krb5_error_code pkinit_get_client_cert_pkcs11
	(krb5_context context, pkinit_plg_crypto_context plg_cryptoctx,
		pkinit_req_crypto_context req_cryptoctx,
		pkinit_identity_crypto_context id_cryptoctx,
		const char *principal,
		krb5_get_init_creds_opt *opt);
static krb5_error_code pkinit_sign_data_pkcs11
	(krb5_context context, pkinit_identity_crypto_context id_cryptoctx,
		unsigned char *data, unsigned int data_len,
		unsigned char **sig, unsigned int *sig_len);
static krb5_error_code pkinit_decode_data_pkcs11
	(krb5_context context, pkinit_identity_crypto_context id_cryptoctx,
		unsigned char *data, unsigned int data_len,
		unsigned char **decoded_data, unsigned int *decoded_data_len);
#endif	/* WITHOUT_PKCS11 */

static krb5_error_code pkinit_get_client_cert_fs
	(krb5_context context, pkinit_plg_crypto_context plg_cryptoctx,
		pkinit_req_crypto_context req_cryptoctx,
		pkinit_identity_crypto_context id_cryptoctx,
		const char *principal,
		krb5_get_init_creds_opt *opt);
static krb5_error_code pkinit_sign_data_fs
	(krb5_context context, pkinit_identity_crypto_context id_cryptoctx,
		unsigned char *data, unsigned int data_len,
		unsigned char **sig, unsigned int *sig_len);
static krb5_error_code pkinit_decode_data_fs
	(krb5_context context, pkinit_identity_crypto_context id_cryptoctx,
		unsigned char *data, unsigned int data_len,
		unsigned char **decoded_data, unsigned int *decoded_data_len);

static krb5_error_code der_decode_data
	(unsigned char *, long, unsigned char **, long *);

static int encode_signeddata
	(unsigned char *data, unsigned int data_len,
	 unsigned char **out, unsigned int *out_len);

static krb5_error_code load_trusted_certifiers
	(STACK_OF(X509) **trusted_CAs, STACK_OF(X509_CRL) **crls, 
		int return_crls, char *filename);

static krb5_error_code load_trusted_certifiers_dir
	(STACK_OF(X509) **trusted_CAs, STACK_OF(X509_CRL) **crls,
		int return_crls, char *dirname);

static krb5_error_code
create_krb5_invalidCertificates(krb5_context context,
				pkinit_plg_crypto_context plg_cryptoctx,
				pkinit_req_crypto_context req_cryptoctx,
				pkinit_identity_crypto_context id_cryptoctx,
				krb5_external_principal_identifier *** ids);

/* This handy macro borrowed from crypto/x509v3/v3_purp.c */
#define ku_reject(x, usage) \
	(((x)->ex_flags & EXFLAG_KUSAGE) && !((x)->ex_kusage & (usage)))

#endif	/* _PKINIT_CRYPTO_OPENSSL_H */

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

#ifndef _PKINIT_H
#define _PKINIT_H

#include <krb5/krb5.h>
#include <krb5/preauth_plugin.h>
#include <k5-int-pkinit.h>
#include <profile.h>
#include "pkinit_accessor.h"

#define DH_PROTOCOL     1
#define RSA_PROTOCOL    2

#define TD_TRUSTED_CERTIFIERS 104
#define TD_INVALID_CERTIFICATES 105
#define TD_DH_PARAMETERS 109

#define PKINIT_CTX_MAGIC	0x05551212
#define PKINIT_REQ_CTX_MAGIC	0xdeadbeef

#ifdef DEBUG
#define pkiDebug(args...)	printf(args)
#else
#define pkiDebug(args...)
#endif

extern const krb5_octet_data dh_oid;

/* forward declarations of pkinit structures */
struct _pkinit_context;
typedef struct _pkinit_context *pkinit_context;
struct _pkinit_kdc_context;
typedef struct _pkinit_kdc_context *pkinit_kdc_context;
struct _pkinit_req_context;
typedef struct _pkinit_req_context *pkinit_req_context;
struct _pkinit_kdc_req_context;
typedef struct _pkinit_kdc_req_context *pkinit_kdc_req_context;

/*
 * forward declarations of crypto-specific pkinit structures
 */
/*
 * notes about crypto contexts:
 *
 * the basic idea is that there are crypto contexts that live at
 * both the plugin level and request level. the identity context (that
 * keeps info about your own certs and such) is separate because
 * it is needed at different levels for the kdc and and the client.
 * (the kdc's identity is at the plugin level, the client's identity
 * information could change per-request.)
 * the identity context is meant to have the entity's cert,
 * a list of trusted and intermediate cas, a list of crls, and any 
 * pkcs11 information.  the req context is meant to have the
 * received certificate and the DH related information. the plugin
 * context is meant to have global crypto information, i.e., OIDs
 * and constant DH parameter information.
 */ 

/*
 * plugin crypto context should keep plugin common information, 
 * eg., OIDs, known DHparams
 */
typedef struct _pkinit_plg_crypto_context *pkinit_plg_crypto_context;

/*
 * request crypto context should keep reqyest common information,
 * eg., received credentials, DH parameters of this request
 */
typedef struct _pkinit_req_crypto_context *pkinit_req_crypto_context;

/*
 * identity context should keep information about credentials
 * for the request, eg., my credentials, trusted ca certs,
 * intermediate ca certs, crls, pkcs11 info
 */
typedef struct _pkinit_identity_crypto_context *pkinit_identity_crypto_context;

/*
 * this structure keeps information about the config options
 */
typedef struct _pkinit_plg_opts {
    int require_eku;	    /* require EKU checking (default is true) */
    int require_san;	    /* require SAN checking (default is true) */
    int allow_upn;	    /* allow UPN-SAN instead of pkinit-SAN */
    int dh_or_rsa;	    /* selects DH or RSA based pkinit */
    int require_crl_checking; /* require CRL for a CA (default is false) */ 
    int princ_in_cert;
    int dh_min_bits;	    /* minimum DH modulus size allowed */
    int allow_proxy_certs;
} pkinit_plg_opts;

/*
 * this structure keeps options used for a given request
 */
typedef struct _pkinit_req_opts {
    int require_eku;
    int require_san;
    int allow_upn;
    int dh_or_rsa;
    int require_crl_checking;
    int dh_size;	    /* initial request DH modulus size (default=1024) */
    int require_hostname_match;
    int win2k_target;
    int win2k_require_cksum;
} pkinit_req_opts;

/*
 * information about identity from config file or command line
 */

#define PKINIT_ID_OPT_USER_IDENTITY	1
#define PKINIT_ID_OPT_ANCHOR_CAS	2
#define PKINIT_ID_OPT_INTERMEDIATE_CAS	3
#define PKINIT_ID_OPT_CRLS		4
#define PKINIT_ID_OPT_OCSP		5
#define PKINIT_ID_OPT_DN_MAPPING	6   /* XXX ? */

typedef struct _pkinit_identity_opts {
    char *identity;
    char **anchors;
    char **intermediates;
    char **crls;
    char *ocsp;
    char *dn_mapping_file;
} pkinit_identity_opts;


/*
 * Client's plugin context
 */
struct _pkinit_context {
    int magic;
    pkinit_plg_crypto_context cryptoctx;
    pkinit_plg_opts *opts;
    pkinit_identity_opts *idopts;
};

/*
 * Client's per-request context
 */
struct _pkinit_req_context {
    int magic;
    pkinit_req_crypto_context cryptoctx;
    pkinit_req_opts *opts;
    pkinit_identity_crypto_context idctx;
    pkinit_identity_opts *idopts;
    krb5_preauthtype pa_type;
};

/*
 * KDC's plugin context
 */
struct _pkinit_kdc_context {
    int magic;
    pkinit_plg_crypto_context cryptoctx;
    pkinit_plg_opts *opts;
    pkinit_identity_crypto_context idctx;
    pkinit_identity_opts *idopts;
};

/*
 * KDC's per-request context
 */
struct _pkinit_kdc_req_context {
    int magic;
    pkinit_req_crypto_context cryptoctx;
    krb5_auth_pack *rcv_auth_pack;
    krb5_auth_pack_draft9 *rcv_auth_pack9;
    krb5_preauthtype pa_type;
};

/*
 * Functions to initialize and cleanup various context
 */
krb5_error_code pkinit_init_plg_crypto(pkinit_plg_crypto_context *);
void pkinit_fini_plg_crypto(pkinit_plg_crypto_context);

krb5_error_code pkinit_init_req_crypto(pkinit_req_crypto_context *);
void pkinit_fini_req_crypto(pkinit_req_crypto_context);

krb5_error_code pkinit_init_identity_crypto(pkinit_identity_crypto_context *);
void pkinit_fini_identity_crypto(pkinit_identity_crypto_context);

krb5_error_code pkinit_init_req_opts(pkinit_req_opts **);
void pkinit_fini_req_opts(pkinit_req_opts *);

krb5_error_code pkinit_init_plg_opts(pkinit_plg_opts **);
void pkinit_fini_plg_opts(pkinit_plg_opts *);

krb5_error_code pkinit_init_identity_opts(pkinit_identity_opts **idopts);
void pkinit_fini_identity_opts(pkinit_identity_opts *idopts);
krb5_error_code pkinit_dup_identity_opts(pkinit_identity_opts *src_opts,
					 pkinit_identity_opts **dest_opts);


/*
 * these describe the type of CMS message
 */
enum cms_msg_types {
    CMS_SIGN_CLIENT,
    CMS_SIGN_DRAFT9,
    CMS_SIGN_SERVER,
    CMS_ENVEL_SERVER
};

/*
 * this function creates a CMS message where eContentType is SignedData
 */
krb5_error_code cms_signeddata_create
	(krb5_context context,				/* IN */
	pkinit_plg_crypto_context plg_cryptoctx,	/* IN */
	pkinit_req_crypto_context req_cryptoctx,	/* IN */
	pkinit_identity_crypto_context id_cryptoctx,	/* IN */
	int cms_msg_type,				/* IN
		    specifies CMS_SIGN_CLIENT for client-side CMS message
		    and CMS_SIGN_SERVER for kdc-side */
	int include_certchain,				/* IN
		    specifies where certificates field in SignedData
		    should contain certificate path */
	unsigned char *auth_pack,			/* IN
		    contains DER encoded AuthPack (CMS_SIGN_CLIENT)
		    or DER encoded DHRepInfo (CMS_SIGN_SERVER) */
	int auth_pack_len,				/* IN
		    contains length of auth_pack */
	unsigned char **signed_data,			/* OUT
		    for CMS_SIGN_CLIENT receives DER encoded
		    SignedAuthPack (CMS_SIGN_CLIENT) or DER
		    encoded DHInfo (CMS_SIGN_SERVER) */ 
	int *signed_data_len);				/* OUT
		    receives length of signed_data */

/*
 * this function verifies a CMS message where eContentType is SignedData
 */
krb5_error_code cms_signeddata_verify
	(krb5_context context,				/* IN */
	pkinit_plg_crypto_context plg_cryptoctx,	/* IN */
	pkinit_req_crypto_context req_cryptoctx,	/* IN */
	pkinit_identity_crypto_context id_cryptoctx,	/* IN */
	int cms_msg_type,				/* IN
		    specifies CMS_SIGN_CLIENT for client-side
		    CMS message and CMS_SIGN_SERVER for kdc-side */
	int require_crl_checking,			/* IN
		    specifies whether CRL checking should be
		    strictly enforced, i.e. if no CRLs available
		    for the CA then fail verification.
		    note, if the value is 0, crls are still
		    checked if present */
	unsigned char *signed_data,			/* IN
		    contains DER encoded SignedAuthPack (CMS_SIGN_CLIENT)
		    or DER encoded DHInfo (CMS_SIGN_SERVER) */
	int signed_data_len,				/* IN
		    contains length of signed_data*/
	unsigned char **auth_pack,			/* OUT
		    receives DER encoded AuthPack (CMS_SIGN_CLIENT)
		    or DER encoded DHRepInfo (CMS_SIGN_SERVER)*/
	int *auth_pack_len,				/* OUT
		    receives length of auth_pack */
	unsigned char **authz_data,			/* OUT
		    receives required authorization data that
		    contains the verified certificate chain
		    (only used by the KDC) */
	int *authz_data_len);				/* OUT
		    receives length of authz_data */

/*
 * this function creates a CMS message where eContentType is EnvelopedData
 */
krb5_error_code cms_envelopeddata_create	
	(krb5_context context,				/* IN */
	pkinit_plg_crypto_context plg_cryptoctx,	/* IN */
	pkinit_req_crypto_context req_cryptoctx,	/* IN */
	pkinit_identity_crypto_context id_cryptoctx,	/* IN */
	krb5_preauthtype pa_type,			/* IN */ 
	int include_certchain,				/* IN
		    specifies whether the certificates field in
		    SignedData should contain certificate path */
	unsigned char *key_pack,			/* IN
		    contains DER encoded ReplyKeyPack */
	int key_pack_len,				/* IN
		    contains length of key_pack */
	unsigned char **envel_data,			/* OUT
		    receives DER encoded encKeyPack */
	int *envel_data_len);				/* OUT
		    receives length of envel_data */

/*
 * this function creates a CMS message where eContentType is EnvelopedData
 */
krb5_error_code cms_envelopeddata_verify
	(krb5_context context,				/* IN */
	pkinit_plg_crypto_context plg_cryptoctx,	/* IN */
	pkinit_req_crypto_context req_cryptoctx,	/* IN */
	pkinit_identity_crypto_context id_cryptoctx,	/* IN */
	krb5_preauthtype pa_type,			/* IN */
	int require_crl_checking,			/* IN
		    specifies whether CRL checking should be
		    strictly enforced */
	unsigned char *envel_data,			/* IN
		    contains DER encoded encKeyPack */
	int envel_data_len,				/* IN
		    contains length of envel_data */ 
	unsigned char **signed_data,			/* OUT
		    receives ReplyKeyPack */
	int *signed_data_len);				/* OUT
		    receives length of signed_data */

/*
 * this function looks for a SAN in the received certificate.
 * if it finds one, it retrieves and returns Kerberos principal
 * name encoded in the SAN
 */
krb5_error_code verify_id_pkinit_san
	(krb5_context context,				/* IN */ 
	pkinit_plg_crypto_context plg_cryptoctx,	/* IN */
	pkinit_req_crypto_context req_cryptoctx,	/* IN */
	pkinit_identity_crypto_context id_cryptoctx,	/* IN */
	krb5_preauthtype pa_type,			/* IN */
	int allow_upn,					/* IN
		    specifies if Windows SANs are allowed */
	krb5_principal *identity_in_san,		/* OUT
		    receives Kerberos principal found in SAN */
	unsigned char **kdc_hostname,			/* OUT
		    contains dNSName SAN (win2k KDC hostname) */ 
	int *san_valid);				/* OUT
		    receives non-zero if a valid SAN was found */

/*
 * this functions looks for an EKU in the received certificate.
 * if config opts specifies that EKU check should be ignored, then
 * the lack EKU in the received certificate is not treated as an error
 */
krb5_error_code verify_id_pkinit_eku
	(krb5_context context,				/* IN */
	pkinit_plg_crypto_context plg_cryptoctx,	/* IN */
	pkinit_req_crypto_context req_cryptoctx,	/* IN */
	pkinit_identity_crypto_context id_cryptoctx,	/* IN */
	krb5_preauthtype pa_type,			/* IN */
	int require_eku,				/* IN
		    specifies if policy requires EKU checking */
	int *eku_valid);				/* OUT
		    receives non-zero if a valid EKU was found */

/*
 * this functions takes in generated DH secret key and converts
 * it in to a kerberos session key. it takes into the account the
 * enc type and then follows the procedure specified in the RFC p 22.
 */
krb5_error_code pkinit_octetstring2key
	(krb5_context context,				/* IN */
	krb5_enctype etype,				/* IN
		    specifies the enc type */
	unsigned char *key,				/* IN
		    contains the DH secret key */
	int key_len,					/* IN
		    contains length of key */
	krb5_keyblock * krb5key);			/* OUT
		    receives kerberos session key */

/*
 * this function implements clients first part of the DH protocol.
 * client selects its DH parameters and pub key
 */
krb5_error_code client_create_dh
	(krb5_context context,				/* IN */
	pkinit_plg_crypto_context plg_cryptoctx,	/* IN */
	pkinit_req_crypto_context req_cryptoctx,	/* IN */
	pkinit_identity_crypto_context id_cryptoctx,	/* IN */
	int dh_size,					/* IN
		    specifies the DH modulous, eg 1024, 2048, or 4096 */
        unsigned char **dh_paramas,			/* OUT
		    contains DER encoded DH params */
	int *dh_params_len,				/* OUT
		    contains length of dh_parmas */
        unsigned char **dh_pubkey,			/* OUT
		    receives DER encoded DH pub key */ 
	int *dh_pubkey_len);				/* OUT
		    receives length of dh_pubkey */

/*
 * this function completes client's the DH protocol. client
 * processes received DH pub key from the KDC and computes
 * the DH secret key 
 */
krb5_error_code client_process_dh
	(krb5_context context,				/* IN */
	pkinit_plg_crypto_context plg_cryptoctx,	/* IN */
	pkinit_req_crypto_context req_cryptoctx,	/* IN */
	pkinit_identity_crypto_context id_cryptoctx,	/* IN */
	unsigned char *dh_pubkey,			/* IN
		    contains client's DER encoded DH pub key */
	int dh_pubkey_len,				/* IN
		    contains length of dh_pubkey */
	unsigned char **dh_session_key,			/* OUT
		    receives DH secret key */
	int *dh_session_key_len);			/* OUT
		    receives length of dh_session_key */

/*
 * this function implements the KDC first part of the DH protocol.
 * it decodes the client's DH parameters and pub key and checks
 * if they are acceptable.
 */
krb5_error_code server_check_dh
	(krb5_context context,				/* IN */
	pkinit_plg_crypto_context plg_cryptoctx,	/* IN */
	pkinit_req_crypto_context req_cryptoctx,	/* IN */
	pkinit_identity_crypto_context id_cryptoctx,	/* IN */
	krb5_octet_data *dh_params,			/* IN
		    ???? */
	int minbits);					/* IN
		    the mininum number of key bits acceptable */

/*
 * this function completes the KDC's DH protocol. The KDC generates
 * its DH pub key and computes the DH secret key
 */
krb5_error_code server_process_dh
	(krb5_context context,				/* IN */
	pkinit_plg_crypto_context plg_cryptoctx,	/* IN */
	pkinit_req_crypto_context req_cryptoctx,	/* IN */
	pkinit_identity_crypto_context id_cryptoctx,	/* IN */
	unsigned char *received_pubkey,			/* IN
		    contains client's DER encoded DH pub key */
	int received_pub_len,				/* IN
		    contains length of received_pubkey */
	unsigned char **dh_pubkey,			/* OUT
		    receives KDC's DER encoded DH pub key */ 
	int *dh_pubkey_len,				/* OUT
		    receives length of dh_pubkey */
	unsigned char **server_key,			/* OUT
		    receives DH secret key */
	int *server_key_len);				/* OUT
		    receives length of server_key */

/*
 * this functions takes in crypto specific representation of
 * trustedCertifiers and creates a list of
 * krb5_external_principal_identifier
 */
krb5_error_code create_krb5_trustedCertifiers
	(krb5_context context,				/* IN */
	pkinit_plg_crypto_context plg_cryptoctx,	/* IN */
	pkinit_req_crypto_context req_cryptoctx,	/* IN */
	pkinit_identity_crypto_context id_cryptoctx,	/* IN */
	krb5_external_principal_identifier ***trustedCertifiers); /* OUT */

/*
 * this functions takes in crypto specific representation of
 * trustedCas (draft9) and creates a list of krb5_trusted_ca (draft9).
 * draft9 trustedCAs is a CHOICE. we only support choices for
 * [1] caName and [2] issuerAndSerial.  there is no config
 * option available to select the choice yet. default = 1.
 */
krb5_error_code create_krb5_trustedCas
	(krb5_context context,				/* IN */
	pkinit_plg_crypto_context plg_cryptoctx,	/* IN */
	pkinit_req_crypto_context req_cryptoctx,	/* IN */
	pkinit_identity_crypto_context id_cryptoctx,	/* IN */
	int flag,					/* IN
		    specifies the tag of the CHOICE */
	krb5_trusted_ca ***trustedCas);			/* OUT */

/*
 * this functions takes in crypto specific representation of the
 * KDC's certificate and creates a DER encoded kdcPKId
 */
krb5_error_code create_issuerAndSerial
	(krb5_context context,				/* IN */
	pkinit_plg_crypto_context plg_cryptoctx,	/* IN */
	pkinit_req_crypto_context req_cryptoctx,	/* IN */
	pkinit_identity_crypto_context id_cryptoctx,	/* IN */
	unsigned char **kdcId_buf,			/* OUT
		    receives DER encoded kdcPKId */
	int *kdcId_len);				/* OUT
		    receives length of encoded kdcPKId */

/*
 * process identity options specified via the command-line
 * or config file and populate the crypto-specific identity
 * information.
 */
krb5_error_code pkinit_initialize_identity
	(krb5_context context,				/* IN */
	pkinit_identity_opts *idopts,			/* IN */
	pkinit_identity_crypto_context id_cryptoctx);	/* IN/OUT */

krb5_error_code pkinit_process_identity_option
	(krb5_context context,				/* IN */
	int attr,					/* IN */
	const char *value,				/* IN */
	pkinit_identity_crypto_context id_cryptoctx);	/* IN/OUT */ 

krb5_error_code pkinit_get_client_cert
	(krb5_context context, pkinit_plg_crypto_context plg_cryptoctx,
		pkinit_req_crypto_context req_cryptoctx,
		pkinit_identity_crypto_context id_cryptoctx,
		const char *principal, krb5_get_init_creds_opt *opt);

krb5_error_code pkinit_get_kdc_cert
	(krb5_context context, pkinit_plg_crypto_context plg_cryptoctx,
		pkinit_req_crypto_context req_cryptoctx,
		pkinit_identity_crypto_context id_cryptoctx,
		const char *principal, krb5_get_init_creds_opt *opt);

krb5_error_code pkinit_get_trusted_cacerts
	(krb5_context context, pkinit_plg_crypto_context plg_cryptoctx,
		pkinit_req_crypto_context req_cryptoctx,
		pkinit_identity_crypto_context id_cryptoctx,
		krb5_get_init_creds_opt *opt);

krb5_error_code pkinit_get_intermediate_cacerts
	(krb5_context context, pkinit_plg_crypto_context plg_cryptoctx,
		pkinit_req_crypto_context req_cryptoctx,
		pkinit_identity_crypto_context id_cryptoctx,
		krb5_get_init_creds_opt *opt);

krb5_error_code pkinit_get_crls
	(krb5_context context, pkinit_plg_crypto_context plg_cryptoctx,
		pkinit_req_crypto_context req_cryptoctx,
		pkinit_identity_crypto_context id_cryptoctx,
		krb5_get_init_creds_opt *opt);

/*
 * this function creates edata that contains TD-DH-PARAMETERS
 */
krb5_error_code pkinit_create_td_dh_parameters
	(krb5_context context,				/* IN */
	pkinit_plg_crypto_context plg_cryptoctx,	/* IN */
	pkinit_req_crypto_context req_cryptoctx,	/* IN */
	pkinit_identity_crypto_context id_cryptoctx,	/* IN */
	pkinit_plg_opts *opts,				/* IN */
	krb5_data **edata);				/* OUT */

/*
 * this function processes edata that contains TD-DH-PARAMETERS.
 * the client processes the received acceptable by KDC DH
 * parameters and picks the first acceptable to it. it matches
 * them against the known DH parameters.
 */
krb5_error_code pkinit_process_td_dh_params
	(krb5_context context,				/* IN */
	pkinit_plg_crypto_context plg_cryptoctx,	/* IN */
	pkinit_req_crypto_context req_cryptoctx,	/* IN */
	pkinit_identity_crypto_context id_cryptoctx,	/* IN */
	krb5_algorithm_identifier **algId,		/* IN */
	int *new_dh_size);				/* OUT
		    receives the new DH modulus to use in the new AS-REQ */

/*
 * this function creates edata that contains TD-INVALID-CERTIFICATES
 */
krb5_error_code pkinit_create_td_invalid_certificate
	(krb5_context context,				/* IN */
	pkinit_plg_crypto_context plg_cryptoctx,	/* IN */
	pkinit_req_crypto_context req_cryptoctx,	/* IN */ 
	pkinit_identity_crypto_context id_cryptoctx,	/* IN */
	krb5_data **edata);				/* OUT */

/*
 * this function creates edata that contains TD-TRUSTED-CERTIFIERS
 */
krb5_error_code pkinit_create_td_trusted_certifiers
	(krb5_context context,				/* IN */
	pkinit_plg_crypto_context plg_cryptoctx,	/* IN */
	pkinit_req_crypto_context req_cryptoctx,	/* IN */
	pkinit_identity_crypto_context id_cryptoctx,	/* IN */
	krb5_data **edata);				/* OUT */

/*
 * this function processes edata that contains either 
 * TD-TRUSTED-CERTIFICATES or TD-INVALID-CERTIFICATES.
 * current implementation only decodes the received message
 * but does not act on it
 */
krb5_error_code pkinit_process_td_trusted_certifiers
	(krb5_context context,				/* IN */
	pkinit_plg_crypto_context plg_cryptoctx,	/* IN */
	pkinit_req_crypto_context req_cryptoctx,	/* IN */
	pkinit_identity_crypto_context id_cryptoctx,	/* IN */
	krb5_external_principal_identifier **trustedCertifiers, /* IN */
	int td_type);					/* IN */

/*
 * this function checks if the received kdcPKId matches
 * the KDC's certificate
 */
krb5_error_code pkinit_check_kdc_pkid
	(krb5_context context,				/* IN */
	pkinit_plg_crypto_context plg_cryptoctx,	/* IN */
	pkinit_req_crypto_context req_cryptoctx,	/* IN */
	pkinit_identity_crypto_context id_cryptoctx,	/* IN */
	unsigned char *pdid_buf,			/* IN
		    contains DER encoded kdcPKId */
	int pkid_len,					/* IN
		    contains length of pdid_buf */
	int *valid_kdcPkId);				/* OUT
		    1 if kdcPKId matches, otherwise 0 */

krb5_error_code pkinit_get_kdc_identity_crypto
	(krb5_context context, pkinit_plg_crypto_context plg_cryptoctx,
                pkinit_identity_crypto_context id_cryptoctx);

krb5_error_code pkinit_identity_set_prompter
	(pkinit_identity_crypto_context id_cryptoctx,
		krb5_prompter_fct prompter, void *prompter_data);

/*
 * initialization and free functions
 */
void init_krb5_pa_pk_as_req(krb5_pa_pk_as_req **in);
void init_krb5_pa_pk_as_req_draft9(krb5_pa_pk_as_req_draft9 **in);
void init_krb5_reply_key_pack(krb5_reply_key_pack **in);
void init_krb5_reply_key_pack_draft9(krb5_reply_key_pack_draft9 **in);

/*
 * a note about freeing krb5_auth_pack. the caller, if needed,
 * should separately free clientPublicValue->algorithm.algorithm.data.
 * in our implementation the client uses a static value for the
 * alg oid but on the kdc side the oid is decoded (and thus
 * allocated) from the rcvd msg
 */
void init_krb5_auth_pack(krb5_auth_pack **in);
void init_krb5_auth_pack_draft9(krb5_auth_pack_draft9 **in);
void init_krb5_pa_pk_as_rep(krb5_pa_pk_as_rep **in);
void init_krb5_pa_pk_as_rep_draft9(krb5_pa_pk_as_rep_draft9 **in);
void init_krb5_typed_data(krb5_typed_data **in);
void init_krb5_subject_pk_info(krb5_subject_pk_info **in);

void free_krb5_pa_pk_as_req(krb5_pa_pk_as_req **in);
void free_krb5_pa_pk_as_req_draft9(krb5_pa_pk_as_req_draft9 **in);
void free_krb5_reply_key_pack(krb5_reply_key_pack **in);
void free_krb5_reply_key_pack_draft9(krb5_reply_key_pack_draft9 **in);
void free_krb5_auth_pack(krb5_auth_pack **in);
void free_krb5_auth_pack_draft9(krb5_context, krb5_auth_pack_draft9 **in);
void free_krb5_pa_pk_as_rep(krb5_pa_pk_as_rep **in);
void free_krb5_pa_pk_as_rep_draft9(krb5_pa_pk_as_rep_draft9 **in);
void free_krb5_external_principal_identifier(krb5_external_principal_identifier ***in);
void free_krb5_trusted_ca(krb5_trusted_ca ***in);
void free_krb5_typed_data(krb5_typed_data ***in);
void free_krb5_algorithm_identifier(krb5_algorithm_identifier ***in);
void free_krb5_kdc_dh_key_info(krb5_kdc_dh_key_info **in);
void free_krb5_subject_pk_info(krb5_subject_pk_info **in);

/*
 * Functions in pkinit_profile.c
 */
krb5_error_code pkinit_kdcdefault_strings
	(krb5_context context, const char *option, char ***ret_value);
krb5_error_code pkinit_kdcdefault_string
	(krb5_context context, const char *option, char **ret_value);
krb5_error_code pkinit_kdcdefault_boolean
	(krb5_context context, const char *option,
	 int default_value, int *ret_value);
krb5_error_code pkinit_kdcdefault_integer
	(krb5_context context, const char *option,
         int default_value, int *ret_value);


krb5_error_code pkinit_libdefault_strings
	(krb5_context context, const krb5_data *realm,
         const char *option, char ***ret_value);
krb5_error_code pkinit_libdefault_string
	(krb5_context context, const krb5_data *realm,
         const char *option, char **ret_value);
krb5_error_code pkinit_libdefault_boolean
	(krb5_context context, const krb5_data *realm, const char *option,
	 int default_value, int *ret_value);
krb5_error_code pkinit_libdefault_integer
	(krb5_context context, const krb5_data *realm, const char *option,
	 int default_value, int *ret_value);

krb5_error_code pkinit_get_kdc_hostnames
	(krb5_context context, krb5_data *realm, char ***hostnames);

/*
 * main api end
 */

/* debugging functions */
void print_buffer(unsigned char *, int);
void print_buffer_bin(unsigned char *, int, char *);

#endif	/* _PKINIT_H */

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

#ifndef _PKINIT_H
#define _PKINIT_H

#include "pkinit_accessor.h"

#define DH_PROTOCOL     1
#define RSA_PROTOCOL    2

extern const krb5_octet_data dh_oid;
extern unsigned char pkinit_1024_dhprime[1024/8];
extern unsigned char pkinit_2048_dhprime[2048/8];
extern unsigned char pkinit_4096_dhprime[4096/8];

typedef struct _pkinit_context {
    int magic;
    krb5_context context;
    int require_eku;
    int require_san;
    int allow_upn;
    int dh_or_rsa;
    int require_crl_checking;
    char *ctx_identity;
    char *ctx_anchors;
    char *ctx_pool;
    char *ctx_revoke;
    char *ctx_ocsp;
    char *ctx_mapping_file;
    int ctx_princ_in_cert;
    int ctx_dh_min_bits;
    int ctx_allow_proxy_certs;
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
} pkinit_context;

typedef struct _pkinit_req_context {
    int magic;
    pkinit_context *plugctx;
    DH *dh;
    int dh_size;
    int require_eku;
    int require_san;
    int require_hostname_match;
    int allow_upn;
    int dh_or_rsa;
    int require_crl_checking;
    int win2k_target;
    int win2k_require_cksum;
    krb5_preauthtype patype;
    krb5_prompter_fct prompter;
    void *prompter_data;
    int pkcs11_method;
#ifndef WITHOUT_PKCS11
    char *p11_module_name;
    void *p11_module;
    unsigned int slotid;
    CK_SESSION_HANDLE session;
    CK_FUNCTION_LIST_PTR p11;
    CK_BYTE_PTR cert_id;
    int cert_id_len;
    CK_MECHANISM_TYPE mech;
#endif
    void *credctx;
} pkinit_req_context;

typedef struct _pkinit_cred_context {
    STACK_OF(X509) *cert;
    STACK_OF(X509) *trustedCAs;
    STACK_OF(X509) *untrustedCAs;
    DH *dh;
} pkinit_cred_context;

int pkinit_get_certs(int type, STACK_OF(X509) **certs);
int get_file_certs(char *name, STACK_OF(X509) **certs);
int get_dir_certs(char *name, STACK_OF(X509) **certs);
int get_pkcs11_certs(char *name, STACK_OF(X509) **certs);

/* Function prototypes */
void openssl_init(void);

krb5_error_code pkinit_init_dh_params(krb5_context, pkinit_context *);
void pkinit_fini_dh_params(krb5_context, pkinit_context *);
krb5_error_code pkinit_encode_dh_params
	(BIGNUM *, BIGNUM *, BIGNUM *, unsigned char **, int *);
DH *pkinit_decode_dh_params
	(DH **, unsigned char **, long ); 
int pkinit_check_dh_params
	(BIGNUM * p1, BIGNUM * p2, BIGNUM * g1, BIGNUM * q1);

krb5_error_code pkinit_sign_data
	(pkinit_req_context *, unsigned char *data, int data_len, 
		unsigned char **sig, int *sig_len, char *filename);

krb5_error_code create_signature
        (unsigned char **, int *, unsigned char *, int, char *);

krb5_error_code pkinit_decode_data
	(pkinit_req_context *, unsigned char *data, int data_len, unsigned char **decoded,
		int *decoded_len, char *filename, X509 *cert);

krb5_error_code decode_data
        (unsigned char **, int *, unsigned char *, int, char *, X509 *cert);

krb5_error_code pkcs7_signeddata_create
	(unsigned char *, int, unsigned char **, int *, X509 *,
		char *, ASN1_OBJECT *, krb5_context, pkinit_req_context *);

krb5_error_code pkcs7_signeddata_verify
	(unsigned char *, int, char **, int *, X509 **,
		ASN1_OBJECT *, krb5_context, pkinit_context *);

krb5_error_code pkinit_octetstring2key
	(krb5_context context, krb5_enctype etype, unsigned char *key,
		int key_len, krb5_keyblock * krb5key);

krb5_error_code pkcs7_envelopeddata_create	
	(unsigned char *key_pack, int key_pack_len, unsigned char **out, 
		int *out_len, X509 *client_cert, X509 *kdc_cert, 
		krb5_preauthtype pa_type, char *filename, 
		ASN1_OBJECT *, krb5_context context);

krb5_error_code pkcs7_envelopeddata_verify
	(unsigned char *, int, char **, int *, X509 *, char *, 
		krb5_preauthtype, X509 **, pkinit_req_context *);

int verify_id_pkinit_san
	(X509 * x, krb5_principal *out, krb5_context context, 
		krb5_preauthtype pa_type, pkinit_context *plgctx);

int verify_id_pkinit_eku
	(pkinit_context *plgctx, X509 *x, krb5_preauthtype pa_type,
	 int require_eku);

krb5_error_code load_trusted_certifiers
	(STACK_OF(X509) **, char *);

krb5_error_code create_krb5_trustedCertifiers
	(STACK_OF(X509) *, krb5_external_principal_identifier ***);

krb5_error_code pkinit_lib_init
	(krb5_context context, void **blob);

void pkinit_lib_fini
	(krb5_context context, void *blob);

krb5_error_code get_filename(char **, char *, int);
X509 *get_cert(char *filename);
void hexdump(const u_char * buf, int len, int offset);
void print_buffer(unsigned char *, int);
void print_buffer_bin(unsigned char *, int, char *);
void print_dh(DH *, unsigned char *);
void print_pubkey(BIGNUM *, unsigned char *);

void init_krb5_pa_pk_as_req(krb5_pa_pk_as_req **in);
void init_krb5_pa_pk_as_req_draft9(krb5_pa_pk_as_req_draft9 **in);
void init_krb5_reply_key_pack(krb5_reply_key_pack **in);
void init_krb5_reply_key_pack_draft9(krb5_reply_key_pack_draft9 **in);
void init_krb5_auth_pack(krb5_auth_pack **in);
void init_krb5_auth_pack_draft9(krb5_auth_pack_draft9 **in);
void init_krb5_pa_pk_as_rep(krb5_pa_pk_as_rep **in);
void init_krb5_typed_data(krb5_typed_data **in);

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

#define TD_TRUSTED_CERTIFIERS 104
#define TD_INVALID_CERTIFICATES 105
#define TD_DH_PARAMETERS 109

#endif	/* _PKINIT_H */

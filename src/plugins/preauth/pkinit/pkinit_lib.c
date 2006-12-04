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

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/asn1_mac.h>
#include <openssl/sha.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>

#ifndef WITHOUT_PKCS11
#include <opensc/pkcs11.h>
#endif

#include <krb5/preauth_plugin.h>
#include <k5-int-pkinit.h>
#include "pkinit.h"

#define FAKECERT
#ifdef DEBUG
#define pkiDebug(args...)       printf(args)
#else
#define pkiDebug(args...)
#endif

#define PKINIT_CTX_MAGIC 0x05551212

/*
 * Custom OIDS to specify as eContentType
 */
unsigned dh_oid_num[6] = { 1, 2, 840, 10046, 2, 1 };
const krb5_octet_data dh_oid = { 0, 7, "\x2A\x86\x48\xce\x3e\x02\x01" };

/* DH parameters */
unsigned char pkinit_1024_dhprime[128] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

unsigned char pkinit_2048_dhprime[2048/8] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
    0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
    0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
    0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
    0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
    0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
    0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
    0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
    0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

unsigned char pkinit_4096_dhprime[4096/8] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
    0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
    0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
    0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
    0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
    0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
    0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
    0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
    0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D,
    0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A, 0x33,
    0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
    0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A,
    0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D,
    0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
    0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7,
    0x1E, 0x8C, 0x94, 0xE0, 0x4A, 0x25, 0x61, 0x9D,
    0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
    0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64,
    0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64,
    0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
    0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C,
    0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2,
    0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
    0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E,
    0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x21, 0x08, 0x01,
    0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7,
    0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA, 0x5B, 0x26,
    0x99, 0xC3, 0x27, 0x18, 0x6A, 0xF4, 0xE2, 0x3C,
    0x1A, 0x94, 0x68, 0x34, 0xB6, 0x15, 0x0B, 0xDA,
    0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8,
    0xDB, 0xBB, 0xC2, 0xDB, 0x04, 0xDE, 0x8E, 0xF9,
    0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6,
    0x28, 0x7C, 0x59, 0x47, 0x4E, 0x6B, 0xC0, 0x5D,
    0x99, 0xB2, 0x96, 0x4F, 0xA0, 0x90, 0xC3, 0xA2,
    0x23, 0x3B, 0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED,
    0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF,
    0xB8, 0x1B, 0xDD, 0x76, 0x21, 0x70, 0x48, 0x1C,
    0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9,
    0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1,
    0x86, 0xFF, 0xB7, 0xDC, 0x90, 0xA6, 0xC0, 0x8F,
    0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x06, 0x31, 0x99,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static int prepare_enc_data
	(unsigned char *indata, int indata_len, unsigned char **outdata,
		int *outdata_len);

static int openssl_callback (int, X509_STORE_CTX *);
static int openssl_callback_ignore_crls (int, X509_STORE_CTX *);

static int pkcs7_decrypt
	(PKCS7 *p7, X509 *cert, BIO *bio, char *filename);

static BIO * pkcs7_dataDecode(PKCS7 *p7, X509 *pcert, char *filename);

/* This handy macro borrowed from crypto/x509v3/v3_purp.c */
#define ku_reject(x, usage) \
	(((x)->ex_flags & EXFLAG_KUSAGE) && !((x)->ex_kusage & (usage)))

krb5_error_code
pkinit_lib_init(krb5_context context, void **blob)
{
    pkinit_context *plgctx;
    krb5_error_code retval = ENOMEM;
    int tmp = 0;

    plgctx = (pkinit_context *) calloc(1, sizeof(*plgctx));
    if (plgctx == NULL) 
	goto out;

    plgctx->magic = PKINIT_CTX_MAGIC;
    plgctx->require_eku = 1;
    plgctx->require_san = 1;
    plgctx->allow_upn = 0;
    plgctx->require_crl_checking = 0;

    plgctx->ctx_identity = NULL;
    plgctx->ctx_anchors = NULL;
    plgctx->ctx_pool = NULL;
    plgctx->ctx_revoke = NULL;
    plgctx->ctx_ocsp = NULL;
    plgctx->ctx_mapping_file = NULL;
    plgctx->ctx_princ_in_cert = 0;
    plgctx->ctx_dh_min_bits = 0;
    plgctx->ctx_allow_proxy_certs = 0;

    tmp = OBJ_create("1.3.6.1.5.2.2", "id-pkinit-san", "KRB5PrincipalName");
    if (tmp == NID_undef) 
	goto out;
    plgctx->id_pkinit_san = OBJ_nid2obj(tmp);

    tmp = OBJ_create("1.3.6.1.5.2.3.1", "id-pkinit-authdata", 
		     "PKINIT signedAuthPack");
    if (tmp == NID_undef) 
	goto out;
    plgctx->id_pkinit_authData = OBJ_nid2obj(tmp);

    tmp = OBJ_create("1.3.6.1.5.2.3.2", "id-pkinit-DHKeyData",
		     "PKINIT dhSignedData");
    if (tmp == NID_undef) 
	goto out;
    plgctx->id_pkinit_DHKeyData = OBJ_nid2obj(tmp);

    tmp = OBJ_create("1.3.6.1.5.2.3.3", "id-pkinit-rkeyData",
		     "PKINIT encKeyPack");
    if (tmp == NID_undef) 
	goto out;
    plgctx->id_pkinit_rkeyData = OBJ_nid2obj(tmp);
    
    tmp = OBJ_create("1.3.6.1.5.2.3.4", "id-pkinit-KPClientAuth",
		     "PKINIT Client EKU");
    if (tmp == NID_undef) 
	goto out;
    plgctx->id_pkinit_KPClientAuth = OBJ_nid2obj(tmp);
    
    tmp = OBJ_create("1.3.6.1.5.2.3.5", "id-pkinit-KPKdc", "KDC EKU");
    if (tmp == NID_undef) 
	goto out;
    plgctx->id_pkinit_KPKdc = OBJ_nid2obj(tmp);
    tmp = OBJ_create("1.2.840.113549.1.7.1", "id-data",
		     "CMS id-data");
    if (tmp == NID_undef) 
	goto out;
    plgctx->id_pkinit_authData9 = OBJ_nid2obj(tmp);
    tmp = OBJ_create("1.3.6.1.4.1.311.20.2.3", "id-pkinit-san draft9",
		     "KRB5PrincipalName draft9");
    if (tmp == NID_undef) 
	goto out;
    plgctx->id_pkinit_san9 = OBJ_nid2obj(tmp);
    tmp = OBJ_create("1.3.6.1.4.1.311.20.2.2", "id-ms-kp-sc-logon EKU",
		     "KDC/Client EKU draft9");
    if (tmp == NID_undef) 
	goto out;
    plgctx->id_ms_kp_sc_logon = OBJ_nid2obj(tmp);
    tmp = OBJ_create("1.3.6.1.5.5.7.3.1", "id-kp-serverAuth EKU",
		     "KDC EKU draft9");
    if (tmp == NID_undef) 
	goto out;
    plgctx->id_kp_serverAuth = OBJ_nid2obj(tmp);

    *blob = (void *) plgctx;
    pkiDebug("%s: returning plgctx at %p\n", __FUNCTION__, plgctx);

    /* initialize openssl routines */
    openssl_init();

    plgctx->dh_1024 = NULL;
    plgctx->dh_2048 = NULL;
    plgctx->dh_4096 = NULL;

    retval = 0;

  out:
    return retval;
}

void
pkinit_lib_fini(krb5_context context, void *blob)
{
    pkinit_context *plgctx;

    plgctx = (pkinit_context *) blob;

    OBJ_cleanup();
    pkiDebug("%s: got plgctx at %p\n", __FUNCTION__, plgctx);
    if (plgctx == NULL || plgctx->magic != PKINIT_CTX_MAGIC) {
	pkiDebug("pkinit_lib_fini: got bad plgctx (%p)!\n", plgctx);
	return;
    }
    free(plgctx);
}

void
openssl_init()
{
    static int did_init;

    if (!did_init) {
	/* initialize openssl routines */
	CRYPTO_malloc_init();
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	did_init++;
    }
}

void
pkinit_fini_dh_params(krb5_context context, pkinit_context *plgctx)
{
    if (plgctx->dh_1024)
	DH_free(plgctx->dh_1024);
    if (plgctx->dh_2048)
	DH_free(plgctx->dh_2048);
    if (plgctx->dh_4096)
	DH_free(plgctx->dh_4096);

    plgctx->dh_1024 = plgctx->dh_2048 = plgctx->dh_4096 = NULL;
}

krb5_error_code
pkinit_init_dh_params(krb5_context context, pkinit_context *plgctx)
{
    krb5_error_code retval = ENOMEM;
    plgctx->dh_1024 = DH_new();
    if (plgctx->dh_1024 == NULL) 
	goto cleanup;
    plgctx->dh_1024->p = BN_bin2bn(pkinit_1024_dhprime, 
	sizeof(pkinit_1024_dhprime), NULL);
    if ((plgctx->dh_1024->g = BN_new()) == NULL ||
	(plgctx->dh_1024->q = BN_new()) == NULL)
	goto cleanup;
    BN_set_word(plgctx->dh_1024->g, DH_GENERATOR_2);
    BN_rshift1(plgctx->dh_1024->q, plgctx->dh_1024->p);

    plgctx->dh_2048 = DH_new();
    if (plgctx->dh_2048 == NULL) 
	goto cleanup;
    plgctx->dh_2048->p = BN_bin2bn(pkinit_2048_dhprime, 
	sizeof(pkinit_2048_dhprime), NULL);
    if ((plgctx->dh_2048->g = BN_new()) == NULL ||
	(plgctx->dh_2048->q = BN_new()) == NULL)
	goto cleanup;
    BN_set_word(plgctx->dh_2048->g, DH_GENERATOR_2);
    BN_rshift1(plgctx->dh_2048->q, plgctx->dh_2048->p);

    plgctx->dh_4096 = DH_new();
    if (plgctx->dh_4096 == NULL) 
	goto cleanup;
    plgctx->dh_4096->p = BN_bin2bn(pkinit_4096_dhprime, 
	sizeof(pkinit_4096_dhprime), NULL);
    if ((plgctx->dh_4096->g = BN_new()) == NULL ||
	(plgctx->dh_4096->q = BN_new()) == NULL)
	goto cleanup;
    BN_set_word(plgctx->dh_4096->g, DH_GENERATOR_2);
    BN_rshift1(plgctx->dh_4096->q, plgctx->dh_4096->p);

    retval = 0;

cleanup:
    if (retval) {
	pkinit_fini_dh_params(context, plgctx);
    }

    return retval;
}

krb5_error_code
pkinit_encode_dh_params(BIGNUM *p, BIGNUM *g, BIGNUM *q, 
			unsigned char **buf, int *buf_len) 
{
    krb5_error_code retval = ENOMEM;
    int bufsize = 0, r = 0;
    unsigned char *tmp = NULL;
    ASN1_INTEGER *ap = NULL, *ag = NULL, *aq = NULL;

    if ((ap = BN_to_ASN1_INTEGER(p, NULL)) == NULL)
	goto cleanup;
    if ((ag = BN_to_ASN1_INTEGER(g, NULL)) == NULL)
	goto cleanup;
    if ((aq = BN_to_ASN1_INTEGER(q, NULL)) == NULL)
	goto cleanup;
    bufsize = i2d_ASN1_INTEGER(ap, NULL);
    bufsize += i2d_ASN1_INTEGER(ag, NULL);
    bufsize += i2d_ASN1_INTEGER(aq, NULL);

    r = ASN1_object_size(1, bufsize, V_ASN1_SEQUENCE);

    tmp = *buf = malloc((size_t) r);
    if (tmp == NULL) 
	goto cleanup;

    ASN1_put_object(&tmp, 1, bufsize, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);

    i2d_ASN1_INTEGER(ap, &tmp);
    i2d_ASN1_INTEGER(ag, &tmp);
    i2d_ASN1_INTEGER(aq, &tmp);

    *buf_len = r;

    retval = 0;

cleanup:
    if (ap != NULL)
	ASN1_INTEGER_free(ap);
    if (ag != NULL)
	ASN1_INTEGER_free(ag);
    if (aq != NULL)
	ASN1_INTEGER_free(aq);

    return retval;
}

DH *
pkinit_decode_dh_params(DH ** a, unsigned char **pp, long length)
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

int
pkinit_check_dh_params(BIGNUM * p1, BIGNUM * p2, BIGNUM * g1, BIGNUM * q1)
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

static int
purpose_print(BIO * bio, X509 * cert, X509_PURPOSE * pt)
{
    int id, i, idret;
    char *pname;
    id = X509_PURPOSE_get_id(pt);
    pname = X509_PURPOSE_get0_name(pt);
    for (i = 0; i < 2; i++) {
	idret = X509_check_purpose(cert, id, i);
	BIO_printf(bio, "%s%s : ", pname, i ? " CA" : "");
	if (idret == 1)
	    BIO_printf(bio, "Yes\n");
	else if (idret == 0)
	    BIO_printf(bio, "No\n");
	else
	    BIO_printf(bio, "Yes (WARNING code=%d)\n", idret);
    }
    return 1;
}

static int
openssl_callback(int ok, X509_STORE_CTX * ctx)
{
#ifdef DEBUG
    if (!ok) {
	X509 *cert = ctx->current_cert;
	char buf[256];

	X509_NAME_oneline(X509_get_subject_name(ctx->current_cert), buf, 256);
	pkiDebug("cert = %s\n", buf);
	pkiDebug("callback function: %d=%s\n", ctx->error,
		X509_verify_cert_error_string(ctx->error));
    }
#endif
    return ok;
}

static int
openssl_callback_ignore_crls(int ok, X509_STORE_CTX * ctx)
{
    if (!ok) {
	switch (ctx->error) {
	    case X509_V_ERR_UNABLE_TO_GET_CRL:
		return 1;
	    default: 
		return 0;
	}
    }
    return ok;
}

krb5_error_code
pkcs7_signeddata_create(unsigned char *data,
			int data_len,
			unsigned char **signed_data,
			int *signed_data_len,
			X509 * cert,
			char *filename,
			ASN1_OBJECT *oid,
			krb5_context context)
{
    krb5_error_code retval = ENOMEM;
    PKCS7  *p7 = NULL, *inner_p7 = NULL;
    PKCS7_SIGNED *p7s = NULL;
    PKCS7_SIGNER_INFO *p7si = NULL;
    unsigned char *p;
    ASN1_TYPE *pkinit_data = NULL;
    STACK_OF(X509) * cert_stack = NULL;
    ASN1_OCTET_STRING *digest_attr = NULL;
    EVP_MD_CTX ctx;
    const EVP_MD *md_tmp;
    unsigned char md_data[EVP_MAX_MD_SIZE], *abuf = NULL;
    unsigned int md_len, alen;
    STACK_OF(X509_ATTRIBUTE) * sk;
    unsigned char *sig = NULL;
    int sig_len = 0;

    /* start creating PKCS7 data */
    if ((p7 = PKCS7_new()) == NULL)
	goto cleanup;
    p7->type = OBJ_nid2obj(NID_pkcs7_signed);

    if ((p7s = PKCS7_SIGNED_new()) == NULL)
	goto cleanup;
    p7->d.sign = p7s;
    if (!ASN1_INTEGER_set(p7s->version, 1))
	goto cleanup;

    /* create a cert chain */
    if ((cert_stack = sk_X509_new_null()) == NULL)
	goto cleanup;
    p7s->cert = cert_stack;
    sk_X509_push(cert_stack, X509_dup(cert));

    /* fill-in PKCS7_SIGNER_INFO */
    if ((p7si = PKCS7_SIGNER_INFO_new()) == NULL)
	goto cleanup;
    if (!ASN1_INTEGER_set(p7si->version, 1))
	goto cleanup;
    if (!X509_NAME_set(&p7si->issuer_and_serial->issuer,
		       X509_get_issuer_name(cert)))
	goto cleanup;
    /* because ASN1_INTEGER_set is used to set a 'long' we will do
     * things the ugly way. */
    M_ASN1_INTEGER_free(p7si->issuer_and_serial->serial);
    if (!(p7si->issuer_and_serial->serial =
	  M_ASN1_INTEGER_dup(X509_get_serialNumber(cert))))
	goto cleanup;

    /* will not fill-out EVP_PKEY because it's on the smartcard */

    /* Set digest algs */
    p7si->digest_alg->algorithm = OBJ_nid2obj(NID_sha1);

    if (p7si->digest_alg->parameter != NULL)
	ASN1_TYPE_free(p7si->digest_alg->parameter);
    if ((p7si->digest_alg->parameter = ASN1_TYPE_new()) == NULL)
	goto cleanup;
    p7si->digest_alg->parameter->type = V_ASN1_NULL;

    /* Set sig algs */
    if (p7si->digest_enc_alg->parameter != NULL)
	ASN1_TYPE_free(p7si->digest_enc_alg->parameter);
    p7si->digest_enc_alg->algorithm = OBJ_nid2obj(NID_rsaEncryption);
    if (!(p7si->digest_enc_alg->parameter = ASN1_TYPE_new()))
	goto cleanup;
    p7si->digest_enc_alg->parameter->type = V_ASN1_NULL;

    /* add signed attributes */
    /* compute sha1 digest over the EncapsulatedContentInfo */
    EVP_MD_CTX_init(&ctx);
    EVP_DigestInit_ex(&ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(&ctx, data, data_len);
    md_tmp = EVP_MD_CTX_md(&ctx);
    EVP_DigestFinal_ex(&ctx, md_data, &md_len);

    /* create a message digest attr */
    digest_attr = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(digest_attr, md_data, md_len);
    PKCS7_add_signed_attribute(p7si, NID_pkcs9_messageDigest,
			       V_ASN1_OCTET_STRING, (char *) digest_attr);

    /* create a content-type attr */
    PKCS7_add_signed_attribute(p7si, NID_pkcs9_contentType, V_ASN1_OBJECT, oid);

    /* create the signature over signed attributes. get DER encoded value */
    /* This is the place where smartcard signature needs to be calculated */
    sk = p7si->auth_attr;
    alen = ASN1_item_i2d((ASN1_VALUE *) sk, &abuf,
			 ASN1_ITEM_rptr(PKCS7_ATTR_SIGN));
    if (abuf == NULL)
	goto cleanup;

    retval = pkinit_sign_data(abuf, alen, &sig, &sig_len, filename);
    free(abuf);
    if (retval)
	goto cleanup;

    /* Add signature */
    if (!ASN1_STRING_set(p7si->enc_digest, (unsigned char *) sig, sig_len)) {
	unsigned long err = ERR_peek_error();
	retval = KRB5KDC_ERR_PREAUTH_FAILED;
	krb5_set_error_message(context, retval, "%s\n", 
			       ERR_error_string(err, NULL));
	pkiDebug("failed to add a signed digest attribute\n");
	goto cleanup;
    }
    /* adder signer_info to pkcs7 signed */
    if (!PKCS7_add_signer(p7, p7si))
	goto cleanup;

    /* start on adding data to the pkcs7 signed */
    if ((inner_p7 = PKCS7_new()) == NULL)
	goto cleanup;
    if ((pkinit_data = ASN1_TYPE_new()) == NULL)
	goto cleanup;
    pkinit_data->type = V_ASN1_OCTET_STRING;
    if ((pkinit_data->value.octet_string = ASN1_OCTET_STRING_new()) == NULL)
	goto cleanup;
    if (!ASN1_OCTET_STRING_set(pkinit_data->value.octet_string, data, 
			       data_len)) {
	unsigned long err = ERR_peek_error();
	retval = KRB5KDC_ERR_PREAUTH_FAILED;
	krb5_set_error_message(context, retval, "%s\n", 
			       ERR_error_string(err, NULL));
	pkiDebug("failed to add pkcs7 data\n");
	goto cleanup;
    }

    if (!PKCS7_set0_type_other(inner_p7, OBJ_obj2nid(oid), pkinit_data)) 
	goto cleanup;
    if (p7s->contents != NULL)
	PKCS7_free(p7s->contents);
    p7s->contents = inner_p7;

    *signed_data_len = i2d_PKCS7(p7, NULL);
    if (!(*signed_data_len)) {
	unsigned long err = ERR_peek_error();
	retval = KRB5KDC_ERR_PREAUTH_FAILED;
	krb5_set_error_message(context, retval, "%s\n", 
			       ERR_error_string(err, NULL));
	pkiDebug("failed to der encode pkcs7\n");
	goto cleanup;
    }
    if ((p = *signed_data =
	 (unsigned char *) malloc(*signed_data_len)) == NULL)
	goto cleanup;

    /* DER encode PKCS7 data */
    retval = i2d_PKCS7(p7, &p);
    if (!retval) {
	unsigned long err = ERR_peek_error();
	retval = KRB5KDC_ERR_PREAUTH_FAILED;
	krb5_set_error_message(context, retval, "%s\n", 
			       ERR_error_string(err, NULL));
	pkiDebug("failed to der encode pkcs7\n");
	goto cleanup;
    }
    retval = 0;

  cleanup:
    if (p7 != NULL)
	PKCS7_free(p7);
    EVP_MD_CTX_cleanup(&ctx);
    if (sig != NULL)
	free(sig);

    return retval;
}

krb5_error_code
pkcs7_signeddata_verify(unsigned char *signed_data,
			int signed_data_len,
			char **data, 
			int *data_len, 
			X509 ** cert,
			ASN1_OBJECT *oid,
			krb5_context context,
			pkinit_context *plgctx)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    PKCS7 *p7 = NULL;
    BIO *out = NULL;
    X509_STORE *store = NULL;
    X509_LOOKUP *lookup = NULL;
    int flags = PKCS7_NOVERIFY, i = 0, size = 0;
    int vflags = 0;
    const unsigned char *p = signed_data;
    STACK_OF(PKCS7_SIGNER_INFO) *si_sk = NULL;
    PKCS7_SIGNER_INFO *si = NULL;
    X509 *x = NULL;
    X509_STORE_CTX cert_ctx;
    char *filename = NULL;

    if (get_filename(&filename, "X509_CA_DIR", 1) != 0) {
	pkiDebug("failed to get the name of the directory for trusted CAs\n");
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    if ((p7 = d2i_PKCS7(NULL, &p, signed_data_len)) == NULL) {
	unsigned long err = ERR_peek_error();
	krb5_set_error_message(context, retval, "%s\n", 
			       ERR_error_string(err, NULL));
	goto cleanup;
    }

    if (OBJ_obj2nid(p7->type) != NID_pkcs7_signed) {
	pkiDebug("Excepted id-signedData PKCS7 mgs (received type = %d)\n",
		 OBJ_obj2nid(p7->type));
	krb5_set_error_message(context, retval, "wrong oid\n");
	goto cleanup;
    }

    /* setup verify */
    if (!(store = X509_STORE_new()))
	goto cleanup;

    if (!X509_STORE_load_locations(store, NULL, filename)) {
	unsigned long err = ERR_peek_error();
	pkiDebug("error loading CA files\n");
	krb5_set_error_message(context, retval, "%s\n", 
			       ERR_error_string(err, NULL));
	goto cleanup;
    }
    vflags = X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL;
    if (plgctx->require_crl_checking) 
	X509_STORE_set_verify_cb_func(store, openssl_callback);
    else 
	X509_STORE_set_verify_cb_func(store, openssl_callback_ignore_crls);

    X509_STORE_set_flags(store, vflags);

    /* get the signer's cert from the chain */
    if ((si_sk = PKCS7_get_signer_info(p7)) == NULL)
	goto cleanup;
    if ((si = sk_PKCS7_SIGNER_INFO_value(si_sk, 0)) == NULL)
	goto cleanup;
    if ((x = PKCS7_cert_from_signer_info(p7, si)) == NULL)
	goto cleanup;
    if (!X509_STORE_CTX_init(&cert_ctx, store, x, p7->d.sign->cert)) 
	goto cleanup;
    i = X509_verify_cert(&cert_ctx);
    if (i <= 0) {
	int j = X509_STORE_CTX_get_error(&cert_ctx);
	*cert = X509_dup(cert_ctx.current_cert);
	switch(j) {
	    case X509_V_ERR_CERT_REVOKED:
		retval = KRB5KDC_ERR_REVOKED_CERTIFICATE;
		break;
	    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
	    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
		retval = KRB5KDC_ERR_CANT_VERIFY_CERTIFICATE;
		break;
	    default:
		retval = KRB5KDC_ERR_INVALID_CERTIFICATE;
	}
	pkiDebug("%s\n", X509_verify_cert_error_string(j));
	krb5_set_error_message(context, retval, "%s\n", 
	    X509_verify_cert_error_string(j));
    }
    X509_STORE_CTX_cleanup(&cert_ctx);
    if (i <= 0) 
	goto cleanup;

    out = BIO_new(BIO_s_mem());
    if (PKCS7_verify(p7, NULL, store, NULL, out, flags)) {
	if (!OBJ_cmp(p7->d.sign->contents->type, oid))
	    pkiDebug("PKCS7 Verification successful\n");
	else {
	    pkiDebug("wrong oid in eContentType\n");
	    retval = KRB5KDC_ERR_PREAUTH_FAILED;
	    krb5_set_error_message(context, retval, "wrong oid\n");
	    goto cleanup;
	}
    }
    else {
	unsigned long err = ERR_peek_error();
	switch(ERR_GET_REASON(err)) {
	    case PKCS7_R_DIGEST_FAILURE:
		retval = KRB5KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED;
		break;
	    case PKCS7_R_SIGNATURE_FAILURE:
	    default:
		retval = KRB5KDC_ERR_INVALID_SIG;
	}
	pkiDebug("PKCS7 Verification failure\n");
	krb5_set_error_message(context, retval, "%s\n", 
			       ERR_error_string(err, NULL));
	goto cleanup;
    }

    for (;;) {
	if ((*data = realloc(*data, size + 1024 * 10)) == NULL)
	    goto cleanup;
	i = BIO_read(out, &((*data)[size]), 1024 * 10);
	if (i <= 0)
	    break;
	else
	    size += i;
    }
    *data_len = size;

    *cert = X509_dup(x);

    retval = 0;

  cleanup:
    if (p7 != NULL)
	PKCS7_free(p7);
    if (out != NULL)
	BIO_free(out);
    if (store != NULL)
	X509_STORE_free(store);
    if (filename != NULL)
	free(filename);

    return retval;
}

static int encode_signeddata(unsigned char *data, int data_len,
			     unsigned char **out, int *out_len) {

    int size = 0, r = 0;
    ASN1_OBJECT *oid;
    unsigned char *p = NULL;

    r = ASN1_object_size(1, data_len, V_ASN1_SEQUENCE);
    oid = OBJ_nid2obj(NID_pkcs7_signed);
    size = i2d_ASN1_OBJECT(oid, NULL);
    size += r;

    r = ASN1_object_size(1, size, V_ASN1_SEQUENCE);
    p = *out = malloc(r);
    if (p == NULL) return -1;
    ASN1_put_object(&p, 1, size, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);

    i2d_ASN1_OBJECT(oid, &p);
    ASN1_put_object(&p, 1, data_len, 0, V_ASN1_CONTEXT_SPECIFIC);
    memcpy(p, data, data_len);

    *out_len = r;

    return 0;
}

krb5_error_code
pkcs7_envelopeddata_verify(unsigned char *enveloped_data,
			   int enveloped_data_len,
			   char **data,
			   int *data_len,
			   X509 *client_cert,
			   char *key_filename,
			   krb5_preauthtype pa_type,
			   pkinit_context *plgctx,
			   X509 ** cert,
			   krb5_context context)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    PKCS7 *p7 = NULL;
    BIO *out = NULL;
    int i = 0, size = 0;
    const unsigned char *p = enveloped_data;

    int tmp_buf_len = 0, tmp_buf2_len = 0;
    unsigned char *tmp_buf = NULL, *tmp_buf2 = NULL;

    if ((p7 = d2i_PKCS7(NULL, &p, enveloped_data_len)) == NULL) {
	unsigned long err = ERR_peek_error();
	pkiDebug("failed to decode pkcs7\n");
	krb5_set_error_message(context, retval, "%s\n", 
			       ERR_error_string(err, NULL));
	goto cleanup;
    }

    if (OBJ_obj2nid(p7->type) != NID_pkcs7_enveloped) {
	pkiDebug("Excepted id-enveloped PKCS7 msg (received type = %d)\n",
		 OBJ_obj2nid(p7->type));
	krb5_set_error_message(context, retval, "wrong oid\n");
	goto cleanup;
    }

    out = BIO_new(BIO_s_mem());
    if (pkcs7_decrypt(p7, client_cert, out, key_filename)) {
	pkiDebug("PKCS7 decryption successful\n");
    } else {
	unsigned long err = ERR_peek_error();
	if (err != 0)
	    krb5_set_error_message(context, retval, "%s\n", 
				   ERR_error_string(err, NULL));
	pkiDebug("PKCS7 decryption failed\n");
	goto cleanup;
    }

    for (;;) {
	if ((tmp_buf = realloc(tmp_buf, size + 1024 * 10)) == NULL)
	    goto cleanup;
	i = BIO_read(out, &(tmp_buf[size]), 1024 * 10);
	if (i <= 0)
	    break;
	else
	    size += i;
    }
    tmp_buf_len = size;
#ifdef DEBUG_ASN1
    print_buffer_bin(tmp_buf, tmp_buf_len, "/tmp/client_enc_keypack");
#endif
    switch (pa_type) {
	case KRB5_PADATA_PK_AS_REP:
	    retval = encode_signeddata(tmp_buf, tmp_buf_len, &tmp_buf2, 
				       &tmp_buf2_len);
	    if (retval) {
		pkiDebug("failed to encode signeddata\n");
		goto cleanup;
	    }
#ifdef DEBUG_ASN1
    print_buffer_bin(tmp_buf2, tmp_buf2_len, "/tmp/client_enc_keypack2");
#endif
	    retval = pkcs7_signeddata_verify(tmp_buf2, tmp_buf2_len, data, 
		data_len, cert, plgctx->id_pkinit_rkeyData, context, plgctx);
	    break;
	case KRB5_PADATA_PK_AS_REP_OLD:
	    retval = pkcs7_signeddata_verify(tmp_buf, tmp_buf_len, data, 
		data_len, cert, plgctx->id_pkinit_authData9, context, plgctx);
	    break;
    }
    if (!retval)
	pkiDebug("PKCS7 Verification Success\n");
    else { 	
	pkiDebug("PKCS7 Verification Failure\n");
	goto cleanup;
    }

    retval = 0;

  cleanup:

    if (p7 != NULL)
	PKCS7_free(p7);
    if (out != NULL)
	BIO_free(out);
    if (tmp_buf != NULL)
	free(tmp_buf);
    if (tmp_buf2 != NULL)
	free(tmp_buf2);

    return retval;
}

static int prepare_enc_data(unsigned char *indata,
		     int indata_len,
		     unsigned char **outdata,
		     int *outdata_len) {
    int retval = -1;
    ASN1_const_CTX c;
    long length = indata_len;
    int Tinf,Ttag,Tclass;
    long Tlen;

    c.pp = (const unsigned char **)&indata;
    c.q = *(const unsigned char **)&indata;
    c.error = ERR_R_NESTED_ASN1_ERROR;
    c.p= *(const unsigned char **)&indata;
    c.max = (length == 0)?0:(c.p+length);

    asn1_GetSequence(&c,&length);

    ASN1_get_object(&c.p,&Tlen,&Ttag,&Tclass,c.slen);
    c.p += Tlen;
    ASN1_get_object(&c.p,&Tlen,&Ttag,&Tclass,c.slen);

    asn1_const_Finish(&c);

    *outdata = malloc(Tlen);
    if (outdata == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    memcpy(*outdata, c.p, Tlen);
    *outdata_len = Tlen;

    retval = 0;
cleanup:

    return retval;
}

krb5_error_code 
pkcs7_envelopeddata_create(unsigned char *key_pack,
			   int key_pack_len,
			   unsigned char **out,
			   int *out_len,
			   X509 *client_cert,
			   X509 *kdc_cert,
			   krb5_preauthtype pa_type,
			   char *filename,
			   ASN1_OBJECT *oid,
			   krb5_context context)
{

    int retval = -1;
    unsigned char *signed_data = NULL, *enc_data = NULL;
    int signed_data_len = 0, enc_data_len = 0;
    STACK_OF(X509) *encerts = NULL;
    const EVP_CIPHER *cipher = NULL;
    int flags = PKCS7_BINARY;
    PKCS7 *p7 = NULL;
    BIO *in = NULL;
    unsigned char *p = NULL;

    retval = pkcs7_signeddata_create(key_pack, key_pack_len, &signed_data,
	&signed_data_len, kdc_cert, filename, oid, context);
    if (retval) {
	pkiDebug("failed to create pkcs7 signed data\n");
	goto cleanup;
    }

    encerts = sk_X509_new_null();
    sk_X509_push(encerts, client_cert);

    cipher = EVP_des_ede3_cbc();
    in = BIO_new(BIO_s_mem());
    switch (pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    prepare_enc_data(signed_data, signed_data_len, &enc_data, 
			     &enc_data_len);
	    retval = BIO_write(in, enc_data, enc_data_len);
	    if (retval != enc_data_len) {
		pkiDebug("BIO_write only wrote %d\n", retval);
		goto cleanup;
	    }
	    break;
	case KRB5_PADATA_PK_AS_REP_OLD:
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    retval = BIO_write(in, signed_data, signed_data_len);
		if (retval != signed_data_len) {
		    pkiDebug("BIO_write only wrote %d\n", retval);
		    goto cleanup;
	    }
	    break;
	default:
	    retval = -1;
	    goto cleanup;
    }

    p7 = PKCS7_encrypt(encerts, in, cipher, flags);
    if (p7 == NULL) {
	pkiDebug("failed to encrypt PKCS7 object\n");
	retval = -1;
	goto cleanup;
    }
    p7->d.enveloped->enc_data->content_type = OBJ_nid2obj(NID_pkcs7_signed);

    *out_len = i2d_PKCS7(p7, NULL);
    if (!*out_len || (p = *out = malloc(*out_len)) == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    retval = i2d_PKCS7(p7, &p);
    if (!retval) {
	pkiDebug("unable to write pkcs7 object\n");
	goto cleanup;
    }

    retval = 0;

cleanup:
    if (p7 != NULL)
	PKCS7_free(p7);
    if (in != NULL)
	BIO_free(in);
    if (signed_data != NULL)
	free(signed_data);
    if (enc_data != NULL)
	free(enc_data);
    if (encerts != NULL)
	sk_X509_free(encerts);
	
    return retval;
}

int
verify_id_pkinit_san(X509 *x, 
		     krb5_principal *out, 
		     krb5_context context, 
		     krb5_preauthtype pa_type,
		     pkinit_context *plgctx)
{
    int i = 0;
    int ok = 0;
    char buf[256];

    if (x == NULL) return -1;

    /* now let's verify that KDC's certificate has id-pkinit-san */
    X509_NAME_oneline(X509_get_subject_name(x), buf, 256);
    pkiDebug("cert = %s\n", buf);

    if ((i = X509_get_ext_by_NID(x, NID_subject_alt_name, -1)) >= 0) {
	X509_EXTENSION *ext = NULL;
	GENERAL_NAMES *ialt = NULL;
	GENERAL_NAME *gen = NULL;
	int ret = 0;

	if (!(ext = X509_get_ext(x, i)) || !(ialt = X509V3_EXT_d2i(ext))) {
	    pkiDebug("unable to retrieve subject alt name ext\n");
	    goto cleanup;
	}

	pkiDebug("found %d subject alt name extension(s)\n", 
		sk_GENERAL_NAME_num(ialt));

	for (i = 0; i < sk_GENERAL_NAME_num(ialt); i++) {
	    krb5_data name = { 0, 0, NULL };

	    gen = sk_GENERAL_NAME_value(ialt, i);
	    switch (gen->type) {
	    case GEN_OTHERNAME:
		name.length = gen->d.otherName->value->value.sequence->length;
		name.data = gen->d.otherName->value->value.sequence->data;
		if (!OBJ_cmp(plgctx->id_pkinit_san, 
			     gen->d.otherName->type_id)) {
#ifdef DEBUG_ASN1
		    print_buffer_bin(name.data, name.length, "/tmp/pkinit_san");
#endif
		    ret = decode_krb5_principal_name(&name, out);
		} else if (plgctx->allow_upn && 
			    !OBJ_cmp(plgctx->id_pkinit_san9, 
				     gen->d.otherName->type_id)) {
		    ret = krb5_parse_name(context, name.data, out);
		} else {
		    pkiDebug("unrecognized or pa_type incorrect oid in SAN\n");
		    continue;
		}

		if (ret) {
		    pkiDebug("failed to decode Krb5PrincipalName in SAN\n"); 
		    break;
		} 
		if (out != NULL)
		    ok = 1;
		break;
	    case GEN_DNS:
		if (pa_type == KRB5_PADATA_PK_AS_REP_OLD) {
		    pkiDebug("Win2K KDC on host = %s\n", gen->d.dNSName->data);
		    ok = 1;
		}
		break;
	    default:
		pkiDebug("SAN type = %d expecting %d\n", gen->type,
			GEN_OTHERNAME);
	    }
	    if (ok)
		break;
	}
	sk_GENERAL_NAME_free(ialt);
    }

    if (!ok) {
	pkiDebug("didn't find id_pkinit_san\n");
    }

  cleanup:
    return ok;
}

int
verify_id_pkinit_eku(pkinit_context *plgctx,
		     X509 * x,
		     krb5_preauthtype pa_type,
		     int require_eku)
{
    int i = 0;
    int ok = 0;
    char buf[256];
    int id_pkinit_eku = 0;
    ASN1_OBJECT * oid_client = NULL, *oid_server = NULL; 
    ASN1_OBJECT *oid_logon = NULL, *oid_kp = NULL;

    if (x == NULL) return -1;

    /* now let's verify that KDC's certificate has pkinit EKU */
    X509_NAME_oneline(X509_get_subject_name(x), buf, 256);
    pkiDebug("cert = %s\n", buf);

    oid_client = plgctx->id_pkinit_KPClientAuth;
    oid_server = plgctx->id_pkinit_KPKdc;
    oid_logon = plgctx->id_ms_kp_sc_logon;
    oid_kp = plgctx->id_kp_serverAuth;

    if ((i = X509_get_ext_by_NID(x, NID_ext_key_usage, -1)) >= 0) {
	EXTENDED_KEY_USAGE *extusage;

	if ((extusage = X509_get_ext_d2i(x, NID_ext_key_usage, NULL, NULL))) {
	    for (i = 0; i < sk_ASN1_OBJECT_num(extusage); i++) {
		ASN1_OBJECT *tmp_oid = NULL;
		int flag = 0;

		tmp_oid = sk_ASN1_OBJECT_value(extusage, i);
		switch ((int)pa_type) {
		    case KRB5_PADATA_PK_AS_REQ_OLD:
		    case KRB5_PADATA_PK_AS_REQ:
			if (!OBJ_cmp(oid_client, tmp_oid) ||
			    !OBJ_cmp(oid_logon, tmp_oid))
			    flag = 1;
			break;
		    case KRB5_PADATA_PK_AS_REP_OLD:
		    case KRB5_PADATA_PK_AS_REP:
			if (!OBJ_cmp(oid_server, tmp_oid) ||
			    !OBJ_cmp(oid_kp, tmp_oid))
			    flag = 1;
			break;
		    default: 
			goto cleanup;
		}
		if (flag) {
		    ASN1_BIT_STRING *usage = NULL;
		    pkiDebug("found pa_type-specific EKU\n");

		    /* check that digitalSignature KeyUsage is present */
		    if ((usage =
			 X509_get_ext_d2i(x, NID_key_usage, NULL, NULL))) {

			if (!ku_reject(x, X509v3_KU_DIGITAL_SIGNATURE)) {
			    pkiDebug("found digitalSignature KU\n");
			    ok = 1;
			} else
			    pkiDebug("didn't find digitalSignature KU\n");
		    }

		    ASN1_BIT_STRING_free(usage);
		    break;
		}
	    }
	}
    }
cleanup:
    if (!ok) {
	pkiDebug("didn't find extended key usage (EKU) for pkinit\n");
	if (0 == require_eku) {
	    pkiDebug("configuration says ignore missing EKU\n");
	    ok = 1;
	}
    }

    return ok;
}

krb5_error_code
pkinit_octetstring2key(krb5_context context,
		       krb5_enctype etype,
		       unsigned char *key,
		       int dh_key_len, 
		       krb5_keyblock * key_block)
{
    krb5_error_code retval;
    unsigned char *buf = NULL;
    unsigned char md[SHA_DIGEST_LENGTH];
    unsigned char counter;
    size_t keybytes, keylength, offset;
    int i;
    krb5_data random_data;

    
    if ((buf = (unsigned char *) malloc(dh_key_len)) == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    memset(buf, 0, dh_key_len);

    counter = 0;
    offset = 0;
    do {
	SHA_CTX c;

	SHA1_Init(&c);
	SHA1_Update(&c, &counter, 1);
	SHA1_Update(&c, key, dh_key_len);
	SHA1_Final(md, &c);

	if (dh_key_len - offset < sizeof(md))
	    memcpy(buf + offset, md, dh_key_len - offset);
	else
	    memcpy(buf + offset, md, sizeof(md));

	offset += sizeof(md);
	counter++;
    } while (offset < dh_key_len);

    key_block->magic = 0;
    key_block->enctype = etype;

    retval = krb5_c_keylengths(context, etype, &keybytes, &keylength);
    if (retval)
	goto cleanup;

    key_block->length = keylength;
    key_block->contents = calloc(keylength, 1);
    if (key_block->contents == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }

    random_data.length = keybytes;
    random_data.data = buf;

    retval = krb5_c_random_to_key(context, etype, &random_data, key_block);

  cleanup:
    if (buf != NULL)
	free(buf);
    if (retval && key_block->contents != NULL && key_block->length != 0) {
	memset(key_block->contents, 0, key_block->length);
	key_block->length = 0;
    }

    return retval;
}

/* debugging functions */
void
hexdump(const u_char * buf, int len, int offset)
{

    u_int i, j, jm;
    int c;
    char msgbuff[256];
    char *m = msgbuff;
    int written;

    if (buf == NULL || len <= 0)
	return;

    for (i = 0; i < len; i += 0x10) {
	written = sprintf(m, "\t%04x: ", (u_int) (i + offset));
	m += written;
	jm = len - i;
	jm = jm > 16 ? 16 : jm;

	for (j = 0; j < jm; j++) {
	    if ((j % 2) == 1)
		written = sprintf(m, "%02x ", (u_int) buf[i + j]);
	    else
		written = sprintf(m, "%02x", (u_int) buf[i + j]);
	    m += written;
	}
	for (; j < 16; j++) {
	    if ((j % 2) == 1)
		written = sprintf(m, "\t ");
	    else
		written = sprintf(m, "\t");
	    m += written;
	}
	sprintf(m, " ");
	m++;

	for (j = 0; j < jm; j++) {
	    c = buf[i + j];
	    c = isprint(c) ? c : '.';
	    sprintf(m, "%c", c);
	    m++;
	}
	sprintf(m, "\n");

	pkiDebug("%s", msgbuff);
	m = msgbuff;
	memset(msgbuff, '\0', sizeof(msgbuff));
    }
}

void
print_buffer(unsigned char *buf, int len)
{
    int i = 0;
    if (len <= 0)
	return;

    for (i = 0; i < len; i++)
	pkiDebug("%02x ", buf[i]);
    pkiDebug("\n");
}

void
print_buffer_bin(unsigned char *buf, int len, char *filename)
{
    FILE *f = NULL;
    int i = 0;

    if (len <= 0 || filename == NULL)
	return;

    if ((f = fopen(filename, "w")) == NULL)
	return;

    for (i = 0; i < len; i++)
	fputc(buf[i], f);

    fclose(f);
}

void
print_dh(DH * dh, unsigned char *msg)
{
    BIO *bio_err = NULL;

    bio_err = BIO_new(BIO_s_file());
    BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (msg)
	BIO_puts(bio_err, msg);
    if (dh)
	DHparams_print(bio_err, dh);

    BN_print(bio_err, dh->q);
    BIO_puts(bio_err, "\n");
    BIO_free(bio_err);

}

void
print_pubkey(BIGNUM * key, unsigned char *msg)
{
    BIO *bio_err = NULL;

    bio_err = BIO_new(BIO_s_file());
    BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (msg)
	BIO_puts(bio_err, msg);
    if (key)
	BN_print(bio_err, key);
    BIO_puts(bio_err, "\n");

    BIO_free(bio_err);

}

krb5_error_code
get_filename(char **name, char *env_name, int type)
{
    char *ev;

    if ((*name = (unsigned char *) malloc(1024)) == NULL)
	return ENOMEM;

    if ((ev = getenv(env_name)) == NULL) {
	if (!type) {
	    snprintf(*name, 1024, "/tmp/x509up_u%d", geteuid());
	    pkiDebug("using %s=%s\n", env_name, *name);
	} else {
	    free(*name);
	    *name = NULL;
	    return ENOENT;
	}
    } else {
	pkiDebug("found %s=%s\n", env_name, ev);
	snprintf(*name, 1024, "%s", ev);
    }

    return 0;
}

krb5_error_code
decode_data(unsigned char **out_data, int *out_data_len, unsigned char *data,
	    int data_len, char *filename, X509 *cert)
{
    krb5_error_code retval = ENOMEM;
    BIO *tmp = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *buf = NULL;
    int buf_len = 0;

    if (filename == NULL)
	return ENOENT;

    if ((tmp = BIO_new(BIO_s_file()))
	&& (BIO_read_filename(tmp, filename) > 0))
	pkey = (EVP_PKEY *) PEM_read_bio_PrivateKey(tmp, NULL, NULL, NULL);
    if (pkey == NULL) {
	pkiDebug("failed to get private key from %s\n", filename);
	goto cleanup;
    }
    if (cert && !X509_check_private_key(cert, pkey)) {
	pkiDebug("private key does not match certificate\n");
	goto cleanup;
    }
    if (tmp != NULL)
	BIO_free(tmp);

    buf_len = EVP_PKEY_size(pkey);
    buf = malloc(buf_len + 10);
    if (buf == NULL)
	goto cleanup;

    retval = EVP_PKEY_decrypt(buf, data, data_len, pkey);
    if (retval <= 0) {
	pkiDebug("unable to decrypt received data (len=%d)\n", data_len);
	goto cleanup;
    }
    *out_data = buf;
    *out_data_len = retval;

  cleanup:
    if (pkey != NULL) 
	EVP_PKEY_free(pkey);
    if (retval == ENOMEM)
	free(buf);

    return retval;
}
krb5_error_code
create_signature(unsigned char **sig, int *sig_len, unsigned char *data,
		 int data_len, char *filename)
{
    krb5_error_code retval = ENOMEM;
    BIO *tmp = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX md_ctx;

    if (filename == NULL)
	return ENOENT;

    if ((tmp = BIO_new(BIO_s_file()))
	&& (BIO_read_filename(tmp, filename) > 0))
	pkey = (EVP_PKEY *) PEM_read_bio_PrivateKey(tmp, NULL, NULL, NULL);
    if (pkey == NULL) {
	pkiDebug("failed to get private key from %s\n", filename);
	goto cleanup;
    }
	
    if (tmp != NULL)
	BIO_free(tmp);

    EVP_VerifyInit(&md_ctx, EVP_sha1());
    EVP_SignUpdate(&md_ctx, data, data_len);
    *sig_len = EVP_PKEY_size(pkey);
    if ((*sig = (unsigned char *) malloc(*sig_len)) == NULL)
	goto cleanup;
    EVP_SignFinal(&md_ctx, *sig, sig_len, pkey);

    retval = 0;

  cleanup:
    if (pkey != NULL) {
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_cleanup(&md_ctx);
    }

    return retval;
}

X509   *
get_cert(char *filename)
{
    X509 *cert = NULL;
    BIO *tmp = NULL;

    if (filename == NULL)
	return NULL;

    if ((tmp = BIO_new(BIO_s_file()))
	&& (BIO_read_filename(tmp, filename) > 0))
	cert = (X509 *) PEM_read_bio_X509(tmp, NULL, NULL, NULL);
    if (tmp != NULL)
	BIO_free(tmp);

    return cert;
}

krb5_error_code 
load_trusted_certifiers(STACK_OF(X509) **trusted_CAs, 
			char *filename) 
{
    STACK_OF(X509_INFO) *sk = NULL;
    STACK_OF(X509) *ca_certs = NULL;
    BIO *in = NULL;
    krb5_error_code retval = ENOMEM;

    *trusted_CAs = NULL;

    ca_certs = sk_X509_new_null();
    if (!ca_certs) {
	return ENOMEM;
    }

    if (!(in = BIO_new_file(filename, "r"))) {
	pkiDebug("error opening the CAfile\n");
	goto cleanup;
    }

    /* This loads from a file, a stack of x509/crl/pkey sets */
    if ((sk = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL)) == NULL) {
	pkiDebug("error reading the CAfile\n");
	goto cleanup;
    }

    /* scan over it and pull out the certs */
    while (sk_X509_INFO_num(sk)) {
	X509_INFO *xi = NULL;

	xi = sk_X509_INFO_shift(sk);
	if (xi->x509 != NULL) {
	    sk_X509_push(ca_certs, xi->x509);
	    xi->x509 = NULL;
	}
	X509_INFO_free(xi);
    }

    if (!sk_X509_num(ca_certs)) {
	pkiDebug("no certificates in file, %s\n", filename);
	sk_X509_free(ca_certs);
    } else
	*trusted_CAs = ca_certs;

    retval = 0;

  cleanup:

    if (in != NULL)
	BIO_free(in);
    if (sk != NULL)
	sk_X509_INFO_free(sk);

    return retval;
}

krb5_error_code
create_krb5_trustedCertifiers(STACK_OF(X509) * sk,
			      krb5_external_principal_identifier *** ids)
{

    krb5_error_code retval = ENOMEM;
    int i = 0, sk_size = sk_X509_num(sk);
    krb5_external_principal_identifier **krb5_cas = NULL;

    krb5_cas =
	malloc((sk_size + 1) * sizeof(krb5_external_principal_identifier *));
    if (krb5_cas == NULL)
	return ENOMEM;
    krb5_cas[sk_size] = NULL;

    for (i = 0; i < sk_size; i++) {
	X509 *x = NULL;
	char buf[256];
	X509_NAME *xn = NULL;
	unsigned char *p = NULL;
	int len = 0;
	PKCS7_ISSUER_AND_SERIAL *is = NULL;

	krb5_cas[i] = malloc(sizeof(krb5_external_principal_identifier));

	x = sk_X509_value(sk, i);

	X509_NAME_oneline(X509_get_subject_name(x), buf, 256);
	pkiDebug("#%d cert= %s\n", i, buf);

	/* fill-in subjectName */
	krb5_cas[i]->subjectName.magic = 0;
	krb5_cas[i]->subjectName.length = 0;
	krb5_cas[i]->subjectName.data = NULL;

	xn = X509_get_subject_name(x);
	len = i2d_X509_NAME(xn, NULL);
	if ((p = krb5_cas[i]->subjectName.data = malloc((size_t) len)) == NULL)
	    goto cleanup;
	i2d_X509_NAME(xn, &p);
	krb5_cas[i]->subjectName.length = len;

	/* fill-in issuerAndSerialNumber */
	krb5_cas[i]->issuerAndSerialNumber.length = 0;
	krb5_cas[i]->issuerAndSerialNumber.magic = 0;
	krb5_cas[i]->issuerAndSerialNumber.data = NULL;

	is = PKCS7_ISSUER_AND_SERIAL_new();
	X509_NAME_set(&is->issuer, X509_get_issuer_name(x));
	M_ASN1_INTEGER_free(is->serial);
	is->serial = M_ASN1_INTEGER_dup(X509_get_serialNumber(x));
	len = i2d_PKCS7_ISSUER_AND_SERIAL(is, NULL);
	if ((p = krb5_cas[i]->issuerAndSerialNumber.data =
	     malloc((size_t) len)) == NULL)
	    goto cleanup;
	i2d_PKCS7_ISSUER_AND_SERIAL(is, &p);
	krb5_cas[i]->issuerAndSerialNumber.length = len;

	/* fill-in subjectKeyIdentifier */
	krb5_cas[i]->subjectKeyIdentifier.length = 0;
	krb5_cas[i]->subjectKeyIdentifier.magic = 0;
	krb5_cas[i]->subjectKeyIdentifier.data = NULL;

	if (X509_get_ext_by_NID(x, NID_subject_key_identifier, -1) >= 0) {
	    ASN1_OCTET_STRING *ikeyid = NULL;

	    if ((ikeyid = X509_get_ext_d2i(x, NID_subject_key_identifier, NULL,
					   NULL))) {
		len = i2d_ASN1_OCTET_STRING(ikeyid, NULL);
		if ((p = krb5_cas[i]->subjectKeyIdentifier.data =
			malloc((size_t) len)) == NULL)
		    goto cleanup;
		i2d_ASN1_OCTET_STRING(ikeyid, &p);		
		krb5_cas[i]->subjectKeyIdentifier.length = len;
	    }
	    if (ikeyid != NULL)
		ASN1_OCTET_STRING_free(ikeyid);
	}
	if (is != NULL) {
	    if (is->issuer != NULL)
		X509_NAME_free(is->issuer);
	    if (is->serial != NULL)
		ASN1_INTEGER_free(is->serial);
	    free(is);
	}
    }

    *ids = krb5_cas;

    retval = 0;
  cleanup:
    if (retval)
	free_krb5_external_principal_identifier(&krb5_cas);

    return retval;
}

static int 
pkcs7_decrypt(PKCS7 *p7, X509 *cert, BIO *data, char *filename) 
{
    int flags = PKCS7_BINARY;
    BIO *tmpmem = NULL;
    int retval = 0, i = 0;
    char buf[4096];

    if(p7 == NULL) 
	return 0;

    if(!PKCS7_type_is_enveloped(p7)) {
	pkiDebug("wrong pkcs7 content type\n");
	return 0;
    }

    if(!(tmpmem = pkcs7_dataDecode(p7, cert, filename))) {
	pkiDebug("unable to decrypt pkcs7 object\n");
	return 0;
    }

    for(;;) {
	i = BIO_read(tmpmem, buf, sizeof(buf));
	if (i <= 0) break;
	BIO_write(data, buf, i);
	BIO_free_all(tmpmem);
	return 1;
    }
    return retval;
}

static BIO * 
pkcs7_dataDecode(PKCS7 *p7, X509 *pcert, char *filename)
{
    int i = 0, jj= 0, jj2 = 0, tmp_len = 0;
    BIO *out=NULL,*etmp=NULL,*bio=NULL;
    unsigned char *tmp=NULL, *tmp1 = NULL;
    X509_ALGOR *xa;
    ASN1_OCTET_STRING *data_body=NULL;
    const EVP_CIPHER *evp_cipher=NULL;
    EVP_CIPHER_CTX *evp_ctx=NULL;
    X509_ALGOR *enc_alg=NULL;
    STACK_OF(X509_ALGOR) *md_sk=NULL;
    STACK_OF(PKCS7_RECIP_INFO) *rsk=NULL;
    X509_ALGOR *xalg=NULL;
    PKCS7_RECIP_INFO *ri=NULL;

    p7->state=PKCS7_S_HEADER;

    rsk=p7->d.enveloped->recipientinfo;
    enc_alg=p7->d.enveloped->enc_data->algorithm;
    data_body=p7->d.enveloped->enc_data->enc_data;
    evp_cipher=EVP_get_cipherbyobj(enc_alg->algorithm);
    if (evp_cipher == NULL) {
	PKCS7err(PKCS7_F_PKCS7_DATADECODE,PKCS7_R_UNSUPPORTED_CIPHER_TYPE);
	goto cleanup;
    }
    xalg=p7->d.enveloped->enc_data->algorithm;

    if ((etmp=BIO_new(BIO_f_cipher())) == NULL) {
	PKCS7err(PKCS7_F_PKCS7_DATADECODE,ERR_R_BIO_LIB);
	goto cleanup;
    }

/* It was encrypted, we need to decrypt the secret key
 * with the private key */

/* Find the recipientInfo which matches the passed certificate
 * (if any)
 */

    if (pcert) {
	for (i=0; i<sk_PKCS7_RECIP_INFO_num(rsk); i++) {
	    int tmp_ret = 0;
	    ri=sk_PKCS7_RECIP_INFO_value(rsk,i);
	    tmp_ret = X509_NAME_cmp(ri->issuer_and_serial->issuer, 
				    pcert->cert_info->issuer);
	    if (!tmp_ret) {
		tmp_ret = M_ASN1_INTEGER_cmp(pcert->cert_info->serialNumber, 
					     ri->issuer_and_serial->serial);
		if (!tmp_ret)
		    break;
	    }
	    ri=NULL;
	}
	if (ri == NULL) {
	    PKCS7err(PKCS7_F_PKCS7_DATADECODE, 
		     PKCS7_R_NO_RECIPIENT_MATCHES_CERTIFICATE);
	    goto cleanup;
	}
	
    }

/* If we haven't got a certificate try each ri in turn */

    if (pcert == NULL) {
	for (i=0; i<sk_PKCS7_RECIP_INFO_num(rsk); i++) {
	    ri=sk_PKCS7_RECIP_INFO_value(rsk,i);
	    jj = pkinit_decode_data(M_ASN1_STRING_data(ri->enc_key),
				    M_ASN1_STRING_length(ri->enc_key),
				    &tmp, &tmp_len, filename, pcert);
	    if (jj) {
		PKCS7err(PKCS7_F_PKCS7_DATADECODE, ERR_R_EVP_LIB);
		goto cleanup;
	    }

	    if (!jj && tmp_len > 0) {
		jj = tmp_len;
		break;
	    }

	    ERR_clear_error();
	    ri = NULL;
	}
    
	if (ri == NULL) {
	    PKCS7err(PKCS7_F_PKCS7_DATADECODE, PKCS7_R_NO_RECIPIENT_MATCHES_KEY);
	    goto cleanup;
	}
    }
    else {
	jj = pkinit_decode_data(M_ASN1_STRING_data(ri->enc_key),
				M_ASN1_STRING_length(ri->enc_key),
				&tmp, &tmp_len, filename, pcert);
	if (jj || tmp_len <= 0) {
	    PKCS7err(PKCS7_F_PKCS7_DATADECODE, ERR_R_EVP_LIB);
	    goto cleanup;
	}
	jj = tmp_len;
    }

    evp_ctx=NULL;
    BIO_get_cipher_ctx(etmp,&evp_ctx);
    if (EVP_CipherInit_ex(evp_ctx,evp_cipher,NULL,NULL,NULL,0) <= 0)
	goto cleanup;
    if (EVP_CIPHER_asn1_to_param(evp_ctx,enc_alg->parameter) < 0)
	goto cleanup;

    if (jj != EVP_CIPHER_CTX_key_length(evp_ctx)) {
/* Some S/MIME clients don't use the same key
 * and effective key length. The key length is
 * determined by the size of the decrypted RSA key.
 */
	if(!EVP_CIPHER_CTX_set_key_length(evp_ctx, jj)) {
	    PKCS7err(PKCS7_F_PKCS7_DATADECODE, 
		     PKCS7_R_DECRYPTED_KEY_IS_WRONG_LENGTH);
	    goto cleanup;
	}
    } 
    if (EVP_CipherInit_ex(evp_ctx,NULL,NULL,tmp,NULL,0) <= 0)
	goto cleanup;

    OPENSSL_cleanse(tmp,jj);

    if (out == NULL)
	out=etmp;
    else
	BIO_push(out,etmp);
    etmp=NULL;

    if (data_body->length > 0)
	bio = BIO_new_mem_buf(data_body->data, data_body->length);
    else {
	bio=BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(bio,0);
    }
    BIO_push(out,bio);
    bio=NULL;

    if (0) {
cleanup:
	if (out != NULL) BIO_free_all(out);
	if (etmp != NULL) BIO_free_all(etmp);
	if (bio != NULL) BIO_free_all(bio);
	out=NULL;
    }

    if (tmp != NULL)
	free(tmp);

    return(out);
}

void free_krb5_pa_pk_as_req(krb5_pa_pk_as_req **in)
{
    if (*in == NULL) return;
    if ((*in)->signedAuthPack.data != NULL)
	free((*in)->signedAuthPack.data);
    if ((*in)->trustedCertifiers != NULL) 
	free_krb5_external_principal_identifier(&(*in)->trustedCertifiers);
    if ((*in)->kdcPkId.data != NULL)
	free((*in)->kdcPkId.data);
    free(*in);
}

void free_krb5_pa_pk_as_req_draft9(krb5_pa_pk_as_req_draft9 **in)
{
    if (*in == NULL) return;
    if ((*in)->signedAuthPack.data != NULL)
	free((*in)->signedAuthPack.data);
    if ((*in)->kdcCert.data != NULL)
	free((*in)->kdcCert.data);
    if ((*in)->encryptionCert.data != NULL)
	free((*in)->encryptionCert.data);
    if ((*in)->trustedCertifiers != NULL) 
	free_krb5_trusted_ca(&(*in)->trustedCertifiers);
    free(*in);
}

void free_krb5_reply_key_pack(krb5_reply_key_pack **in)
{
    if (*in == NULL) return;
    if ((*in)->replyKey.contents != NULL)
	free((*in)->replyKey.contents);
    if ((*in)->asChecksum.contents != NULL)
	free((*in)->asChecksum.contents);
    free(*in);
}

void free_krb5_reply_key_pack_draft9(krb5_reply_key_pack_draft9 **in)
{
    if (*in == NULL) return;
    if ((*in)->replyKey.contents != NULL)
	free((*in)->replyKey.contents);
    free(*in);
}

void free_krb5_auth_pack(krb5_auth_pack **in)
{
    if ((*in) == NULL) return;
    if ((*in)->clientPublicValue != NULL) {
    /* not freeing clientPublicValue->algorithm.algorithm.data because
     * client has that as static memory but server allocates it therefore
     * the server will free it outside of this function
     */
	if ((*in)->clientPublicValue->algorithm.parameters.data != NULL)
	    free((*in)->clientPublicValue->algorithm.parameters.data);
	if ((*in)->clientPublicValue->subjectPublicKey.data != NULL)
	    free((*in)->clientPublicValue->subjectPublicKey.data);
	free((*in)->clientPublicValue);
    }
    if ((*in)->pkAuthenticator.paChecksum.contents != NULL)
	free((*in)->pkAuthenticator.paChecksum.contents);
    free(*in);
}

void free_krb5_auth_pack_draft9(krb5_context context,
				krb5_auth_pack_draft9 **in)
{
    if ((*in) == NULL) return;
    krb5_free_principal(context, (*in)->pkAuthenticator.kdcName);
    free(*in);
}

void free_krb5_pa_pk_as_rep(krb5_pa_pk_as_rep **in)
{
    if (*in == NULL) return;
    switch ((*in)->choice) {
	case choice_pa_pk_as_rep_dhInfo:
	    if ((*in)->u.dh_Info.dhSignedData.data != NULL)
		free((*in)->u.dh_Info.dhSignedData.data);
	    break;
	case choice_pa_pk_as_rep_encKeyPack:
	    if ((*in)->u.encKeyPack.data != NULL)
		free((*in)->u.encKeyPack.data);
	    break;
	default:
	    break;
    }
    free(*in);
}

void free_krb5_pa_pk_as_rep_draft9(krb5_pa_pk_as_rep_draft9 **in)
{
    if (*in == NULL) return;
    if ((*in)->u.encKeyPack.data != NULL)
	free((*in)->u.encKeyPack.data);
    free(*in);
}

void free_krb5_external_principal_identifier(krb5_external_principal_identifier ***in)
{
    int i = 0;
    if (*in == NULL) return;
    while ((*in)[i] != NULL) {
	if ((*in)[i]->subjectName.data != NULL)
	    free((*in)[i]->subjectName.data);
	if ((*in)[i]->issuerAndSerialNumber.data != NULL)
	    free((*in)[i]->issuerAndSerialNumber.data);
	if ((*in)[i]->subjectKeyIdentifier.data != NULL)
	    free((*in)[i]->subjectKeyIdentifier.data);
	free((*in)[i]);
	i++;
    }
    free(*in);
}   

void free_krb5_trusted_ca(krb5_trusted_ca ***in) 
{
    int i = 0;
    if (*in == NULL) return;
    while ((*in)[i] != NULL) {
	switch((*in)[i]->choice) {
	    case choice_trusted_cas_principalName: 
		break;
	    case choice_trusted_cas_caName:
		if ((*in)[i]->u.caName.data != NULL)
		    free((*in)[i]->u.caName.data);
		break;
	    case choice_trusted_cas_issuerAndSerial:
		if ((*in)[i]->u.issuerAndSerial.data != NULL)
		    free((*in)[i]->u.issuerAndSerial.data);
		break;
	}
	free((*in)[i]);
	i++;
    }
    free(*in);
}

void free_krb5_typed_data(krb5_typed_data ***in) 
{
    int i = 0;
    if (*in == NULL) return;
    while ((*in)[i] != NULL) {
	if ((*in)[i]->data != NULL)
	    free((*in)[i]->data);
	free((*in)[i]);
	i++;
    }
    free(*in);
}

void free_krb5_algorithm_identifier(krb5_algorithm_identifier ***in)
{
    int i = 0;
    if (*in == NULL) return;
    while ((*in)[i] != NULL) {
	if ((*in)[i]->algorithm.data != NULL)
	    free((*in)[i]->algorithm.data);
	if ((*in)[i]->parameters.data != NULL)
	    free((*in)[i]->parameters.data);
	free((*in)[i]);
	i++;
    }
    free(*in);
}

void init_krb5_pa_pk_as_req(krb5_pa_pk_as_req **in)
{
    (*in) = malloc(sizeof(krb5_pa_pk_as_req));
    if ((*in) == NULL) return;
    (*in)->signedAuthPack.data = NULL;
    (*in)->signedAuthPack.length = 0;
    (*in)->trustedCertifiers = NULL;
    (*in)->kdcPkId.data = NULL;
    (*in)->kdcPkId.length = 0;
}

void init_krb5_pa_pk_as_req_draft9(krb5_pa_pk_as_req_draft9 **in)
{
    (*in) = malloc(sizeof(krb5_pa_pk_as_req_draft9));
    if ((*in) == NULL) return;
    (*in)->signedAuthPack.data = NULL;
    (*in)->signedAuthPack.length = 0;
    (*in)->trustedCertifiers = NULL;
    (*in)->kdcCert.data = NULL;
    (*in)->kdcCert.length = 0;
    (*in)->encryptionCert.data = NULL;
    (*in)->encryptionCert.length = 0;
}

void init_krb5_reply_key_pack(krb5_reply_key_pack **in)
{
    (*in) = malloc(sizeof(krb5_reply_key_pack));
    if ((*in) == NULL) return;
    (*in)->replyKey.contents = NULL;
    (*in)->replyKey.length = 0;
    (*in)->asChecksum.contents = NULL;
    (*in)->asChecksum.length = 0;
}

void init_krb5_reply_key_pack_draft9(krb5_reply_key_pack_draft9 **in)
{
    (*in) = malloc(sizeof(krb5_reply_key_pack_draft9));
    if ((*in) == NULL) return;
    (*in)->replyKey.contents = NULL;
    (*in)->replyKey.length = 0;
}

void init_krb5_auth_pack(krb5_auth_pack **in)
{
    (*in) = malloc(sizeof(krb5_auth_pack));
    if ((*in) == NULL) return;
    (*in)->clientPublicValue = NULL;
    (*in)->supportedCMSTypes = NULL;
    (*in)->clientDHNonce.length = 0;
    (*in)->clientDHNonce.data = NULL;
    (*in)->pkAuthenticator.paChecksum.contents = NULL;
}

void init_krb5_auth_pack_draft9(krb5_auth_pack_draft9 **in)
{
    (*in) = malloc(sizeof(krb5_auth_pack_draft9));
    if ((*in) == NULL) return;
    (*in)->clientPublicValue = NULL;
}

void init_krb5_pa_pk_as_rep(krb5_pa_pk_as_rep **in) 
{
    (*in) = malloc(sizeof(krb5_pa_pk_as_rep));
    if ((*in) == NULL) return;
    (*in)->u.dh_Info.serverDHNonce.length = 0;
    (*in)->u.dh_Info.serverDHNonce.data = NULL;
    (*in)->u.dh_Info.dhSignedData.length = 0;
    (*in)->u.dh_Info.dhSignedData.data = NULL;
    (*in)->u.encKeyPack.length = 0;
    (*in)->u.encKeyPack.data = NULL;
}

void init_krb5_pa_pk_as_rep_draft9(krb5_pa_pk_as_rep_draft9 **in) 
{
    (*in) = malloc(sizeof(krb5_pa_pk_as_rep_draft9));
    if ((*in) == NULL) return;
    (*in)->u.dhSignedData.length = 0;
    (*in)->u.dhSignedData.data = NULL;
    (*in)->u.encKeyPack.length = 0;
    (*in)->u.encKeyPack.data = NULL;
}

void init_krb5_typed_data(krb5_typed_data **in) 
{
    (*in) = malloc(sizeof(krb5_typed_data));
    if ((*in) == NULL) return;
    (*in)->type = 0;
    (*in)->length = 0;
    (*in)->data = NULL;
}

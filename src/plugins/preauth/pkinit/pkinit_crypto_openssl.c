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

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <dirent.h>

#define SILLYDECRYPT

#include "pkinit_crypto_openssl.h"

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

const krb5_octet_data dh_oid = { 0, 7, "\x2A\x86\x48\xce\x3e\x02\x01" };

static krb5_error_code create_identifiers_from_stack(STACK_OF(X509) *sk, krb5_external_principal_identifier *** ids);

krb5_error_code
pkinit_init_plg_crypto(pkinit_plg_crypto_context *cryptoctx) {

    krb5_error_code retval = ENOMEM;
    struct _pkinit_plg_crypto_context *ctx = NULL;

    /* initialize openssl routines */
    openssl_init();

    ctx = (struct _pkinit_plg_crypto_context *)malloc(sizeof(*ctx));
    if (ctx == NULL)
	goto out;
    memset(ctx, 0, sizeof(*ctx));

    retval = pkinit_init_pkinit_oids(ctx);
    if (retval)
	goto out;

    retval = pkinit_init_dh_params(ctx);
    if (retval)
	goto out;

    *cryptoctx = ctx;

out:
    if (retval) {
	free(ctx);
	OBJ_cleanup();
    }

    return retval;
}

void
pkinit_fini_plg_crypto(pkinit_plg_crypto_context cryptoctx)
{
    struct _pkinit_plg_crypto_context *ctx = cryptoctx;

    if (ctx == NULL)
	return;
    pkinit_fini_pkinit_oids(ctx);
    pkinit_fini_dh_params(ctx);
    free(ctx);
}

krb5_error_code
pkinit_init_identity_crypto(pkinit_identity_crypto_context *idctx)
{
    krb5_error_code retval = ENOMEM;
    struct _pkinit_identity_crypto_context *ctx = NULL;

    ctx = (struct _pkinit_identity_crypto_context *)malloc(sizeof(*ctx));
    if (ctx == NULL)
	goto out;
    memset(ctx, 0, sizeof(*ctx));

    retval = pkinit_init_certs(ctx);
    if (retval)
	goto out;

    retval = pkinit_init_pkcs11(ctx);
    if (retval)
	goto out;

    pkiDebug("pkinit_init_identity_crypto: returning ctx at %p\n", ctx);
    *idctx = ctx;

out:
    if (retval) {
	free(ctx);
	OBJ_cleanup();
    }

    return retval;
}

void
pkinit_fini_identity_crypto(pkinit_identity_crypto_context idctx)
{
    struct _pkinit_identity_crypto_context *ctx = idctx;

    if (ctx == NULL)
	return;

    pkiDebug("pkinit_fini_identity_crypto: freeing   ctx at %p\n", ctx);
    pkinit_fini_certs(ctx);
    pkinit_fini_pkcs11(ctx);
    free(ctx);
}

krb5_error_code
pkinit_init_req_crypto(pkinit_req_crypto_context *cryptoctx)
{

    krb5_error_code retval = ENOMEM;
    struct _pkinit_req_crypto_context *ctx = NULL;

    ctx = (struct _pkinit_req_crypto_context *)malloc(sizeof(*ctx));
    if (ctx == NULL)
	goto out;
    memset(ctx, 0, sizeof(*ctx));

    ctx->dh = NULL;
    ctx->received_cert = NULL;

    *cryptoctx = ctx;

    pkiDebug("pkinit_init_req_crypto: returning ctx at %p\n", ctx);
    retval = 0;
out:
    if (retval)
	free(ctx);

    return retval;
}

void
pkinit_fini_req_crypto(pkinit_req_crypto_context cryptoctx)
{
    struct _pkinit_req_crypto_context *ctx = cryptoctx;

    if (ctx == NULL)
	return;

    pkiDebug("pkinit_fini_req_crypto: freeing   ctx at %p\n", ctx);
    if (ctx->dh != NULL)
      DH_free(ctx->dh);
    if (ctx->received_cert != NULL)
      X509_free(ctx->received_cert);

    free(ctx);
}

static krb5_error_code
pkinit_init_pkinit_oids(pkinit_plg_crypto_context ctx)
{
    krb5_error_code retval = ENOMEM;
    int tmp = 0;

    tmp = OBJ_create("1.3.6.1.5.2.2", "id-pkinit-san", "KRB5PrincipalName");
    if (tmp == NID_undef)
	goto out;
    ctx->id_pkinit_san = (ASN1_OBJECT *)OBJ_nid2obj(tmp);

    tmp = OBJ_create("1.3.6.1.5.2.3.1", "id-pkinit-authdata",
		     "PKINIT signedAuthPack");
    if (tmp == NID_undef)
	goto out;
    ctx->id_pkinit_authData = (ASN1_OBJECT *)OBJ_nid2obj(tmp);

    tmp = OBJ_create("1.3.6.1.5.2.3.2", "id-pkinit-DHKeyData",
		     "PKINIT dhSignedData");
    if (tmp == NID_undef)
	goto out;
    ctx->id_pkinit_DHKeyData = (ASN1_OBJECT *)OBJ_nid2obj(tmp);

    tmp = OBJ_create("1.3.6.1.5.2.3.3", "id-pkinit-rkeyData",
		     "PKINIT encKeyPack");
    if (tmp == NID_undef)
	goto out;
    ctx->id_pkinit_rkeyData = (ASN1_OBJECT *)OBJ_nid2obj(tmp);

    tmp = OBJ_create("1.3.6.1.5.2.3.4", "id-pkinit-KPClientAuth",
		     "PKINIT Client EKU");
    if (tmp == NID_undef)
	goto out;
    ctx->id_pkinit_KPClientAuth = (ASN1_OBJECT *)OBJ_nid2obj(tmp);

    tmp = OBJ_create("1.3.6.1.5.2.3.5", "id-pkinit-KPKdc", "KDC EKU");
    if (tmp == NID_undef)
	goto out;
    ctx->id_pkinit_KPKdc = (ASN1_OBJECT *)OBJ_nid2obj(tmp);
    tmp = OBJ_create("1.2.840.113549.1.7.1", "id-data",
		     "CMS id-data");
    if (tmp == NID_undef)
	goto out;
    ctx->id_pkinit_authData9 = (ASN1_OBJECT *)OBJ_nid2obj(tmp);
    tmp = OBJ_create("1.3.6.1.4.1.311.20.2.3", "id-pkinit-san draft9",
		     "KRB5PrincipalName draft9");
    if (tmp == NID_undef)
	goto out;
    ctx->id_pkinit_san9 = (ASN1_OBJECT *)OBJ_nid2obj(tmp);
    tmp = OBJ_create("1.3.6.1.4.1.311.20.2.2", "id-ms-kp-sc-logon EKU",
		     "KDC/Client EKU draft9");
    if (tmp == NID_undef)
	goto out;
    ctx->id_ms_kp_sc_logon = (ASN1_OBJECT *)OBJ_nid2obj(tmp);
    tmp = OBJ_create("1.3.6.1.5.5.7.3.1", "id-kp-serverAuth EKU",
		     "KDC EKU draft9");
    if (tmp == NID_undef)
	goto out;
    ctx->id_kp_serverAuth = (ASN1_OBJECT *)OBJ_nid2obj(tmp);

    retval = 0;

out:
    return retval;
}

static void
pkinit_fini_pkinit_oids(pkinit_plg_crypto_context ctx)
{
    OBJ_cleanup();
}

static krb5_error_code
pkinit_init_dh_params(pkinit_plg_crypto_context plgctx)
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
    if (retval)
	pkinit_fini_dh_params(plgctx);

    return retval;
}

static void
pkinit_fini_dh_params(pkinit_plg_crypto_context plgctx)
{
    if (plgctx->dh_1024 != NULL)
	DH_free(plgctx->dh_1024);
    if (plgctx->dh_2048 != NULL)
	DH_free(plgctx->dh_2048);
    if (plgctx->dh_4096 != NULL)
	DH_free(plgctx->dh_4096);

    plgctx->dh_1024 = plgctx->dh_2048 = plgctx->dh_4096 = NULL;
}

static krb5_error_code
pkinit_init_certs(pkinit_identity_crypto_context ctx)
{
    krb5_error_code retval = ENOMEM;

    ctx->my_certs = NULL;
    ctx->cert_index = 0;
    ctx->my_key = NULL;
    ctx->trustedCAs = NULL;
    ctx->intermediateCAs = NULL;
    ctx->revoked = NULL;

    retval = 0;
    return retval;
}

static void
pkinit_fini_certs(pkinit_identity_crypto_context ctx)
{
    if (ctx->my_certs != NULL)
	sk_X509_pop_free(ctx->my_certs, X509_free);

    if (ctx->my_key != NULL)
	EVP_PKEY_free(ctx->my_key);

    if (ctx->trustedCAs != NULL)
	sk_X509_pop_free(ctx->trustedCAs, X509_free);

    if (ctx->intermediateCAs != NULL)
	sk_X509_pop_free(ctx->intermediateCAs, X509_free);

    if (ctx->revoked != NULL)
	sk_X509_CRL_pop_free(ctx->revoked, X509_CRL_free);
}

static krb5_error_code
pkinit_init_pkcs11(pkinit_identity_crypto_context ctx)
{
    krb5_error_code retval = ENOMEM;

#ifndef WITHOUT_PKCS11
    ctx->p11_module_name = strdup(PKCS11_MODNAME);
    ctx->p11_module = NULL;
    ctx->slotid = PK_NOSLOT;
    ctx->token_label = NULL;
    ctx->cert_label = NULL;
    ctx->session = CK_INVALID_HANDLE;
    ctx->p11 = NULL;
    ctx->pkcs11_method = (getenv("PKCS11") != NULL);
#else
    ctx->pkcs11_method = 0;
#endif

    retval = 0;
    return retval;
}

static void
pkinit_fini_pkcs11(pkinit_identity_crypto_context ctx)
{
#ifndef WITHOUT_PKCS11
    if (ctx->p11 != NULL) {
	if (ctx->session) {
	    ctx->p11->C_CloseSession(ctx->session);
	    ctx->session = CK_INVALID_HANDLE;
	}
	ctx->p11->C_Finalize(NULL_PTR);
	ctx->p11 = NULL;
    }
    if (ctx->p11_module != NULL) {
	pkinit_C_UnloadModule(ctx->p11_module);
	ctx->p11_module = NULL;
    }
    if (ctx->p11_module_name != NULL)
	free(ctx->p11_module_name);
    if (ctx->token_label != NULL)
	free(ctx->token_label);
    if (ctx->cert_id != NULL)
	free(ctx->cert_id);
    if (ctx->cert_label != NULL)
	free(ctx->cert_label);
#endif
}

krb5_error_code
pkinit_identity_set_prompter(pkinit_identity_crypto_context id_cryptoctx,
			     krb5_prompter_fct prompter,
			     void *prompter_data)
{
    id_cryptoctx->prompter = prompter;
    id_cryptoctx->prompter_data = prompter_data;

    return 0;
}

krb5_error_code
cms_signeddata_create(krb5_context context,
		      pkinit_plg_crypto_context plg_cryptoctx,
		      pkinit_req_crypto_context req_cryptoctx,
		      pkinit_identity_crypto_context id_cryptoctx,
		      int cms_msg_type,
		      int include_certchain,
		      unsigned char *data,
		      int data_len,
		      unsigned char **signed_data,
		      int *signed_data_len)
{
    krb5_error_code retval = ENOMEM;
    PKCS7  *p7 = NULL, *inner_p7 = NULL;
    PKCS7_SIGNED *p7s = NULL;
    PKCS7_SIGNER_INFO *p7si = NULL;
    unsigned char *p;
    ASN1_TYPE *pkinit_data = NULL;
    STACK_OF(X509) * cert_stack = NULL;
    ASN1_OCTET_STRING *digest_attr = NULL;
    EVP_MD_CTX ctx, ctx2;
    const EVP_MD *md_tmp;
    unsigned char md_data[EVP_MAX_MD_SIZE], md_data2[EVP_MAX_MD_SIZE];
    unsigned char *digestInfo_buf = NULL, *abuf = NULL;
    unsigned int md_len, md_len2, alen, digestInfo_len;
    STACK_OF(X509_ATTRIBUTE) * sk;
    unsigned char *sig = NULL;
    int sig_len = 0;
    X509_ALGOR *alg = NULL;
    ASN1_OCTET_STRING *digest = NULL;
    int alg_len = 0, digest_len = 0;
    unsigned char *y = NULL, *alg_buf = NULL, *digest_buf = NULL;
    X509 *cert = NULL;
    ASN1_OBJECT *oid = NULL;

    /* start creating PKCS7 data */
    if ((p7 = PKCS7_new()) == NULL)
	goto cleanup;
    p7->type = OBJ_nid2obj(NID_pkcs7_signed);

    if ((p7s = PKCS7_SIGNED_new()) == NULL)
	goto cleanup;
    p7->d.sign = p7s;
    if (!ASN1_INTEGER_set(p7s->version, 1))
	goto cleanup;

    /* create a cert chain that has at least the signer's certificate */
    if ((cert_stack = sk_X509_new_null()) == NULL)
	goto cleanup;

    cert = sk_X509_value(id_cryptoctx->my_certs, id_cryptoctx->cert_index);
    if (!include_certchain) {
	pkiDebug("only including signer's certificate\n");
	sk_X509_push(cert_stack, X509_dup(cert));
    } else {
	/* create a cert chain */
	X509_STORE *certstore = NULL;
	X509_STORE_CTX certctx;
	STACK_OF(X509) *certstack = NULL;
	char buf[256];
	int i = 0, size = 0;

	if ((certstore = X509_STORE_new()) == NULL)
	    goto cleanup;
	pkiDebug("building certificate chain\n");
	X509_STORE_set_verify_cb_func(certstore, openssl_callback);
	X509_STORE_CTX_init(&certctx, certstore, cert,
			    id_cryptoctx->intermediateCAs);
	X509_STORE_CTX_trusted_stack(&certctx, id_cryptoctx->trustedCAs);
	if (!X509_verify_cert(&certctx)) {
	    pkiDebug("failed to create a certificate chain: %s\n", 
	    X509_verify_cert_error_string(X509_STORE_CTX_get_error(&certctx)));
	    if (!sk_X509_num(id_cryptoctx->trustedCAs)) 
		pkiDebug("No trusted CAs found. Check your X509_anchors\n");
	    goto cleanup;
	}
	certstack = X509_STORE_CTX_get1_chain(&certctx);
	size = sk_X509_num(certstack);
	pkiDebug("size of certificate chain = %d\n", size);
	for(i = 0; i < size - 1; i++) {
	    X509 *x = sk_X509_value(certstack, i);
	    X509_NAME_oneline(X509_get_subject_name(x), buf, 256);
	    pkiDebug("cert #%d: %s\n", i, buf);
	    sk_X509_push(cert_stack, X509_dup(x));
	}
	X509_STORE_CTX_cleanup(&certctx);
	X509_STORE_free(certstore);
	sk_X509_pop_free(certstack, X509_free);
    }
    p7s->cert = cert_stack;

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
    p7si->digest_enc_alg->algorithm = OBJ_nid2obj(NID_sha1WithRSAEncryption);
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

    /* pick the correct oid for the eContentInfo */
    oid = pkinit_pkcs7type2oid(plg_cryptoctx, cms_msg_type);
    if (oid == NULL)
	goto cleanup;

    /* create a content-type attr */
    PKCS7_add_signed_attribute(p7si, NID_pkcs9_contentType, V_ASN1_OBJECT, oid);

    /* create the signature over signed attributes. get DER encoded value */
    /* This is the place where smartcard signature needs to be calculated */
    sk = p7si->auth_attr;
    alen = ASN1_item_i2d((ASN1_VALUE *) sk, &abuf,
			 ASN1_ITEM_rptr(PKCS7_ATTR_SIGN));
    if (abuf == NULL)
	goto cleanup2;

#ifndef WITHOUT_PKCS11
    /* Some tokens can only do RSAEncryption without sha1 hash */
    /* to compute sha1WithRSAEncryption, encode the algorithm ID for the hash
     * function and the hash value into an ASN.1 value of type DigestInfo
     * DigestInfo::=SEQUENCE {
     *	digestAlgorithm  AlgorithmIdentifier,
     *	digest OCTET STRING }
     */
    if (id_cryptoctx->pkcs11_method && id_cryptoctx->mech == CKM_RSA_PKCS) {
	pkiDebug("mech = CKM_RSA_PKCS\n");
	EVP_MD_CTX_init(&ctx2);
	EVP_DigestInit_ex(&ctx2, md_tmp, NULL);
	EVP_DigestUpdate(&ctx2, abuf, alen);
	EVP_DigestFinal_ex(&ctx2, md_data2, &md_len2);

	alg = X509_ALGOR_new();
	if (alg == NULL)
	    goto cleanup2;
	alg->algorithm = OBJ_nid2obj(NID_sha1);
	alg->parameter = NULL;
	alg_len = i2d_X509_ALGOR(alg, NULL);
	alg_buf = (unsigned char *)malloc(alg_len);
	if (alg_buf == NULL)
	    goto cleanup2;

	digest = ASN1_OCTET_STRING_new();
	if (digest == NULL)
	    goto cleanup2;
	ASN1_OCTET_STRING_set(digest, md_data2, md_len2);
	digest_len = i2d_ASN1_OCTET_STRING(digest, NULL);
	digest_buf = (unsigned char *)malloc(digest_len);
	if (digest_buf == NULL)
	    goto cleanup2;

	digestInfo_len = ASN1_object_size(1, alg_len + digest_len,
					  V_ASN1_SEQUENCE);
	y = digestInfo_buf = (unsigned char *)malloc(digestInfo_len);
	if (digestInfo_buf == NULL)
	    goto cleanup2;
	ASN1_put_object(&y, 1, alg_len + digest_len, V_ASN1_SEQUENCE,
			V_ASN1_UNIVERSAL);
	i2d_X509_ALGOR(alg, &y);
	i2d_ASN1_OCTET_STRING(digest, &y);
#ifdef DEBUG_SIG
	pkiDebug("signing buffer\n");
	print_buffer(digestInfo_buf, digestInfo_len);
	print_buffer_bin(digestInfo_buf, digestInfo_len, "/tmp/pkcs7_tosign");
#endif
	retval = pkinit_sign_data(context, id_cryptoctx, digestInfo_buf,
				  digestInfo_len, &sig, &sig_len);
    } else
#endif
    {
	pkiDebug("mech = %s\n",
	    id_cryptoctx->pkcs11_method ? "CKM_SHA1_RSA_PKCS" : "FS");
	retval = pkinit_sign_data(context, id_cryptoctx, abuf, alen,
				  &sig, &sig_len);
    }
#ifdef DEBUG_SIG
    print_buffer(sig, sig_len);
#endif
    free(abuf);
    if (retval)
	goto cleanup2;

    /* Add signature */
    if (!ASN1_STRING_set(p7si->enc_digest, (unsigned char *) sig, sig_len)) {
	unsigned long err = ERR_peek_error();
	retval = KRB5KDC_ERR_PREAUTH_FAILED;
	krb5_set_error_message(context, retval, "%s\n",
			       ERR_error_string(err, NULL));
	pkiDebug("failed to add a signed digest attribute\n");
	goto cleanup2;
    }
    /* adder signer_info to pkcs7 signed */
    if (!PKCS7_add_signer(p7, p7si))
	goto cleanup2;

    /* start on adding data to the pkcs7 signed */
    if ((inner_p7 = PKCS7_new()) == NULL)
	goto cleanup2;
    if ((pkinit_data = ASN1_TYPE_new()) == NULL)
	goto cleanup2;
    pkinit_data->type = V_ASN1_OCTET_STRING;
    if ((pkinit_data->value.octet_string = ASN1_OCTET_STRING_new()) == NULL)
	goto cleanup2;
    if (!ASN1_OCTET_STRING_set(pkinit_data->value.octet_string, data,
			       data_len)) {
	unsigned long err = ERR_peek_error();
	retval = KRB5KDC_ERR_PREAUTH_FAILED;
	krb5_set_error_message(context, retval, "%s\n",
			       ERR_error_string(err, NULL));
	pkiDebug("failed to add pkcs7 data\n");
	goto cleanup2;
    }

    if (!PKCS7_set0_type_other(inner_p7, OBJ_obj2nid(oid), pkinit_data))
	goto cleanup2;
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
	goto cleanup2;
    }
    if ((p = *signed_data =
	 (unsigned char *) malloc((size_t)*signed_data_len)) == NULL)
	goto cleanup2;

    /* DER encode PKCS7 data */
    retval = i2d_PKCS7(p7, &p);
    if (!retval) {
	unsigned long err = ERR_peek_error();
	retval = KRB5KDC_ERR_PREAUTH_FAILED;
	krb5_set_error_message(context, retval, "%s\n",
			       ERR_error_string(err, NULL));
	pkiDebug("failed to der encode pkcs7\n");
	goto cleanup2;
    }
    retval = 0;

#ifdef DEBUG_ASN1
    //print_buffer_bin(*signed_data, *signed_data_len, "/tmp/pkcs7_signeddata");
#endif

  cleanup2:
    EVP_MD_CTX_cleanup(&ctx);
#ifndef WITHOUT_PKCS11
    if (id_cryptoctx->pkcs11_method && id_cryptoctx->mech == CKM_RSA_PKCS)
	EVP_MD_CTX_cleanup(&ctx2);
#endif
    if (alg != NULL)
	X509_ALGOR_free(alg);
    if (digest != NULL)
	ASN1_OCTET_STRING_free(digest);
    if (alg_buf != NULL)
	free(alg_buf);
    if (digest_buf != NULL)
	free(digest_buf);
    if (digestInfo_buf != NULL)
	free(digestInfo_buf);
  cleanup:
    if (p7 != NULL)
	PKCS7_free(p7);
    if (sig != NULL)
	free(sig);

    return retval;
}

krb5_error_code
cms_signeddata_verify(krb5_context context,
		      pkinit_plg_crypto_context plgctx,
		      pkinit_req_crypto_context reqctx,
		      pkinit_identity_crypto_context idctx,
		      int cms_msg_type,
		      int require_crl_checking,
		      unsigned char *signed_data,
		      int signed_data_len,
		      unsigned char **data,
		      int *data_len,
		      unsigned char **authz_data,
		      int *authz_data_len)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    PKCS7 *p7 = NULL;
    BIO *out = NULL;
    int flags = PKCS7_NOVERIFY, i = 0, size = 0, vflags = 0;
    const unsigned char *p = signed_data;
    STACK_OF(PKCS7_SIGNER_INFO) *si_sk = NULL;
    PKCS7_SIGNER_INFO *si = NULL;
    X509 *x = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX cert_ctx;
    STACK_OF(X509) *intermediateCAs = NULL;
    STACK_OF(X509_CRL) *revoked = NULL;
    STACK_OF(X509) *verified_chain = NULL;
    krb5_external_principal_identifier **krb5_verified_chain = NULL;
    krb5_data *authz = NULL;
    char buf[256];

#ifdef DEBUG_ASN1
    print_buffer_bin(p, signed_data_len, "/tmp/pkcs7_signeddata");
#endif

    /* decode received PKCS7 messag */
    if ((p7 = d2i_PKCS7(NULL, &p, signed_data_len)) == NULL) {
	unsigned long err = ERR_peek_error();
	krb5_set_error_message(context, retval, "%s\n",
			       ERR_error_string(err, NULL));
	goto cleanup;
    }

    /* verify that the received message is PKCS7 SignedData message */
    if (OBJ_obj2nid(p7->type) != NID_pkcs7_signed) {
	pkiDebug("Excepted id-signedData PKCS7 mgs (received type = %d)\n",
		 OBJ_obj2nid(p7->type));
	krb5_set_error_message(context, retval, "wrong oid\n");
	goto cleanup;
    }

    /* setup to verify X509 certificate used to sign PKCS7 message */
    if (!(store = X509_STORE_new()))
	goto cleanup;

    /* check if we are inforcing CRL checking */
    vflags = X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL;
    if (require_crl_checking)
	X509_STORE_set_verify_cb_func(store, openssl_callback);
    else
	X509_STORE_set_verify_cb_func(store, openssl_callback_ignore_crls);
    X509_STORE_set_flags(store, vflags);

    /* get the signer's information from the PKCS7 message */
    if ((si_sk = PKCS7_get_signer_info(p7)) == NULL)
	goto cleanup;
    if ((si = sk_PKCS7_SIGNER_INFO_value(si_sk, 0)) == NULL)
	goto cleanup;
    if ((x = PKCS7_cert_from_signer_info(p7, si)) == NULL)
	goto cleanup;

    /* create available CRL information (get local CRLs and include CRLs
     * received in the PKCS7 message
     */
    if (idctx->revoked == NULL)
	revoked = p7->d.sign->crl;
    else if (p7->d.sign->crl == NULL)
	revoked = idctx->revoked;
    else {
	size = sk_X509_CRL_num(idctx->revoked);
	revoked = sk_X509_CRL_new_null();
	for (i = 0; i < size; i++)
	    sk_X509_CRL_push(revoked, sk_X509_CRL_value(idctx->revoked, i));
	size = sk_X509_num(p7->d.sign->crl);
	for (i = 0; i < size; i++)
	    sk_X509_CRL_push(revoked, sk_X509_CRL_value(p7->d.sign->crl, i));
    }

    /* create available intermediate CAs chains (get local intermediateCAs and
     * include the CA chain received in the PKCS7 message
     */
    if (idctx->intermediateCAs == NULL)
	intermediateCAs = p7->d.sign->cert;
    else if (p7->d.sign->cert == NULL)
	intermediateCAs = idctx->intermediateCAs;
    else {
	size = sk_X509_num(idctx->intermediateCAs);
	intermediateCAs = sk_X509_new_null();
	for (i = 0; i < size; i++) {
	    sk_X509_push(intermediateCAs,
		sk_X509_value(idctx->intermediateCAs, i));
	}
	size = sk_X509_num(p7->d.sign->cert);
	for (i = 0; i < size; i++) {
	    sk_X509_push(intermediateCAs, sk_X509_value(p7->d.sign->cert, i));
	}
    }

    /* initialize x509 context with the received certificate and
     * trusted and intermediate CA chains and CRLs
     */
    if (!X509_STORE_CTX_init(&cert_ctx, store, x, intermediateCAs))
	goto cleanup;

    X509_STORE_CTX_set0_crls(&cert_ctx, revoked);

    /* add trusted CAs certificates for cert verification */
    if (idctx->trustedCAs != NULL)
	X509_STORE_CTX_trusted_stack(&cert_ctx, idctx->trustedCAs);
    else {
	pkiDebug("unable to find any trusted CAs\n");
	goto cleanup;
    }
#ifdef DEBUG_CERTCHAIN
    if (intermediateCAs != NULL) {
	size = sk_X509_num(intermediateCAs);
	pkiDebug("untrusted cert chain of size %d\n", size);
	for (i = 0; i < size; i++) {
	    X509_NAME_oneline(X509_get_subject_name(
		sk_X509_value(intermediateCAs, i)), buf, 256);
	    pkiDebug("cert #%d: %s\n", i, buf);
	}
    }
    if (idctx->trustedCAs != NULL) {
	size = sk_X509_num(idctx->trustedCAs);
	pkiDebug("trusted cert chain of size %d\n", size);
	for (i = 0; i < size; i++) {
	    X509_NAME_oneline(X509_get_subject_name(
		sk_X509_value(idctx->trustedCAs, i)), buf, 256);
	    pkiDebug("cert #%d: %s\n", i, buf);
	}
    }
    if (revoked != NULL) {
	size = sk_X509_CRL_num(revoked);
	pkiDebug("CRL chain of size %d\n", size);
	for (i = 0; i < size; i++) {
	    X509_CRL *crl = sk_X509_CRL_value(revoked, i);
	    X509_NAME_oneline(X509_CRL_get_issuer(crl), buf, 256);
	    pkiDebug("crls by CA #%d: %s\n", i , buf);
	}
    }
#endif

    i = X509_verify_cert(&cert_ctx);
    if (i <= 0) {
	int j = X509_STORE_CTX_get_error(&cert_ctx);

	reqctx->received_cert = X509_dup(cert_ctx.current_cert);
	switch(j) {
	    case X509_V_ERR_CERT_REVOKED:
		retval = KRB5KDC_ERR_REVOKED_CERTIFICATE;
		break;
	    case X509_V_ERR_UNABLE_TO_GET_CRL:
		retval = KRB5KDC_ERR_REVOCATION_STATUS_UNKNOWN;
		break;
	    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
	    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
		retval = KRB5KDC_ERR_CANT_VERIFY_CERTIFICATE;
		break;
	    default:
		retval = KRB5KDC_ERR_INVALID_CERTIFICATE;
	}
	X509_NAME_oneline(X509_get_subject_name(
	    reqctx->received_cert), buf, 256);
	pkiDebug("problem with cert DN = %s (error=%d) %s\n", buf, j,
		 X509_verify_cert_error_string(j));
	krb5_set_error_message(context, retval, "%s\n",
	    X509_verify_cert_error_string(j));
#ifdef DEBUG_CERTCHAIN
	size = sk_X509_num(p7->d.sign->cert);
	pkiDebug("received cert chain of size %d\n", size);
	for (j = 0; j < size; j++) {
	    X509 *tmp_cert = sk_X509_value(p7->d.sign->cert, j);
	    X509_NAME_oneline(X509_get_subject_name(tmp_cert), buf, 256);
	    pkiDebug("cert #%d: %s\n", j, buf);
	}
#endif
    } else {
	/* retrieve verified certificate chain */
	if (cms_msg_type == CMS_SIGN_CLIENT || cms_msg_type == CMS_SIGN_DRAFT9) 
	    verified_chain = X509_STORE_CTX_get1_chain(&cert_ctx);
    }
    X509_STORE_CTX_cleanup(&cert_ctx);
    if (i <= 0)
	goto cleanup;

    out = BIO_new(BIO_s_mem());
    if (PKCS7_verify(p7, NULL, store, NULL, out, flags)) {
	ASN1_OBJECT *oid = NULL;
	oid = pkinit_pkcs7type2oid(plgctx, cms_msg_type);
	if (oid == NULL)
	    goto cleanup;
	if (!OBJ_cmp(p7->d.sign->contents->type, oid))
	    pkiDebug("PKCS7 Verification successful\n");
	else {
	    pkiDebug("wrong oid in eContentType\n");
	    print_buffer(p7->d.sign->contents->type->data, 
		p7->d.sign->contents->type->length);
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

    /* transfer the data from PKCS7 message into return buffer */
    for (size = 0;;) {
	if ((*data = realloc(*data, size + 1024 * 10)) == NULL)
	    goto cleanup;
	i = BIO_read(out, &((*data)[size]), 1024 * 10);
	if (i <= 0)
	    break;
	else
	    size += i;
    }
    *data_len = size;

    reqctx->received_cert = X509_dup(x);

    /* generate authorization data */
    if (cms_msg_type == CMS_SIGN_CLIENT || cms_msg_type == CMS_SIGN_DRAFT9) {

	if (authz_data == NULL || authz_data_len == NULL) 
	    goto out;

	*authz_data = NULL;
	retval = create_identifiers_from_stack(verified_chain, 
					       &krb5_verified_chain);
	if (retval) {
	    pkiDebug("create_identifiers_from_stack failed\n");
	    goto cleanup;
	}

	retval = k5int_encode_krb5_td_trusted_certifiers(krb5_verified_chain, 
	    &authz);
	if (retval) {
	    pkiDebug("encode_krb5_td_trusted_certifiers failed\n");
	    goto cleanup;
	}
#ifdef DEBUG_ASN1
	print_buffer_bin(authz->data, authz->length, "/tmp/kdc_authz");
#endif
	*authz_data = (unsigned char *)malloc(authz->length);
	if (*authz_data == NULL) {
	    retval = ENOMEM;
	    goto cleanup;
	}
	memcpy(*authz_data, authz->data, authz->length);
	*authz_data_len = authz->length;
    }
  out:
    retval = 0;

  cleanup:
    if (out != NULL)
	BIO_free(out);
    if (store != NULL)
	X509_STORE_free(store);
    if (idctx->intermediateCAs != NULL && p7->d.sign->cert)
	sk_X509_free(intermediateCAs);
    if (idctx->revoked != NULL && p7->d.sign->crl)
	sk_X509_CRL_free(revoked);
    if (p7 != NULL)
	PKCS7_free(p7);
    if (verified_chain != NULL)
	sk_X509_pop_free(verified_chain, X509_free);
    if (krb5_verified_chain != NULL)
	free_krb5_external_principal_identifier(&krb5_verified_chain);
    if (authz != NULL)
	krb5_free_data(context, authz);

    return retval;
}

krb5_error_code
cms_envelopeddata_create(krb5_context context,
			 pkinit_plg_crypto_context plgctx,
			 pkinit_req_crypto_context reqctx,
			 pkinit_identity_crypto_context idctx,
			 krb5_preauthtype pa_type,
			 int include_certchain,
			 unsigned char *key_pack,
			 int key_pack_len,
			 unsigned char **out,
			 int *out_len)
{

    krb5_error_code retval = ENOMEM;
    PKCS7 *p7 = NULL;
    BIO *in = NULL;
    unsigned char *p = NULL, *signed_data = NULL, *enc_data = NULL;
    int signed_data_len = 0, enc_data_len = 0, flags = PKCS7_BINARY;
    STACK_OF(X509) *encerts = NULL;
    const EVP_CIPHER *cipher = NULL;
    int cms_msg_type = CMS_ENVEL_SERVER;

    /* create the PKCS7 SignedData portion of the PKCS7 EnvelopedData */
    switch ((int)pa_type) {
	case KRB5_PADATA_PK_AS_REQ_OLD:
	case KRB5_PADATA_PK_AS_REP_OLD:
	    cms_msg_type = CMS_SIGN_DRAFT9;
	    break;
	default:
	    goto cleanup;
    }

    retval = cms_signeddata_create(context, plgctx, reqctx, idctx,
	cms_msg_type, include_certchain, key_pack, key_pack_len,
	&signed_data, &signed_data_len);
    if (retval) {
	pkiDebug("failed to create pkcs7 signed data\n");
	goto cleanup;
    }

    /* check we have client's certificate */
    if (reqctx->received_cert == NULL) {
	retval = KRB5KDC_ERR_PREAUTH_FAILED;
	goto cleanup;
    }
    encerts = sk_X509_new_null();
    sk_X509_push(encerts, reqctx->received_cert);

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
    if (!*out_len || (p = *out = (unsigned char *)malloc(*out_len)) == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    retval = i2d_PKCS7(p7, &p);
    if (!retval) {
	pkiDebug("unable to write pkcs7 object\n");
	goto cleanup;
    }
    retval = 0;

#ifdef DEBUG_ASN1
    print_buffer_bin(*out, *out_len, "/tmp/kdc_enveloped_data");
#endif

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

krb5_error_code
cms_envelopeddata_verify(krb5_context context,
			 pkinit_plg_crypto_context plg_cryptoctx,
			 pkinit_req_crypto_context req_cryptoctx,
			 pkinit_identity_crypto_context id_cryptoctx,
			 krb5_preauthtype pa_type,
			 int require_crl_checking,
			 unsigned char *enveloped_data,
			 int enveloped_data_len,
			 unsigned char **data,
			 int *data_len)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    PKCS7 *p7 = NULL;
    BIO *out = NULL;
    int i = 0, size = 0;
    const unsigned char *p = enveloped_data;
    int tmp_buf_len = 0, tmp_buf2_len = 0;
    unsigned char *tmp_buf = NULL, *tmp_buf2 = NULL;

    /* decode received PKCS7 message */
    if ((p7 = d2i_PKCS7(NULL, &p, enveloped_data_len)) == NULL) {
	unsigned long err = ERR_peek_error();
	pkiDebug("failed to decode pkcs7\n");
	krb5_set_error_message(context, retval, "%s\n",
			       ERR_error_string(err, NULL));
	goto cleanup;
    }

    /* verify that the received message is PKCS7 EnvelopedData message */
    if (OBJ_obj2nid(p7->type) != NID_pkcs7_enveloped) {
	pkiDebug("Excepted id-enveloped PKCS7 msg (received type = %d)\n",
		 OBJ_obj2nid(p7->type));
	krb5_set_error_message(context, retval, "wrong oid\n");
	goto cleanup;
    }

    /* decrypt received PKCS7 message */
    out = BIO_new(BIO_s_mem());
    if (pkcs7_decrypt(context, id_cryptoctx, p7, out)) {
	pkiDebug("PKCS7 decryption successful\n");
    } else {
	unsigned long err = ERR_peek_error();
	if (err != 0)
	    krb5_set_error_message(context, retval, "%s\n",
				   ERR_error_string(err, NULL));
	pkiDebug("PKCS7 decryption failed\n");
	goto cleanup;
    }

    /* transfer the decoded PKCS7 SignedData message into a separate buffer */
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
    /* verify PKCS7 SignedData message */
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
	    retval = cms_signeddata_verify(context, plg_cryptoctx,
		req_cryptoctx, id_cryptoctx, CMS_ENVEL_SERVER,
		require_crl_checking, tmp_buf2, tmp_buf2_len, data, 
		data_len, NULL, NULL);
	    break;
	case KRB5_PADATA_PK_AS_REP_OLD:
	    retval = cms_signeddata_verify(context, plg_cryptoctx,
		req_cryptoctx, id_cryptoctx, CMS_SIGN_DRAFT9,
		require_crl_checking, tmp_buf, tmp_buf_len, data, 
		data_len, NULL, NULL);
	    break;
	default:
	    pkiDebug("unrecognized pa_type = %d\n", pa_type);
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

krb5_error_code
verify_id_pkinit_san(krb5_context context,
		     pkinit_plg_crypto_context plgctx,
		     pkinit_req_crypto_context reqctx,
		     pkinit_identity_crypto_context idctx,
		     krb5_preauthtype pa_type,
		     int allow_upn,
		     krb5_principal *out,
		     unsigned char **kdc_hostname,
		     int *valid_san)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    int i = 0, ok = 0;
    char buf[256];

    *valid_san = 0;
    if (reqctx->received_cert == NULL) return retval;

    /* now let's verify that KDC's certificate has id-pkinit-san */
    X509_NAME_oneline(X509_get_subject_name(reqctx->received_cert), buf, 256);
    pkiDebug("looking for SANs in cert = %s\n", buf);

    if ((i = X509_get_ext_by_NID(reqctx->received_cert,
	    NID_subject_alt_name, -1)) >= 0) {
	X509_EXTENSION *ext = NULL;
	GENERAL_NAMES *ialt = NULL;
	GENERAL_NAME *gen = NULL;
	int ret = 0;

	if (!(ext = X509_get_ext(reqctx->received_cert, i)) 
	    || !(ialt = X509V3_EXT_d2i(ext))) {
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
		if (!OBJ_cmp(plgctx->id_pkinit_san, gen->d.otherName->type_id)) {
#ifdef DEBUG_ASN1
		    print_buffer_bin(name.data, name.length, "/tmp/pkinit_san");
#endif
		    ret = k5int_decode_krb5_principal_name(&name, out);
		} else if (allow_upn && !OBJ_cmp(plgctx->id_pkinit_san9,
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
		if (pa_type == KRB5_PADATA_PK_AS_REP_OLD && 
			kdc_hostname != NULL) {
		    pkiDebug("Win2K KDC on host = %s\n", gen->d.dNSName->data);
		    *kdc_hostname = strdup(gen->d.dNSName->data); 
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
	sk_GENERAL_NAME_pop_free(ialt, GENERAL_NAME_free);
    }

    if (!ok) {
	pkiDebug("didn't find id_pkinit_san\n");
    }
    retval = 0;

  cleanup:
    *valid_san = ok;
    return retval;
}

krb5_error_code
verify_id_pkinit_eku(krb5_context context,
		     pkinit_plg_crypto_context plgctx,
		     pkinit_req_crypto_context reqctx,
		     pkinit_identity_crypto_context idctx,
		     krb5_preauthtype pa_type,
		     int require_eku,
		     int *valid_eku)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    int i = 0, ok = 0;
    char buf[256];
    ASN1_OBJECT * oid_client = NULL, *oid_server = NULL;
    ASN1_OBJECT *oid_logon = NULL, *oid_kp = NULL;

    *valid_eku = 0;
    if (reqctx->received_cert == NULL) return retval;

    /* now let's verify that KDC's certificate has pkinit EKU */
    X509_NAME_oneline(X509_get_subject_name(reqctx->received_cert), buf, 256);
    pkiDebug("looking for EKUs in cert = %s\n", buf);

    oid_client = plgctx->id_pkinit_KPClientAuth;
    oid_server = plgctx->id_pkinit_KPKdc;
    oid_logon = plgctx->id_ms_kp_sc_logon;
    oid_kp = plgctx->id_kp_serverAuth;

    if ((i = X509_get_ext_by_NID(reqctx->received_cert,
	    NID_ext_key_usage, -1)) >= 0) {
	EXTENDED_KEY_USAGE *extusage;

	if ((extusage = X509_get_ext_d2i(reqctx->received_cert,
		NID_ext_key_usage, NULL, NULL))) {
	    for (i = 0; i < sk_ASN1_OBJECT_num(extusage); i++) {
		ASN1_OBJECT *tmp_oid = NULL;
		int flag = 0;

		tmp_oid = sk_ASN1_OBJECT_value(extusage, i);
		switch ((int)pa_type) {
		    case KRB5_PADATA_PK_AS_REQ_OLD:
		    case KRB5_PADATA_PK_AS_REP_OLD:
		    case KRB5_PADATA_PK_AS_REQ:
			if (!OBJ_cmp(oid_client, tmp_oid) ||
			    !OBJ_cmp(oid_logon, tmp_oid))
			    flag = 1;
			break;
		    //case KRB5_PADATA_PK_AS_REP_OLD:
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
		    if ((usage = X509_get_ext_d2i(reqctx->received_cert,
			    NID_key_usage, NULL, NULL))) {

			if (!ku_reject(reqctx->received_cert,
				X509v3_KU_DIGITAL_SIGNATURE)) {
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
	EXTENDED_KEY_USAGE_free(extusage);
    }
    retval = 0;
cleanup:
    if (!ok) {
	pkiDebug("didn't find extended key usage (EKU) for pkinit\n");
	if (0 == require_eku) {
	    pkiDebug("configuration says ignore missing EKU\n");
	    ok = 1;
	}
    }
    *valid_eku = ok;
    return retval;
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
    key_block->contents = calloc(keylength, sizeof(unsigned char *));
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

krb5_error_code
client_create_dh(krb5_context context,
		 pkinit_plg_crypto_context plg_cryptoctx,
		 pkinit_req_crypto_context cryptoctx,
		 pkinit_identity_crypto_context id_cryptoctx,
		 int dh_size,
		 unsigned char **dh_params,
		 int *dh_params_len,
		 unsigned char **dh_pubkey,
		 int *dh_pubkey_len)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    unsigned char *buf = NULL;
    int dh_err = 0;
    ASN1_INTEGER *pub_key = NULL;

    if (cryptoctx->dh == NULL) {
	if ((cryptoctx->dh = DH_new()) == NULL)
	    goto cleanup;
	if ((cryptoctx->dh->g = BN_new()) == NULL ||
	    (cryptoctx->dh->q = BN_new()) == NULL)
	    goto cleanup;

	switch(dh_size) {
	    case 1024:
		pkiDebug("client uses 1024 DH keys\n");
		cryptoctx->dh->p = get_rfc2409_prime_1024(NULL);
		break;
	    case 2048:
		pkiDebug("client uses 2048 DH keys\n");
		cryptoctx->dh->p = BN_bin2bn(pkinit_2048_dhprime,
		    sizeof(pkinit_2048_dhprime), NULL);
		break;
	    case 4096:
		pkiDebug("client uses 4096 DH keys\n");
		cryptoctx->dh->p = BN_bin2bn(pkinit_4096_dhprime,
		    sizeof(pkinit_4096_dhprime), NULL);
		break;
	    default:
		goto cleanup;
	}

	BN_set_word((cryptoctx->dh->g), DH_GENERATOR_2);
	BN_rshift1(cryptoctx->dh->q, cryptoctx->dh->p);
    }

    DH_generate_key(cryptoctx->dh);
    DH_check(cryptoctx->dh, &dh_err);
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
    print_dh(cryptoctx->dh, "client's DH params\n");
    print_pubkey(cryptoctx->dh->pub_key, "client's pub_key=");
#endif

    DH_check_pub_key(cryptoctx->dh, cryptoctx->dh->pub_key, &dh_err);
    if (dh_err != 0) {
	pkiDebug("dh_check_pub_key failed with %d\n", dh_err);
	goto cleanup;
    }

    /* pack DHparams */
    /* aglo: usually we could just call i2d_DHparams to encode DH params
     * however, PKINIT requires RFC3279 encoding and openssl does pkcs#3.
     */
    retval = pkinit_encode_dh_params(cryptoctx->dh->p, cryptoctx->dh->g,
	cryptoctx->dh->q, dh_params, dh_params_len);
    if (retval)
	goto cleanup;

    /* pack DH public key */
    /* Diffie-Hellman public key must be ASN1 encoded as an INTEGER; this
     * encoding shall be used as the contents (the value) of the
     * subjectPublicKey component (a BIT STRING) of the SubjectPublicKeyInfo
     * data element
     */
    if ((pub_key = BN_to_ASN1_INTEGER(cryptoctx->dh->pub_key, NULL)) == NULL)
	goto cleanup;
    *dh_pubkey_len = i2d_ASN1_INTEGER(pub_key, NULL);
    if ((buf = *dh_pubkey = (unsigned char *)
	    malloc((size_t) *dh_pubkey_len)) == NULL) {
	retval  = ENOMEM;
	goto cleanup;
    }
    i2d_ASN1_INTEGER(pub_key, &buf);

    if (pub_key != NULL)
	ASN1_INTEGER_free(pub_key);

    retval = 0;
    return retval;

  cleanup:
    if (cryptoctx->dh != NULL)
	DH_free(cryptoctx->dh);
    cryptoctx->dh = NULL;
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

krb5_error_code
client_process_dh(krb5_context context,
		  pkinit_plg_crypto_context plg_cryptoctx,
		  pkinit_req_crypto_context cryptoctx,
		  pkinit_identity_crypto_context id_cryptoctx,
		  unsigned char *subjectPublicKey_data,
		  int subjectPublicKey_length,
		  unsigned char **client_key,
		  int *client_key_len)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    BIGNUM *server_pub_key = NULL;
    ASN1_INTEGER *pub_key = NULL;
    const unsigned char *p = NULL;
    unsigned char *data = NULL;
    long data_len;

    /* decode subjectPublicKey (retrieve INTEGER from OCTET_STRING) */

    if (der_decode_data(subjectPublicKey_data, subjectPublicKey_length,
			&data, &data_len) != 0) {
	pkiDebug("failed to decode subjectPublicKey\n");
	retval = -1;
	goto cleanup;
    }

    *client_key_len = DH_size(cryptoctx->dh);
    if ((*client_key = (unsigned char *)
	    malloc((size_t) *client_key_len)) == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    p = data;
    if ((pub_key = d2i_ASN1_INTEGER(NULL, &p, data_len)) == NULL)
	goto cleanup;
    if ((server_pub_key = ASN1_INTEGER_to_BN(pub_key, NULL)) == NULL)
	goto cleanup;

    DH_compute_key(*client_key, server_pub_key, cryptoctx->dh);
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
    if (data != NULL)
	free (data);

    return retval;

  cleanup:
    if (*client_key != NULL)
	free(*client_key);
    *client_key = NULL;
    if (pub_key != NULL)
	ASN1_INTEGER_free(pub_key);
    if (data != NULL)
	free (data);

    return retval;
}

krb5_error_code
server_check_dh(krb5_context context,
		pkinit_plg_crypto_context cryptoctx,
		pkinit_req_crypto_context req_cryptoctx,
		pkinit_identity_crypto_context id_cryptoctx,
		krb5_octet_data *dh_params,
		int minbits)
{
    DH *dh = NULL;
    unsigned char *tmp = NULL;
    int dh_prime_bits;
    krb5_error_code retval = KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED;

    tmp = dh_params->data;
    dh = DH_new();
    dh = pkinit_decode_dh_params(&dh, &tmp, dh_params->length);
    if (dh == NULL) {
	pkiDebug("failed to decode dhparams\n");
	goto cleanup;
    }

    /* KDC SHOULD check to see if the key parameters satisfy its policy */
    dh_prime_bits = BN_num_bits(dh->p);
    if (minbits && dh_prime_bits < minbits) {
	pkiDebug("client sent dh params with %d bits, we require %d\n",
		 dh_prime_bits, minbits);
	goto cleanup;
    }

    /* check dhparams is group 2 */
    if (pkinit_check_dh_params(cryptoctx->dh_1024->p,
			       dh->p, dh->g, dh->q) == 0) {
	retval = 0;
	goto cleanup;
    }

    /* check dhparams is group 14 */
    if (pkinit_check_dh_params(cryptoctx->dh_2048->p,
			       dh->p, dh->g, dh->q) == 0) {
	retval = 0;
	goto cleanup;
    }

    /* check dhparams is group 16 */
    if (pkinit_check_dh_params(cryptoctx->dh_4096->p,
			       dh->p, dh->g, dh->q) == 0) {
	retval = 0;
	goto cleanup;
    }

  cleanup:
    if (retval == 0)
	req_cryptoctx->dh = dh;
    else
	DH_free(dh);

    return retval;
}

/* kdc's dh function */
krb5_error_code
server_process_dh(krb5_context context,
		  pkinit_plg_crypto_context plg_cryptoctx,
		  pkinit_req_crypto_context cryptoctx,
		  pkinit_identity_crypto_context id_cryptoctx,
		  unsigned char *data,
		  int data_len,
		  unsigned char **dh_pubkey,
		  int *dh_pubkey_len,
		  unsigned char **server_key, int *server_key_len)
{
    krb5_error_code retval = ENOMEM;
    DH *dh = NULL, *dh_server = NULL;
    unsigned char *p = NULL;
    ASN1_INTEGER *pub_key = NULL;

    /* get client's received DH parameters that we saved in server_check_dh */
    dh = cryptoctx->dh;

    dh_server = DH_new();
    if (dh_server == NULL)
	goto cleanup;
    dh_server->p = BN_dup(dh->p);
    dh_server->g = BN_dup(dh->g);
    dh_server->q = BN_dup(dh->q);

    /* decode client's public key */
    p = data;
    pub_key = d2i_ASN1_INTEGER(NULL, (const unsigned char **)&p, data_len);
    if (pub_key == NULL)
	goto cleanup;
    dh->pub_key = ASN1_INTEGER_to_BN(pub_key, NULL);
    if (dh->pub_key == NULL)
	goto cleanup;
    ASN1_INTEGER_free(pub_key);

    if (!DH_generate_key(dh_server))
	goto cleanup;

    /* generate DH session key */
    *server_key_len = DH_size(dh_server);
    if ((*server_key = (unsigned char *) malloc((size_t)*server_key_len)) == NULL)
	goto cleanup;
    DH_compute_key(*server_key, dh->pub_key, dh_server);

#ifdef DEBUG_DH
    print_dh(dh_server, "client&server's DH params\n");
    print_pubkey(dh->pub_key, "client's pub_key=");
    print_pubkey(dh_server->pub_key, "server's pub_key=");
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
    if ((pub_key = BN_to_ASN1_INTEGER(dh_server->pub_key, NULL)) == NULL)
	goto cleanup;
    *dh_pubkey_len = i2d_ASN1_INTEGER(pub_key, NULL);
    if ((p = *dh_pubkey = (unsigned char *) malloc((size_t)*dh_pubkey_len)) == NULL)
	goto cleanup;
    i2d_ASN1_INTEGER(pub_key, &p);
    if (pub_key != NULL)
	ASN1_INTEGER_free(pub_key);

    retval = 0;

    if (dh_server != NULL)
	DH_free(dh_server);
    return retval;

  cleanup:
    if (dh_server != NULL)
	DH_free(dh_server);
    if (*dh_pubkey != NULL)
	free(*dh_pubkey);
    if (*server_key != NULL)
	free(*server_key);

    return retval;
}

static void
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

static krb5_error_code
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

    tmp = *buf = (unsigned char *)malloc((size_t) r);
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

static DH *
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

static krb5_error_code
pkinit_create_sequence_of_principal_identifiers(
    krb5_context context,
    pkinit_plg_crypto_context plg_cryptoctx,
    pkinit_req_crypto_context req_cryptoctx,
    pkinit_identity_crypto_context id_cryptoctx,
    int type,
    krb5_data **out_data)
{
    krb5_error_code retval = KRB5KRB_ERR_GENERIC;
    krb5_external_principal_identifier **krb5_trusted_certifiers = NULL;
    krb5_data *td_certifiers = NULL, *data = NULL;
    krb5_typed_data **typed_data = NULL;

    switch(type) {
        case TD_TRUSTED_CERTIFIERS:
            retval = create_krb5_trustedCertifiers(context, plg_cryptoctx,
	        req_cryptoctx, id_cryptoctx, &krb5_trusted_certifiers);
            if (retval) {
		pkiDebug("create_krb5_trustedCertifiers failed\n");
		goto cleanup;
    	    }
	    break;
	case TD_INVALID_CERTIFICATES:
	    retval = create_krb5_invalidCertificates(context, plg_cryptoctx,
		req_cryptoctx, id_cryptoctx, &krb5_trusted_certifiers);
            if (retval) {
		pkiDebug("create_krb5_invalidCertificates failed\n");
		goto cleanup;
    	    }
	    break;
	default:
	    retval = -1;
	    goto cleanup;
    }

    retval = k5int_encode_krb5_td_trusted_certifiers(krb5_trusted_certifiers,
						     &td_certifiers);
    if (retval) {
	pkiDebug("encode_krb5_td_trusted_certifiers failed\n");
	goto cleanup;
    }
#ifdef DEBUG_ASN1
    print_buffer_bin(td_certifiers->data, td_certifiers->length,
		     "/tmp/kdc_td_certifiers");
#endif
    typed_data = malloc (2 * sizeof(krb5_typed_data *));
    if (typed_data == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    typed_data[1] = NULL;
    init_krb5_typed_data(&typed_data[0]);
    if (typed_data[0] == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    typed_data[0]->type = type;
    typed_data[0]->length = td_certifiers->length;
    typed_data[0]->data = td_certifiers->data;
    retval = k5int_encode_krb5_typed_data(typed_data, &data);
    if (retval) {
	pkiDebug("encode_krb5_typed_data failed\n");
	goto cleanup;
    }
#ifdef DEBUG_ASN1
    print_buffer_bin(data->data, data->length, "/tmp/kdc_edata");
#endif
    *out_data = (krb5_data *)malloc(sizeof(krb5_data));
    (*out_data)->length = data->length;
    (*out_data)->data = (unsigned char *)malloc(data->length);
    memcpy((*out_data)->data, data->data, data->length);

    retval = 0;

cleanup:
    if (krb5_trusted_certifiers != NULL)
	free_krb5_external_principal_identifier(&krb5_trusted_certifiers);

    if (data != NULL) {
	if (data->data != NULL)
	    free(data->data);
	free(data);
    }

    if (td_certifiers != NULL)
	free(td_certifiers);

    if (typed_data != NULL)
	free_krb5_typed_data(&typed_data);

    return retval;
}

krb5_error_code
pkinit_create_td_trusted_certifiers(krb5_context context,
				    pkinit_plg_crypto_context plg_cryptoctx,
				    pkinit_req_crypto_context req_cryptoctx,
				    pkinit_identity_crypto_context id_cryptoctx,
				    krb5_data **out_data)
{
    krb5_error_code retval = KRB5KRB_ERR_GENERIC;

    retval = pkinit_create_sequence_of_principal_identifiers(context,
	plg_cryptoctx, req_cryptoctx, id_cryptoctx,
	TD_TRUSTED_CERTIFIERS, out_data);

    return retval;
}

krb5_error_code
pkinit_create_td_invalid_certificate(
	krb5_context context,
	pkinit_plg_crypto_context plg_cryptoctx,
	pkinit_req_crypto_context req_cryptoctx,
	pkinit_identity_crypto_context id_cryptoctx,
	krb5_data **out_data)
{
    krb5_error_code retval = KRB5KRB_ERR_GENERIC;

    retval = pkinit_create_sequence_of_principal_identifiers(context,
	plg_cryptoctx, req_cryptoctx, id_cryptoctx,
	TD_INVALID_CERTIFICATES, out_data);

    return retval;
}

krb5_error_code
pkinit_create_td_dh_parameters(krb5_context context,
			       pkinit_plg_crypto_context plg_cryptoctx,
			       pkinit_req_crypto_context req_cryptoctx,
			       pkinit_identity_crypto_context id_cryptoctx,
			       pkinit_plg_opts *opts,
			       krb5_data **out_data)
{
    krb5_error_code retval = ENOMEM;
    int buf1_len = 0, buf2_len = 0, buf3_len = 0, i = 0;
    unsigned char *buf1 = NULL, *buf2 = NULL, *buf3 = NULL;
    krb5_typed_data **typed_data = NULL;
    krb5_data *data = NULL, *encoded_algId = NULL;
    krb5_algorithm_identifier **algId = NULL;

    if (opts->dh_min_bits > 4096)
	goto cleanup;

    if (opts->dh_min_bits <= 1024) {
	retval = pkinit_encode_dh_params(plg_cryptoctx->dh_1024->p,
	    plg_cryptoctx->dh_1024->g, plg_cryptoctx->dh_1024->q,
	    &buf1, &buf1_len);
	if (retval)
	    goto cleanup;
    }
    if (opts->dh_min_bits <= 2048) {
	retval = pkinit_encode_dh_params(plg_cryptoctx->dh_2048->p,
	    plg_cryptoctx->dh_2048->g, plg_cryptoctx->dh_2048->q,
	    &buf2, &buf2_len);
	if (retval)
	    goto cleanup;
    }
    retval = pkinit_encode_dh_params(plg_cryptoctx->dh_4096->p,
	plg_cryptoctx->dh_4096->g, plg_cryptoctx->dh_4096->q,
	&buf3, &buf3_len);
    if (retval)
	goto cleanup;

    if (opts->dh_min_bits <= 1024) {
	algId = malloc(4 * sizeof(krb5_algorithm_identifier *));
	if (algId == NULL)
	    goto cleanup;
	algId[3] = NULL;
	algId[0] = (krb5_algorithm_identifier *)malloc(sizeof(krb5_algorithm_identifier));
	if (algId[0] == NULL)
	    goto cleanup;
	algId[0]->parameters.data = (unsigned char *)malloc(buf2_len);
	if (algId[0]->parameters.data == NULL)
	    goto cleanup;
	memcpy(algId[0]->parameters.data, buf2, buf2_len);
	algId[0]->parameters.length = buf2_len;
	algId[0]->algorithm = dh_oid;

	algId[1] = (krb5_algorithm_identifier *)malloc(sizeof(krb5_algorithm_identifier));
	if (algId[1] == NULL)
	    goto cleanup;
	algId[1]->parameters.data = (unsigned char *)malloc(buf3_len);
	if (algId[1]->parameters.data == NULL)
	    goto cleanup;
	memcpy(algId[1]->parameters.data, buf3, buf3_len);
	algId[1]->parameters.length = buf3_len;
	algId[1]->algorithm = dh_oid;

	algId[2] = (krb5_algorithm_identifier *)malloc(sizeof(krb5_algorithm_identifier));
	if (algId[2] == NULL)
	    goto cleanup;
	algId[2]->parameters.data = (unsigned char *)malloc(buf1_len);
	if (algId[2]->parameters.data == NULL)
	    goto cleanup;
	memcpy(algId[2]->parameters.data, buf1, buf1_len);
	algId[2]->parameters.length = buf1_len;
	algId[2]->algorithm = dh_oid;

    } else if (opts->dh_min_bits <= 2048) {
	algId = malloc(3 * sizeof(krb5_algorithm_identifier *));
	if (algId == NULL)
	    goto cleanup;
	algId[2] = NULL;
	algId[0] = (krb5_algorithm_identifier *)malloc(sizeof(krb5_algorithm_identifier));
	if (algId[0] == NULL)
	    goto cleanup;
	algId[0]->parameters.data = (unsigned char *)malloc(buf2_len);
	if (algId[0]->parameters.data == NULL)
	    goto cleanup;
	memcpy(algId[0]->parameters.data, buf2, buf2_len);
	algId[0]->parameters.length = buf2_len;
	algId[0]->algorithm = dh_oid;

	algId[1] = (krb5_algorithm_identifier *)malloc(sizeof(krb5_algorithm_identifier));
	if (algId[1] == NULL)
	    goto cleanup;
	algId[1]->parameters.data = (unsigned char *)malloc(buf3_len);
	if (algId[1]->parameters.data == NULL)
	    goto cleanup;
	memcpy(algId[1]->parameters.data, buf3, buf3_len);
	algId[1]->parameters.length = buf3_len;
	algId[1]->algorithm = dh_oid;

    } else if (opts->dh_min_bits <= 4096) {
	algId = malloc(2 * sizeof(krb5_algorithm_identifier *));
	if (algId == NULL)
	    goto cleanup;
	algId[1] = NULL;
	algId[0] = (krb5_algorithm_identifier *)malloc(sizeof(krb5_algorithm_identifier));
	if (algId[0] == NULL)
	    goto cleanup;
	algId[0]->parameters.data = (unsigned char *)malloc(buf3_len);
	if (algId[0]->parameters.data == NULL)
	    goto cleanup;
	memcpy(algId[0]->parameters.data, buf3, buf3_len);
	algId[0]->parameters.length = buf3_len;
	algId[0]->algorithm = dh_oid;

    }
    retval = k5int_encode_krb5_td_dh_parameters(algId, &encoded_algId);
    if (retval)
	goto cleanup;
#ifdef DEBUG_ASN1
    print_buffer_bin(encoded_algId->data, encoded_algId->length, "/tmp/kdc_td_dh_params");
#endif
    typed_data = malloc (2 * sizeof(krb5_typed_data *));
    if (typed_data == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    typed_data[1] = NULL;
    init_krb5_typed_data(&typed_data[0]);
    if (typed_data == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    typed_data[0]->type = TD_DH_PARAMETERS;
    typed_data[0]->length = encoded_algId->length;
    typed_data[0]->data = encoded_algId->data;
    retval = k5int_encode_krb5_typed_data(typed_data, &data);
    if (retval) {
	pkiDebug("encode_krb5_typed_data failed\n");
	goto cleanup;
    }
#ifdef DEBUG_ASN1
    print_buffer_bin(data->data, data->length, "/tmp/kdc_edata");
#endif
    *out_data = (krb5_data *)malloc(sizeof(krb5_data));
    if (*out_data == NULL)
	goto cleanup;
    (*out_data)->length = data->length;
    (*out_data)->data = (unsigned char *)malloc(data->length);
    if ((*out_data)->data == NULL) {
	free(*out_data);
	*out_data = NULL;
	goto cleanup;
    }
    memcpy((*out_data)->data, data->data, data->length);

    retval = 0;
cleanup:

    if (buf1 != NULL)
	free(buf1);
    if (buf2 != NULL)
	free(buf2);
    if (buf3 != NULL)
	free(buf3);
    if (data != NULL) {
	if (data->data != NULL)
	    free(data->data);
	free(data);
    }
    if (typed_data != NULL)
	free_krb5_typed_data(&typed_data);
    if (encoded_algId != NULL)
	free(encoded_algId);

    if (algId != NULL) {
	while(algId[i] != NULL) {
	    if (algId[i]->parameters.data != NULL)
		free(algId[i]->parameters.data);
	    free(algId[i]);
	    i++;
	}
	free(algId);
    }

    return retval;
}

krb5_error_code pkinit_check_kdc_pkid(
    krb5_context context,
    pkinit_plg_crypto_context plg_cryptoctx,
    pkinit_req_crypto_context req_cryptoctx,
    pkinit_identity_crypto_context id_cryptoctx,
    unsigned char *pdid_buf,
    int pkid_len,
    int *valid_kdcPkId)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    PKCS7_ISSUER_AND_SERIAL *is = NULL;
    const unsigned char *p = pdid_buf;
    int status = 1;
    X509 *kdc_cert = sk_X509_value(id_cryptoctx->my_certs, 0);

    *valid_kdcPkId = 0;
    pkiDebug("found kdcPkId in AS REQ\n");
    is = d2i_PKCS7_ISSUER_AND_SERIAL(NULL, &p, pkid_len);
    if (is == NULL)
	goto cleanup;

    status = X509_NAME_cmp(X509_get_issuer_name(kdc_cert), is->issuer);
    if (!status) {
	status = ASN1_INTEGER_cmp(X509_get_serialNumber(kdc_cert), is->serial);
	if (!status)
	    *valid_kdcPkId = 1;
    }

    retval = 0;
cleanup:
    X509_NAME_free(is->issuer);
    ASN1_INTEGER_free(is->serial);
    free(is);

    return retval;
}

static int
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

krb5_error_code
pkinit_process_td_dh_params(krb5_context context,
			    pkinit_plg_crypto_context cryptoctx,
			    pkinit_req_crypto_context req_cryptoctx,
			    pkinit_identity_crypto_context id_cryptoctx,
			    krb5_algorithm_identifier **algId,
			    int *new_dh_size)
{
    krb5_error_code retval = KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED;
    int i = 0, use_sent_dh = 0, ok = 0;

    pkiDebug("dh parameters\n");

    while (algId[i] != NULL) {
	DH *dh = NULL;
	unsigned char *tmp = NULL;
	int dh_prime_bits = 0;

	if (algId[i]->algorithm.length != dh_oid.length ||
	    memcmp(algId[i]->algorithm.data, dh_oid.data, dh_oid.length))
	    goto cleanup;

	tmp = algId[i]->parameters.data;
	dh = DH_new();
	dh = pkinit_decode_dh_params(&dh, &tmp, algId[i]->parameters.length);
	dh_prime_bits = BN_num_bits(dh->p);
	pkiDebug("client sent %d DH bits server prefers %d DH bits\n",
		 *new_dh_size, dh_prime_bits);
	switch(dh_prime_bits) {
	    case 1024:
		if (pkinit_check_dh_params(cryptoctx->dh_1024->p, dh->p,
			dh->g, dh->q) == 0) {
		    *new_dh_size = 1024;
		    ok = 1;
		}
		break;
	    case 2048:
		if (pkinit_check_dh_params(cryptoctx->dh_2048->p, dh->p,
			dh->g, dh->q) == 0) {
		    *new_dh_size = 2048;
		    ok = 1;
		}
		break;
	    case 4096:
		if (pkinit_check_dh_params(cryptoctx->dh_4096->p, dh->p,
			dh->g, dh->q) == 0) {
		    *new_dh_size = 4096;
		    ok = 1;
		}
		break;
	    default:
		break;
	}
	if (!ok) {
	    DH_check(dh, &retval);
	    if (retval != 0) {
		pkiDebug("DH parameters provided by server are unacceptable\n");
		retval = KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED;
	    }
	    else {
		use_sent_dh = 1;
		ok = 1;
	    }
	}
	if (!use_sent_dh)
	    DH_free(dh);
	if (ok) {
	    if (req_cryptoctx->dh != NULL) {
		DH_free(req_cryptoctx->dh);
		req_cryptoctx->dh = NULL;
	    }
	    if (use_sent_dh)
		req_cryptoctx->dh = dh;
	    break;
	}
	i++;
    }

    if (ok)
	retval = 0;

cleanup:
    return retval;
}

static int
openssl_callback(int ok, X509_STORE_CTX * ctx)
{
#ifdef DEBUG
    if (!ok) {
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

static ASN1_OBJECT *
pkinit_pkcs7type2oid(pkinit_plg_crypto_context cryptoctx, int pkcs7_type)
{

    switch (pkcs7_type) {
	case CMS_SIGN_CLIENT:
	    return cryptoctx->id_pkinit_authData;
	case CMS_SIGN_DRAFT9:
	    return cryptoctx->id_pkinit_authData9;
	case CMS_SIGN_SERVER:
	    return cryptoctx->id_pkinit_DHKeyData;
	case CMS_ENVEL_SERVER:
	    return cryptoctx->id_pkinit_rkeyData;
	default:
	    return NULL;
    }

}

static int
encode_signeddata(unsigned char *data, int data_len,
		  unsigned char **out, int *out_len)
{

    int size = 0, r = 0;
    ASN1_OBJECT *oid;
    unsigned char *p = NULL;

    r = ASN1_object_size(1, data_len, V_ASN1_SEQUENCE);
    oid = OBJ_nid2obj(NID_pkcs7_signed);
    size = i2d_ASN1_OBJECT(oid, NULL);
    size += r;

    r = ASN1_object_size(1, size, V_ASN1_SEQUENCE);
    p = *out = (unsigned char *)malloc(r);
    if (p == NULL) return -1;
    ASN1_put_object(&p, 1, size, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);

    i2d_ASN1_OBJECT(oid, &p);
    ASN1_put_object(&p, 1, data_len, 0, V_ASN1_CONTEXT_SPECIFIC);
    memcpy(p, data, data_len);

    *out_len = r;

    return 0;
}

static int
prepare_enc_data(unsigned char *indata,
		 int indata_len,
		 unsigned char **outdata,
		 int *outdata_len)
{
    int retval = -1;
    ASN1_const_CTX c;
    long length = indata_len;
    int Ttag, Tclass;
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

    *outdata = (unsigned char *)malloc((size_t)Tlen);
    if (outdata == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    memcpy(*outdata, c.p, (size_t)Tlen);
    *outdata_len = Tlen;

    retval = 0;
cleanup:

    return retval;
}

#ifndef WITHOUT_PKCS11
static void *
pkinit_C_LoadModule(const char *modname, CK_FUNCTION_LIST_PTR_PTR p11p)
{
    void *handle;
    CK_RV (*getflist)(CK_FUNCTION_LIST_PTR_PTR);

    pkiDebug("loading module \"%s\"... ", modname);
    handle = dlopen(modname, RTLD_NOW);
    if (handle == NULL) {
	pkiDebug("not found\n");
	return NULL;
    }
    getflist = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR)) dlsym(handle, "C_GetFunctionList");
    if (getflist == NULL || (*getflist)(p11p) != CKR_OK) {
	dlclose(handle);
	pkiDebug("failed\n");
	return NULL;
    }
    pkiDebug("ok\n");
    return handle;
}

static CK_RV
pkinit_C_UnloadModule(void *handle)
{
    dlclose(handle);
    return CKR_OK;
}

static krb5_error_code
pkinit_login(krb5_context context,
	     pkinit_identity_crypto_context id_cryptoctx,
	     CK_TOKEN_INFO *tip)
{
    krb5_data rdat;
    char *prompt;
    krb5_prompt kprompt;
    krb5_prompt_type prompt_type;
    int r = 0;

    if (tip->flags & CKF_PROTECTED_AUTHENTICATION_PATH) {
	rdat.data = NULL;
	rdat.length = 0;
    } else {
	if ((prompt = (char *) malloc(sizeof (tip->label) + 8)) == NULL)
	    return ENOMEM;
	sprintf(prompt, "%.*s PIN", sizeof (tip->label), tip->label);
	rdat.data = (unsigned char *)malloc(tip->ulMaxPinLen + 2);
	rdat.length = tip->ulMaxPinLen + 1;

	kprompt.prompt = prompt;
	kprompt.hidden = 1;
	kprompt.reply = &rdat;
	prompt_type = KRB5_PROMPT_TYPE_PREAUTH;

	/* PROMPTER_INVOCATION */
	krb5int_set_prompt_types(context, &prompt_type);
	r = (*id_cryptoctx->prompter)(context, id_cryptoctx->prompter_data,
		NULL, NULL, 1, &kprompt);
	krb5int_set_prompt_types(context, 0);
	free(prompt);
    }

    if (r == 0) {
	r = id_cryptoctx->p11->C_Login(id_cryptoctx->session, CKU_USER,
		(u_char *) rdat.data, rdat.length);

	if (r != CKR_OK) {
	    pkiDebug("fail C_Login %x\n", r);
	    r = KRB5KDC_ERR_PREAUTH_FAILED;
	}
    }
    if (rdat.data)
	free(rdat.data);

    return r;
}

static krb5_error_code
pkinit_open_session(krb5_context context,
		    pkinit_identity_crypto_context id_cryptoctx)
{
    int r;
    char *cp;
    CK_ULONG count = 0;
    CK_SLOT_ID_PTR slotlist;
    CK_TOKEN_INFO tinfo;

    if (id_cryptoctx->p11_module != NULL)
	return 0; /* session already open */

    /* Load module */
    id_cryptoctx->p11_module =
	pkinit_C_LoadModule(id_cryptoctx->p11_module_name, &id_cryptoctx->p11);
    if (id_cryptoctx->p11_module == NULL)
	return KRB5KDC_ERR_PREAUTH_FAILED;

    /* Init */
    if ((r = id_cryptoctx->p11->C_Initialize(NULL)) != CKR_OK) {
	pkiDebug("fail C_Initialize %x\n", r);
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    /* Decide which slot to use if none specified */
    if (id_cryptoctx->slotid == PK_NOSLOT) {
	if (id_cryptoctx->p11->C_GetSlotList((CK_BBOOL) TRUE, NULL, &count) != CKR_OK)
	    return KRB5KDC_ERR_PREAUTH_FAILED;
	if (count == 0)
	    return KRB5KDC_ERR_PREAUTH_FAILED;
	slotlist = (CK_SLOT_ID_PTR) malloc(count * sizeof (CK_SLOT_ID));
	if (id_cryptoctx->p11->C_GetSlotList((CK_BBOOL) TRUE, slotlist, &count) != CKR_OK)
	    return KRB5KDC_ERR_PREAUTH_FAILED;
	/* take the first one */
	id_cryptoctx->slotid = slotlist[0];
	free(slotlist);
	pkiDebug("autoselect slotid %d (1 of %d)\n", (int) id_cryptoctx->slotid,
		(int) count);
    }

    /* Open session */
    if ((r = id_cryptoctx->p11->C_OpenSession(id_cryptoctx->slotid,
	CKF_SERIAL_SESSION, NULL, NULL, &id_cryptoctx->session)) != CKR_OK) {
	pkiDebug("fail C_OpenSession %x\n", r);
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    /* Get token info */
    if ((r = id_cryptoctx->p11->C_GetTokenInfo(id_cryptoctx->slotid, &tinfo)) != CKR_OK) {
	pkiDebug("fail C_GetTokenInfo %x\n", r);
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    for (cp = tinfo.label + sizeof (tinfo.label) - 1; *cp == '\0' || *cp == ' '; cp--)
	*cp = '\0';

    /* Login if needed */
    if (tinfo.flags & CKF_LOGIN_REQUIRED)
	r = pkinit_login(context, id_cryptoctx, &tinfo);

    return r;
}

/*
 * Look for a key that's:
 * 1. private
 * 2. capable of the specified operation (usually signing or decrypting)
 * 3. RSA (this may be wrong but it's all we can do for now)
 * 4. matches the id of the cert we chose
 *
 * You must call pkinit_get_client_cert before calling pkinit_find_private_key
 * (that's because we need the ID of the private key)
 *
 * pkcs11 says the id of the key doesn't have to match that of the cert, but
 * I can't figure out any other way to decide which key to use.
 *
 * We should only find one key that fits all the requirements.
 * If there are more than one, we just take the first one.
 */

krb5_error_code
pkinit_find_private_key(pkinit_identity_crypto_context id_cryptoctx,
                        CK_ATTRIBUTE_TYPE usage,
                        CK_OBJECT_HANDLE *objp)
{
    CK_OBJECT_CLASS cls;
    CK_ATTRIBUTE attrs[4];
    CK_ULONG count;
    CK_BBOOL bool;
    CK_KEY_TYPE keytype;
    int r, nattrs = 0;

    cls = CKO_PRIVATE_KEY;
    attrs[nattrs].type = CKA_CLASS;
    attrs[nattrs].pValue = &cls;
    attrs[nattrs].ulValueLen = sizeof cls;
    nattrs++;

#ifdef PKINIT_USE_KEY_USAGE
    /*
     * Some cards get confused if you try to specify a key usage,
     * so don't, and hope for the best. This will fail if you have
     * several keys with the same id and different usages but I have
     * not seen this on real cards.
     */
    bool = TRUE;
    attrs[nattrs].type = usage;
    attrs[nattrs].pValue = &bool;
    attrs[nattrs].ulValueLen = sizeof bool;
    nattrs++;
#endif

    keytype = CKK_RSA;
    attrs[nattrs].type = CKA_KEY_TYPE;
    attrs[nattrs].pValue = &keytype;
    attrs[nattrs].ulValueLen = sizeof keytype;
    nattrs++;

    attrs[nattrs].type = CKA_ID;
    attrs[nattrs].pValue = id_cryptoctx->cert_id;
    attrs[nattrs].ulValueLen = id_cryptoctx->cert_id_len;
    nattrs++;

    if (id_cryptoctx->p11->C_FindObjectsInit(id_cryptoctx->session,
            attrs, nattrs) != CKR_OK) {
        pkiDebug("krb5_pkinit_sign_data: fail C_FindObjectsInit\n");
        return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    r = id_cryptoctx->p11->C_FindObjects(id_cryptoctx->session, objp, 1, &count);
    id_cryptoctx->p11->C_FindObjectsFinal(id_cryptoctx->session);
    pkiDebug("found %d private keys %x\n", (int) count, (int) r);
    if (r != CKR_OK || count < 1)
        return KRB5KDC_ERR_PREAUTH_FAILED;
    return 0;
}
#endif

static krb5_error_code
pkinit_decode_data_fs(krb5_context context,
		      pkinit_identity_crypto_context id_cryptoctx,
		      unsigned char *data,
		      int data_len,
		      unsigned char **decoded_data,
		      int *decoded_data_len)
{
    if (decode_data(decoded_data, decoded_data_len, data, data_len,
		id_cryptoctx->my_key, sk_X509_value(id_cryptoctx->my_certs,
		id_cryptoctx->cert_index)) <= 0) {
	pkiDebug("failed to decode data\n");
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    return 0;
}

#ifndef WITHOUT_PKCS11
#ifdef SILLYDECRYPT
CK_RV
pkinit_C_Decrypt(pkinit_identity_crypto_context id_cryptoctx,
		 CK_BYTE_PTR pEncryptedData,
		 CK_ULONG  ulEncryptedDataLen,
		 CK_BYTE_PTR pData,
		 CK_ULONG_PTR pulDataLen)
{
    CK_RV rv = CKR_OK;

    rv = id_cryptoctx->p11->C_Decrypt(id_cryptoctx->session, pEncryptedData,
	ulEncryptedDataLen, pData, pulDataLen);
    if (rv == CKR_OK) {
	pkiDebug("pData %x *pulDataLen %d\n", (int) pData, (int) *pulDataLen);
    }
    return rv;
}
#endif

static krb5_error_code
pkinit_decode_data_pkcs11(krb5_context context,
			  pkinit_identity_crypto_context id_cryptoctx,
			  unsigned char *data,
			  int data_len,
			  unsigned char **decoded_data,
			  int *decoded_data_len)
{
    CK_OBJECT_HANDLE obj;
    CK_ULONG len;
    CK_MECHANISM mech;
    unsigned char *cp;
    int r;

    if (pkinit_open_session(context, id_cryptoctx)) {
	pkiDebug("can't open pkcs11 session\n");
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    pkinit_find_private_key(id_cryptoctx, CKA_DECRYPT, &obj);

    mech.mechanism = CKM_RSA_PKCS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    if ((r = id_cryptoctx->p11->C_DecryptInit(id_cryptoctx->session, &mech,
	    obj)) != CKR_OK) {
	pkiDebug("fail C_DecryptInit %x\n", (int) r);
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    pkiDebug("data_len = %d\n", data_len);
    cp = (unsigned char *)malloc((size_t) data_len);
    if (cp == NULL)
	return ENOMEM;
    len = data_len;
#ifdef SILLYDECRYPT
    pkiDebug("session %x edata %x edata_len %d data %x datalen @%x %d\n",
	    (int) id_cryptoctx->session, (int) data, (int) data_len, (int) cp,
	    (int) &len, (int) len);
    if ((r = pkinit_C_Decrypt(id_cryptoctx, data, (CK_ULONG) data_len,
	    cp, &len)) != CKR_OK) {
#else
    if ((r = id_cryptoctx->p11->C_Decrypt(id_cryptoctx->session, data,
	    (CK_ULONG) data_len, cp, &len)) != CKR_OK) {
#endif
	pkiDebug("fail C_Decrypt %x\n", (int) r);
	if (r == CKR_BUFFER_TOO_SMALL)
	    pkiDebug("decrypt %d needs %d\n", (int) data_len, (int) len);
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    pkiDebug("decrypt %d -> %d\n", (int) data_len, (int) len);
    *decoded_data_len = len;
    *decoded_data = cp;

    return 0;
}
#endif

krb5_error_code
pkinit_decode_data(krb5_context context,
		   pkinit_identity_crypto_context id_cryptoctx,
		   unsigned char *data,
		   int data_len,
		   unsigned char **decoded_data,
		   int *decoded_data_len)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;

    if (!id_cryptoctx->pkcs11_method)
	retval = pkinit_decode_data_fs(context, id_cryptoctx, data, data_len,
	    decoded_data, decoded_data_len);
#ifndef WITHOUT_PKCS11
    else
	retval = pkinit_decode_data_pkcs11(context, id_cryptoctx, data,
	    data_len, decoded_data, decoded_data_len);
#endif

    return retval;
}

static krb5_error_code
pkinit_sign_data_fs(krb5_context context,
		 pkinit_identity_crypto_context id_cryptoctx,
		 unsigned char *data,
		 int data_len,
		 unsigned char **sig,
		 int *sig_len)
{
    if (create_signature(sig, sig_len, data, data_len,
	    id_cryptoctx->my_key) != 0) {
	    pkiDebug("failed to create the signature\n");
	    return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    return 0;
}

#ifndef WITHOUT_PKCS11
static krb5_error_code
pkinit_sign_data_pkcs11(krb5_context context,
			pkinit_identity_crypto_context id_cryptoctx,
			unsigned char *data,
			int data_len,
			unsigned char **sig,
			int *sig_len)
{
    CK_OBJECT_HANDLE obj;
    CK_ULONG len;
    CK_MECHANISM mech;
    unsigned char *cp;
    int r;

    if (pkinit_open_session(context, id_cryptoctx)) {
	pkiDebug("can't open pkcs11 session\n");
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    pkinit_find_private_key(id_cryptoctx, CKA_SIGN, &obj);

    mech.mechanism = id_cryptoctx->mech;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    if ((r = id_cryptoctx->p11->C_SignInit(id_cryptoctx->session, &mech,
	    obj)) != CKR_OK) {
	pkiDebug("fail C_SignInit %x\n", (int) r);
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    /*
     * Key len would give an upper bound on sig size, but there's no way to
     * get that. So guess, and if it's too small, re-malloc.
     */
    len = PK_SIGLEN_GUESS;
    cp = (unsigned char *)malloc((size_t) len);
    if (cp == NULL)
	return ENOMEM;

    r = id_cryptoctx->p11->C_Sign(id_cryptoctx->session, data,
				 (CK_ULONG) data_len, cp, &len);
    if (r == CKR_BUFFER_TOO_SMALL || (r == CKR_OK && len >= PK_SIGLEN_GUESS)) {
	free(cp);
	pkiDebug("C_Sign realloc %d\n", (int) len);
	cp = (unsigned char *)malloc((size_t) len);
	r = id_cryptoctx->p11->C_Sign(id_cryptoctx->session, data,
				     (CK_ULONG) data_len, cp, &len);
    }
    if (r != CKR_OK) {
	pkiDebug("fail C_Sign %x\n", (int) r);
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    pkiDebug("sign %d -> %d\n", (int) data_len, (int) len);
    *sig_len = len;
    *sig = cp;

    return 0;
}
#endif

krb5_error_code
pkinit_sign_data(krb5_context context,
		 pkinit_identity_crypto_context id_cryptoctx,
		 unsigned char *data,
		 int data_len,
		 unsigned char **sig,
		 int *sig_len)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;

    if (id_cryptoctx == NULL || !id_cryptoctx->pkcs11_method)
	retval = pkinit_sign_data_fs(context, id_cryptoctx, data, data_len,
				     sig, sig_len);
#ifndef WITHOUT_PKCS11
    else
	retval = pkinit_sign_data_pkcs11(context, id_cryptoctx, data, data_len,
					 sig, sig_len);
#endif

    return retval;
}


static krb5_error_code
decode_data(unsigned char **out_data, int *out_data_len, unsigned char *data,
	    int data_len, EVP_PKEY *pkey, X509 *cert)
{
    krb5_error_code retval = ENOMEM;
    unsigned char *buf = NULL;
    int buf_len = 0;

    if (cert && !X509_check_private_key(cert, pkey)) {
	pkiDebug("private key does not match certificate\n");
	goto cleanup;
    }

    buf_len = EVP_PKEY_size(pkey);
    buf = (unsigned char *)malloc((size_t) buf_len + 10);
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
    if (retval == ENOMEM)
	free(buf);

    return retval;
}

static krb5_error_code
create_signature(unsigned char **sig, int *sig_len, unsigned char *data,
		 int data_len, EVP_PKEY *pkey)
{
    krb5_error_code retval = ENOMEM;
    EVP_MD_CTX md_ctx;

    if (pkey == NULL)
	return retval;

    EVP_VerifyInit(&md_ctx, EVP_sha1());
    EVP_SignUpdate(&md_ctx, data, data_len);
    *sig_len = EVP_PKEY_size(pkey);
    if ((*sig = (unsigned char *) malloc((size_t) *sig_len)) == NULL)
	goto cleanup;
    EVP_SignFinal(&md_ctx, *sig, sig_len, pkey);

    retval = 0;

  cleanup:
    EVP_MD_CTX_cleanup(&md_ctx);

    return retval;
}

static EVP_PKEY *
get_key(char *filename)
{
    BIO *tmp = NULL;
    EVP_PKEY *pkey = NULL;

    if (filename == NULL)
	return NULL;

    if ((tmp = BIO_new(BIO_s_file()))
	&& (BIO_read_filename(tmp, filename) > 0))
	pkey = (EVP_PKEY *) PEM_read_bio_PrivateKey(tmp, NULL, NULL, NULL);
    if (pkey == NULL) {
	pkiDebug("failed to get private key from %s\n", filename);
	return NULL;
    }
    if (tmp != NULL)
	BIO_free(tmp);

    return pkey;
}

krb5_error_code
pkinit_get_kdc_cert(krb5_context context,
		    pkinit_plg_crypto_context plg_cryptoctx,
		    pkinit_req_crypto_context req_cryptoctx,
		    pkinit_identity_crypto_context id_cryptoctx,
		    const char *principal,
		    krb5_get_init_creds_opt *opt)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;

    req_cryptoctx->received_cert = NULL;
    retval = 0;
    return retval;
}

static krb5_error_code
pkinit_get_client_cert_fs(krb5_context context,
			  pkinit_plg_crypto_context plg_cryptoctx,
			  pkinit_req_crypto_context req_cryptoctx,
			  pkinit_identity_crypto_context id_cryptoctx,
			  const char *principal,
			  krb5_get_init_creds_opt *opt)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    X509 *x = NULL;
    char *cert_filename = NULL, *key_filename = NULL;

    if (get_filename(&cert_filename, "X509_USER_CERT", 0) != 0) {
	pkiDebug("failed to get user's cert location\n");
	goto cleanup;
    }

    if (get_filename(&key_filename, "X509_USER_KEY", 0) != 0) {
	pkiDebug("failed to get user's private key location\n");
	goto cleanup;
    }
	
    /* get location of the certificate and the private key */
    if ((x = get_cert(cert_filename)) == NULL) {
	pkiDebug("failed to get user's cert\n");
	goto cleanup;
    }
    else {
	/* add the certificate */
	id_cryptoctx->my_certs = sk_X509_new_null();	
	sk_X509_push(id_cryptoctx->my_certs, x);
	id_cryptoctx->cert_index = 0;

	/* add the private key */
	if ((id_cryptoctx->my_key = get_key(key_filename)) == NULL) {
	    pkiDebug("failed to get user's private key\n");
	    goto cleanup;
	}
    }
    retval = 0;

cleanup:
    if (cert_filename != NULL)
	free(cert_filename);
    if (key_filename != NULL)
	free(key_filename);
    if (retval) {
	if (id_cryptoctx->my_certs != NULL)
	    sk_X509_pop_free(id_cryptoctx->my_certs, X509_free);
    }
    return retval;
}

#ifndef WITHOUT_PKCS11
static krb5_error_code
pkinit_get_client_cert_pkcs11(krb5_context context,
			      pkinit_plg_crypto_context plg_cryptoctx,
			      pkinit_req_crypto_context req_cryptoctx,
			      pkinit_identity_crypto_context id_cryptoctx,
			      const char *principal,
			      krb5_get_init_creds_opt *opt)
{
    CK_MECHANISM_TYPE_PTR mechp;
    CK_MECHANISM_INFO info;
    CK_OBJECT_CLASS cls;
    CK_OBJECT_HANDLE obj;
    CK_ATTRIBUTE attrs[4];
    CK_ULONG count;
    CK_CERTIFICATE_TYPE certtype;
    CK_BYTE_PTR cert = NULL, cert_id;
    const unsigned char *cp;
    int i, r, nattrs;
    X509 *x = NULL;

    if (principal == NULL) {
	return KRB5_PRINC_NOMATCH;
    }

    if (pkinit_open_session(context, id_cryptoctx)) {
	pkiDebug("can't open pkcs11 session\n");
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

#ifndef PKINIT_USE_MECH_LIST
    /*
     * We'd like to use CKM_SHA1_RSA_PKCS for signing if it's available, but
     * many cards seems to be confused about whether they are capable of
     * this or not. The safe thing seems to be to ignore the mechanism list,
     * always use CKM_RSA_PKCS and calculate the sha1 digest ourselves.
     */

    id_cryptoctx->mech = CKM_RSA_PKCS;
#else
    if ((r = id_cryptoctx->p11->C_GetMechanismList(id_cryptoctx->slotid, NULL,
	    &count)) != CKR_OK || count <= 0) {
	pkiDebug("can't find any mechanisms %x\n", r);
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    mechp = (CK_MECHANISM_TYPE_PTR) malloc(count * sizeof (CK_MECHANISM_TYPE));
    if (mechp == NULL)
	return ENOMEM;
    if ((r = id_cryptoctx->p11->C_GetMechanismList(id_cryptoctx->slotid,
	    mechp, &count)) != CKR_OK)
	return KRB5KDC_ERR_PREAUTH_FAILED;
    for (i = 0; i < count; i++) {
	if ((r = id_cryptoctx->p11->C_GetMechanismInfo(id_cryptoctx->slotid,
		mechp[i], &info)) != CKR_OK)
	    return KRB5KDC_ERR_PREAUTH_FAILED;
#ifdef DEBUG_MECHINFO
	pkiDebug("mech %x flags %x\n", (int) mechp[i], (int) info.flags);
	if ((info.flags & (CKF_SIGN|CKF_DECRYPT)) == (CKF_SIGN|CKF_DECRYPT))
	    pkiDebug("  this mech is good for sign & decrypt\n");
#endif
	if (mechp[i] == CKM_RSA_PKCS) {
	    /* This seems backwards... */
	    id_cryptoctx->mech =
		(info.flags & CKF_SIGN) ? CKM_SHA1_RSA_PKCS : CKM_RSA_PKCS;
	}
    }
    free(mechp);

    pkiDebug("got %d mechs; reading certs for '%s' from card\n",
	    (int) count, principal);
#endif

    cls = CKO_CERTIFICATE;
    attrs[0].type = CKA_CLASS;
    attrs[0].pValue = &cls;
    attrs[0].ulValueLen = sizeof cls;

    certtype = CKC_X_509;
    attrs[1].type = CKA_CERTIFICATE_TYPE;
    attrs[1].pValue = &certtype;
    attrs[1].ulValueLen = sizeof certtype;

    nattrs = 2;

    /* If a cert id and/or label were given, use them too */
    if (id_cryptoctx->cert_id_len > 0) {
	attrs[nattrs].type = CKA_ID;
	attrs[nattrs].pValue = id_cryptoctx->cert_id;
	attrs[nattrs].ulValueLen = id_cryptoctx->cert_id_len;
	nattrs++;
    }
    if (id_cryptoctx->cert_label != NULL) {
	attrs[nattrs].type = CKA_LABEL;
	attrs[nattrs].pValue = id_cryptoctx->cert_label;
	attrs[nattrs].ulValueLen = strlen(id_cryptoctx->cert_label);
	nattrs++;
    }

    if (id_cryptoctx->p11->C_FindObjectsInit(id_cryptoctx->session,
	    attrs, nattrs) != CKR_OK) {
	pkiDebug("fail C_FindObjectsInit\n");
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    for (i = 0; ; i++) {
	/* Look for x.509 cert */
	if ((r = id_cryptoctx->p11->C_FindObjects(id_cryptoctx->session,
		&obj, 1, &count)) != CKR_OK || count <= 0) {
	    break;
	}

	/* Get cert and id len */
	attrs[0].type = CKA_VALUE;
	attrs[0].pValue = NULL;
	attrs[0].ulValueLen = 0;

	attrs[1].type = CKA_ID;
	attrs[1].pValue = NULL;
	attrs[1].ulValueLen = 0;

	if ((r = id_cryptoctx->p11->C_GetAttributeValue(id_cryptoctx->session,
		obj, attrs, 2)) != CKR_OK && r != CKR_BUFFER_TOO_SMALL) {
	    pkiDebug("fail C_GetAttributeValue len %x\n", r);
	    return KRB5KDC_ERR_PREAUTH_FAILED;
	}
	cert = (CK_BYTE_PTR) malloc((size_t) attrs[0].ulValueLen + 1);
	cert_id = (CK_BYTE_PTR) malloc((size_t) attrs[1].ulValueLen + 1);
	if (cert == NULL || cert_id == NULL)
	    return ENOMEM;

	/* Read the cert and id off the card */

	attrs[0].type = CKA_VALUE;
	attrs[0].pValue = cert;

	attrs[1].type = CKA_ID;
	attrs[1].pValue = cert_id;

	if ((r = id_cryptoctx->p11->C_GetAttributeValue(id_cryptoctx->session,
		obj, attrs, 2)) != CKR_OK) {
	    pkiDebug("fail C_GetAttributeValue %x\n", r);
	    return KRB5KDC_ERR_PREAUTH_FAILED;
	}

	pkiDebug("cert %d size %d id %d idlen %d\n", i,
	    (int) attrs[0].ulValueLen, (int) cert_id[0],
	    (int) attrs[1].ulValueLen);
	/* Just take the first one */
	if (i == 0) {
	    id_cryptoctx->cert_id = cert_id;
	    id_cryptoctx->cert_id_len = attrs[1].ulValueLen;
	    cp = (unsigned char *) cert;
	    x = d2i_X509(NULL, &cp, (int) attrs[0].ulValueLen);
	    if (x == NULL)
		return KRB5KDC_ERR_PREAUTH_FAILED;
	    id_cryptoctx->my_certs = sk_X509_new_null();	
	    sk_X509_push(id_cryptoctx->my_certs, x);
	    id_cryptoctx->cert_index = 0;
	} else
	    free(cert_id);
	free(cert);
    }
    id_cryptoctx->p11->C_FindObjectsFinal(id_cryptoctx->session);
    if (cert == NULL)
	return KRB5KDC_ERR_PREAUTH_FAILED;
    return 0;
}
#endif

krb5_error_code
pkinit_get_client_cert(krb5_context context,
		       pkinit_plg_crypto_context plg_cryptoctx,
		       pkinit_req_crypto_context req_cryptoctx,
		       pkinit_identity_crypto_context id_cryptoctx,
		       const char *principal,
		       krb5_get_init_creds_opt *opt)
{

    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;

    if (!id_cryptoctx->pkcs11_method) {
	retval =pkinit_get_client_cert_fs(context, plg_cryptoctx,
	    req_cryptoctx, id_cryptoctx, principal, opt);
    }
#ifndef WITHOUT_PKCS11
    else {
	retval =pkinit_get_client_cert_pkcs11(context, plg_cryptoctx,
	    req_cryptoctx, id_cryptoctx, principal, opt);
    }
#endif
    return retval;
}

krb5_error_code
pkinit_get_trusted_cacerts(krb5_context context,
			   pkinit_plg_crypto_context plg_cryptoctx,
			   pkinit_req_crypto_context req_cryptoctx,
			   pkinit_identity_crypto_context id_cryptoctx,
			   krb5_get_init_creds_opt *opt)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    char *filename = NULL, *dirname = NULL;

    id_cryptoctx->trustedCAs = NULL;

    if (get_filename(&filename, "X509_CA_TRUSTED_BUNDLE", 1) != 0) {
	pkiDebug("failed to get the name of the ca-bundle file of trusted CAs\n");
    }

    if (get_filename(&dirname, "X509_CA_TRUSTED_DIR", 1) != 0) {
	pkiDebug("failed to get the dir of trusted CAs\n");
    }

    if (filename) {
	retval = load_trusted_certifiers(&id_cryptoctx->trustedCAs, NULL, 0, 
					 filename);
	if (retval)
	    goto cleanup;
    }

    if (dirname) {
	retval = load_trusted_certifiers_dir(&id_cryptoctx->trustedCAs, 
					     NULL, 0, dirname);
	if (retval)
	    goto cleanup;
    }

    retval = 0;
cleanup:
    if (filename != NULL)
	free(filename);
    if (dirname != NULL)
	free(dirname);

    return retval;
}

krb5_error_code
pkinit_get_intermediate_cacerts(krb5_context context,
				pkinit_plg_crypto_context plg_cryptoctx,
				pkinit_req_crypto_context req_cryptoctx,
				pkinit_identity_crypto_context id_cryptoctx,
				krb5_get_init_creds_opt *opt)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    char *filename = NULL, *dirname = NULL;

    id_cryptoctx->intermediateCAs = NULL;

    if (get_filename(&filename, "X509_CA_INTERM_BUNDLE", 1) != 0) {
	pkiDebug("failed to get the name of the ca-bundle file of intermediate CAs\n");
    }

    if (get_filename(&dirname, "X509_CA_INTERM_DIR", 1) != 0) {
	pkiDebug("failed to get the dir of intermediate CAs\n");
    }

    if (filename) {
	retval = load_trusted_certifiers(&id_cryptoctx->intermediateCAs, NULL, 
					 0, filename);
	if (retval)
	    goto cleanup;
    }

    if (dirname) {
	retval = load_trusted_certifiers_dir(&id_cryptoctx->intermediateCAs, 
					     NULL, 0, dirname);
	if (retval)
	    goto cleanup;
    }

    retval = 0;
cleanup:
    if (filename != NULL)
	free(filename);
    if (dirname != NULL)
	free(dirname);

    return retval;
}

krb5_error_code
pkinit_get_crls(krb5_context context,
		pkinit_plg_crypto_context plg_cryptoctx,
		pkinit_req_crypto_context req_cryptoctx,
		pkinit_identity_crypto_context id_cryptoctx,
		krb5_get_init_creds_opt *opt)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    char *filename = NULL, *dirname = NULL;

    id_cryptoctx->revoked = NULL;

    if (get_filename(&filename, "X509_CRL_BUNDLE", 1) != 0) {
	pkiDebug("failed to get the name of the ca-bundle file of CRLs\n");
    }

    if (get_filename(&dirname, "X509_CRL_DIR", 1) != 0) {
	pkiDebug("failed to get the dir of CRLs\n");
    }

    if (filename) {
	retval = load_trusted_certifiers(NULL, &id_cryptoctx->revoked, 
					 1, filename);
	if (retval)
	    goto cleanup;
    }

    if (dirname) {
	retval = load_trusted_certifiers_dir(NULL, &id_cryptoctx->revoked,
					     1, dirname);
	if (retval)
	    goto cleanup;
    }

    retval = 0;
cleanup:
    if (filename != NULL)
	free(filename);
    if (dirname != NULL)
	free(dirname);

    return retval;
}

static krb5_error_code
load_trusted_certifiers_dir(STACK_OF(X509) **trusted_CAs,
			    STACK_OF(X509_CRL) **crls,
			    int return_crls,
			    char *dirname) 
{
    STACK_OF(X509) *ca_certs = NULL;
    STACK_OF(X509) *ca_crls = NULL;
    krb5_error_code retval = ENOMEM;
    DIR *d = NULL;
    struct dirent *dentry = NULL;
    char filename[1024];

    if (dirname == NULL)
	return ENOMEM;

    if (return_crls) {
	if (*crls != NULL) 
	    ca_crls = *crls;
	else {
	    ca_crls = sk_X509_CRL_new_null();
	    if (ca_crls == NULL) 
		return ENOMEM;
	}
    } else {
	if (*trusted_CAs != NULL)
	    ca_certs = *trusted_CAs;
	else {
	    ca_certs = sk_X509_new_null();
	    if (ca_certs == NULL) 
		return ENOMEM;
	}
    }

    d = opendir(dirname);
    if (d == NULL) 
	goto cleanup;

    while ((dentry = readdir(d))) {
	if (strlen(dirname) + strlen(dentry->d_name) + 2 > sizeof(filename))
	    goto cleanup;
	sprintf(filename, "%s/%s", dirname, dentry->d_name);

	retval = load_trusted_certifiers(&ca_certs, &ca_crls, return_crls, 
					 filename);
	if (retval)
	    goto cleanup;
    }

    if (return_crls)
	*crls = ca_crls;
    else
	*trusted_CAs = ca_certs;

    retval = 0;

  cleanup:
    if (d) 
	closedir(d);

    if (retval) {
	if (return_crls) 
	    sk_X509_CRL_pop_free(ca_crls, X509_CRL_free);
	else
	    sk_X509_pop_free(ca_certs, X509_free);
    }

    return retval;
}

static krb5_error_code
load_trusted_certifiers(STACK_OF(X509) **trusted_CAs,
			STACK_OF(X509_CRL) **crls,
			int return_crls,
			char *filename)
{
    STACK_OF(X509_INFO) *sk = NULL;
    STACK_OF(X509) *ca_certs = NULL;
    STACK_OF(X509_CRL) *ca_crls = NULL;
    BIO *in = NULL;
    krb5_error_code retval = ENOMEM;
    int i = 0;

    if (return_crls) {
	if (*crls != NULL)
	    ca_crls = *crls;
	else {
	    ca_crls = sk_X509_CRL_new_null();
	    if (!ca_crls) 
		return ENOMEM;
	}
    } else {
	if (*trusted_CAs != NULL)
	    ca_certs = *trusted_CAs;
	else {
	    ca_certs = sk_X509_new_null();
	    if (!ca_certs) 
		return ENOMEM;
	}
    }

    if (!(in = BIO_new_file(filename, "r"))) {
	retval = errno;
	pkiDebug("error opening the CAfile '%s': %s\n", filename,
		 error_message(errno));
	goto cleanup;
    }

    /* This loads from a file, a stack of x509/crl/pkey sets */
    if ((sk = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL)) == NULL) {
	pkiDebug("error reading the CAfile\n");
	goto cleanup;
    }

    /* scan over it and pull out the certs */
    for (i = 0; i < sk_X509_INFO_num(sk); i++) {
	X509_INFO *xi = sk_X509_INFO_value(sk, i);
	if (xi != NULL && xi->x509 != NULL && !return_crls) { 
	    int j = 0, size = sk_X509_num(ca_certs), flag = 0;

	    if (!size) {
		sk_X509_push(ca_certs, xi->x509);
		xi->x509 = NULL;
		continue;
	    }
	    for (j = 0; j < size; j++) {
		X509 *x = sk_X509_value(ca_certs, j);
		flag = X509_cmp(x, xi->x509);
		if (flag == 0)
		    break;
		else 
		    continue;
	    }
	    if (flag != 0) {
		sk_X509_push(ca_certs, X509_dup(xi->x509));
	    }
	} else if (xi != NULL && xi->crl != NULL && return_crls) {
	    int j = 0, size = sk_X509_CRL_num(ca_crls), flag = 0;
	    if (!size) {
		sk_X509_CRL_push(ca_crls, xi->crl);
		xi->crl = NULL;
		continue;
	    }
	    for (j = 0; j < size; j++) {
		X509_CRL *x = sk_X509_CRL_value(ca_crls, j);
		flag = X509_CRL_cmp(x, xi->crl);
		if (flag == 0)
		    break;
		else
		    continue;
	    }
	    if (flag != 0) {
		sk_X509_push(ca_crls, X509_CRL_dup(xi->crl));
	    }
	}
    }

    if (return_crls) {
	if (!sk_X509_num(ca_crls)) {
	    pkiDebug("no crls in file, %s\n", filename);
	    if (*crls == NULL)
		sk_X509_CRL_free(ca_crls);
	} else {
	    *crls = ca_crls;
	}
    } else {
	if (!sk_X509_num(ca_certs)) {
	    pkiDebug("no certificates in file, %s\n", filename);
	    if (*trusted_CAs == NULL) 
		sk_X509_free(ca_certs);
	} else
	    *trusted_CAs = ca_certs;
    }

    retval = 0;

  cleanup:
    if (in != NULL)
	BIO_free(in);
    if (sk != NULL)
	sk_X509_INFO_pop_free(sk, X509_INFO_free);

    return retval;
}

static krb5_error_code
create_identifiers_from_stack(STACK_OF(X509) *sk, krb5_external_principal_identifier *** ids)
{
    krb5_error_code retval = ENOMEM;
    int i = 0, sk_size = sk_X509_num(sk);
    krb5_external_principal_identifier **krb5_cas = NULL;
    X509 *x = NULL;
    X509_NAME *xn = NULL;
    unsigned char *p = NULL;
    int len = 0;
    PKCS7_ISSUER_AND_SERIAL *is = NULL;
    char buf[256];

    *ids = NULL;

    krb5_cas =
	malloc((sk_size + 1) * sizeof(krb5_external_principal_identifier *));
    if (krb5_cas == NULL)
	return ENOMEM;
    krb5_cas[sk_size] = NULL;

    for (i = 0; i < sk_size; i++) {
	krb5_cas[i] = (krb5_external_principal_identifier *)malloc(sizeof(krb5_external_principal_identifier));

	x = sk_X509_value(sk, i);

	X509_NAME_oneline(X509_get_subject_name(x), buf, 256);
	pkiDebug("#%d cert= %s\n", i, buf);

	/* fill-in subjectName */
	krb5_cas[i]->subjectName.magic = 0;
	krb5_cas[i]->subjectName.length = 0;
	krb5_cas[i]->subjectName.data = NULL;

	xn = X509_get_subject_name(x);
	len = i2d_X509_NAME(xn, NULL);
	if ((p = krb5_cas[i]->subjectName.data = (unsigned char *)malloc((size_t) len)) == NULL)
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
	     (unsigned char *)malloc((size_t) len)) == NULL)
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
			(unsigned char *)malloc((size_t) len)) == NULL)
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

krb5_error_code
create_krb5_invalidCertificates(krb5_context context,
			        pkinit_plg_crypto_context plg_cryptoctx,
			        pkinit_req_crypto_context req_cryptoctx,
			        pkinit_identity_crypto_context id_cryptoctx,
			        krb5_external_principal_identifier *** ids)
{

    krb5_error_code retval = ENOMEM;
    STACK_OF(X509) *sk = NULL;

    *ids = NULL;
    if (req_cryptoctx->received_cert == NULL)
	return KRB5KDC_ERR_PREAUTH_FAILED;

    sk = sk_X509_new_null();
    if (sk == NULL) 
	goto cleanup;
    sk_X509_push(sk, req_cryptoctx->received_cert);

    retval = create_identifiers_from_stack(sk, ids);

    sk_X509_free(sk);
cleanup:

    return retval;
}

krb5_error_code
create_krb5_trustedCertifiers(krb5_context context,
			      pkinit_plg_crypto_context plg_cryptoctx,
			      pkinit_req_crypto_context req_cryptoctx,
			      pkinit_identity_crypto_context id_cryptoctx,
			      krb5_external_principal_identifier *** ids)
{

    krb5_error_code retval = ENOMEM;
    STACK_OF(X509) *sk = id_cryptoctx->trustedCAs;

    *ids = NULL;
    if (id_cryptoctx->trustedCAs == NULL)
	return KRB5KDC_ERR_PREAUTH_FAILED;

    retval = create_identifiers_from_stack(sk, ids);

    return retval;
}

krb5_error_code
create_krb5_trustedCas(krb5_context context,
		       pkinit_plg_crypto_context plg_cryptoctx,
		       pkinit_req_crypto_context req_cryptoctx,
		       pkinit_identity_crypto_context id_cryptoctx,
		       int flag,
		       krb5_trusted_ca *** ids)
{
    krb5_error_code retval = ENOMEM;
    STACK_OF(X509) *sk = id_cryptoctx->trustedCAs;;
    int i = 0, len = 0, sk_size = sk_X509_num(sk);
    krb5_trusted_ca **krb5_cas = NULL;
    X509 *x = NULL;
    char buf[256];
    X509_NAME *xn = NULL;
    unsigned char *p = NULL;
    PKCS7_ISSUER_AND_SERIAL *is = NULL;

    *ids = NULL;
    if (id_cryptoctx->trustedCAs == NULL)
	return KRB5KDC_ERR_PREAUTH_FAILED;

    krb5_cas = malloc((sk_size + 1) * sizeof(krb5_trusted_ca *));
    if (krb5_cas == NULL)
	return ENOMEM;
    krb5_cas[sk_size] = NULL;

    for (i = 0; i < sk_size; i++) {
	krb5_cas[i] = (krb5_trusted_ca *)malloc(sizeof(krb5_trusted_ca));
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
		    (unsigned char *)malloc((size_t) len)) == NULL)
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
		    (unsigned char *)malloc((size_t) len)) == NULL)
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

#define IDTYPE_FILE	1
#define IDTYPE_DIR	2
#define IDTYPE_PKCS11	3

#define CATYPE_ANCHORS		1
#define CATYPE_INTERMEDIATES	2
#define CATYPE_CRLS		3

static krb5_error_code
parse_pkcs11_options(krb5_context context,
		     pkinit_identity_crypto_context id_cryptoctx,
		     const char *residual)
{
    char *s, *cp, *vp;
    krb5_error_code retval = ENOMEM;
    BIGNUM *bn;

    if (residual == NULL || residual[0] == '\0')
	return 0;

    /* Split string into attr=value substrings */
    s = strdup(residual);
    if (s == NULL)
	return retval;

    for ((cp = strtok(s, ":")); cp; (cp = strtok(NULL, ":"))) {
        vp = strchr(cp, '=');

        /* If there is no "=", this is a pkcs11 module name */
        if (vp == NULL) {
	    if (id_cryptoctx->p11_module_name != NULL)
		free(id_cryptoctx->p11_module_name);
            id_cryptoctx->p11_module_name = strdup(cp);
	    if (id_cryptoctx->p11_module_name == NULL)
		goto cleanup;
            continue;
        }
        *vp++ = '\0';
        if (!strcmp(cp, "module_name")) {
	    if (id_cryptoctx->p11_module_name != NULL)
		free(id_cryptoctx->p11_module_name);
            id_cryptoctx->p11_module_name = strdup(vp);
	    if (id_cryptoctx->p11_module_name == NULL)
		goto cleanup;
        } else if (!strcmp(cp, "slotid")) {
	    long slotid = strtol(vp, NULL, 10);
	    if ((slotid == LONG_MIN || slotid == LONG_MAX) && errno != 0) {
		retval = EINVAL;
		goto cleanup;
	    }
	    if ((long) (int) slotid != slotid) {
		retval = EINVAL;
		goto cleanup;
	    }
            id_cryptoctx->slotid = slotid;
        } else if (!strcmp(cp, "token")) {
            if (id_cryptoctx->token_label != NULL)
                free(id_cryptoctx->token_label);
            id_cryptoctx->token_label = strdup(vp);
	    if (id_cryptoctx->token_label == NULL)
		goto cleanup;
        } else if (!strcmp(cp, "certid")) {
            if (id_cryptoctx->cert_id != NULL)
                free(id_cryptoctx->cert_id);
            bn = NULL;
	    /* XXX do we need BN stuff at this point? */
            BN_hex2bn(&bn, vp);
            id_cryptoctx->cert_id_len = BN_num_bytes(bn);
            id_cryptoctx->cert_id = (unsigned char *)malloc((size_t) id_cryptoctx->cert_id_len);
            if (id_cryptoctx->cert_id == NULL)
		goto cleanup;
            BN_bn2bin(bn, id_cryptoctx->cert_id);
            BN_free(bn);
        } else if (!strcmp(cp, "certlabel")) {
            if (id_cryptoctx->cert_label != NULL)
                free(id_cryptoctx->cert_label);
            id_cryptoctx->cert_label = strdup(vp);
	    if (id_cryptoctx->cert_label == NULL)
		goto cleanup;
        }
    }
    retval = 0;
cleanup:
    free(s);
    /* XXX Clean up other stuff too? */
    return retval;
}

static krb5_error_code
process_option_identity(krb5_context context, const char *value,
			pkinit_identity_crypto_context id_cryptoctx)
{
    char *sep, *residual;
    int idtype;
    krb5_error_code retval = 0;

    if (value == NULL)
	return ENOENT;	    /* XXX */

    residual = strchr(value, ':');
    if (residual) {
	int typelen;
	residual++; /* skip past colon */
	typelen = residual - value;
	if (strncmp(value, "FILE:", typelen) == 0) {
	    idtype = IDTYPE_FILE;
	} else if (strncmp(value, "PKCS11:", typelen) == 0) {
	    idtype = IDTYPE_PKCS11;
	} else {
	    krb5_set_error_message(context, KRB5_PREAUTH_FAILED,
				   "Unsupported type while processing '%s'\n",
				   value);
	    return KRB5_PREAUTH_FAILED;
	}
    } else {
	idtype = IDTYPE_FILE;
	residual = (char *)value;
    }

    switch (idtype) {
	int certlen;
	char certbuf[256];
	char keybuf[256];
	X509 *cert;
    case IDTYPE_FILE:
	sep = strchr(residual, ',');
	if (sep) {
	    certlen = sep - residual;
	    strncpy(certbuf, residual, certlen);
	    certbuf[certlen] = '\0';
	    strncpy(keybuf, ++sep, sizeof keybuf);
	    keybuf[sizeof(keybuf) - 1] = '\0';
	} else {
	    strncpy(certbuf, residual, sizeof certbuf);
	    certbuf[sizeof(certbuf) - 1] = '\0';
	    strncpy(keybuf, residual, sizeof keybuf);
	    keybuf[sizeof(keybuf) - 1] = '\0';
	}
	/* Load the certificate and the private key */
	if ((cert = get_cert(certbuf)) == NULL) {
	    pkiDebug("failed to load cert from '%s'\n", certbuf);
	    retval = EINVAL;	/* XXX */
	    goto cleanup;
	}
	/* add the certificate to the id_cryptoctx */
	id_cryptoctx->my_certs = sk_X509_new_null();
	sk_X509_push(id_cryptoctx->my_certs, cert);
	id_cryptoctx->cert_index = 0;

	/* add the private key to the id_cryptoctx */
	if ((id_cryptoctx->my_key = get_key(keybuf)) == NULL) {
	    pkiDebug("failed to load private key from '%s'\n", keybuf);
	    goto cleanup;
	}
	break;
#ifndef WITHOUT_PKCS11
    case IDTYPE_PKCS11:
	id_cryptoctx->pkcs11_method = 1;
	retval = parse_pkcs11_options(context, id_cryptoctx, residual);
	if (retval == 0)
	    retval = pkinit_get_client_cert_pkcs11(context, NULL, NULL,
						   id_cryptoctx,
						   "<not specified>", NULL);
	break;
#endif
    case IDTYPE_DIR:
	pkiDebug("DIR: not supported for user_identity '%s'\n", value);
	retval = EINVAL;    /* XXX  */
    default:
	krb5_set_error_message(context, KRB5_PREAUTH_FAILED,
			       "Internal error parsing X509_user_identity\n");
	retval = EINVAL;    /* XXX */
    }
cleanup:
    return retval;
}

static krb5_error_code
process_option_ca_crl(krb5_context context, const char *value,
		      pkinit_identity_crypto_context id_cryptoctx, int catype)
{
    char *residual;
    int typelen;
    krb5_error_code retval = 0;

    residual = strchr(value, ':');
    if (residual == NULL) {
	pkiDebug("No type given for '%s'\n", value);
	return EINVAL;	    /* XXX */
    }
    residual++; /* skip past colon */
    typelen = residual - value;
    if (strncmp(value, "FILE:", typelen) == 0) {
	if (catype == CATYPE_ANCHORS)
	    retval = load_trusted_certifiers(&id_cryptoctx->trustedCAs,
					     NULL, 0, residual); 
	else if (catype == CATYPE_INTERMEDIATES)
	    retval = load_trusted_certifiers(&id_cryptoctx->intermediateCAs,
					     NULL, 0, residual); 
	else if (catype == CATYPE_CRLS)
	    retval = load_trusted_certifiers(NULL, &id_cryptoctx->revoked,
					     1, residual); 
	else
	    retval = ENOTSUP;
    } else if (strncmp(value, "DIR:", typelen) == 0) {
	if (catype == CATYPE_ANCHORS)
	    retval = load_trusted_certifiers_dir(&id_cryptoctx->trustedCAs,
						 NULL, 0, residual); 
	else if (catype == CATYPE_INTERMEDIATES)
	    retval = load_trusted_certifiers_dir(&id_cryptoctx->intermediateCAs,
						 NULL, 0, residual); 
	else if (catype == CATYPE_CRLS)
	    retval = load_trusted_certifiers_dir(NULL, &id_cryptoctx->revoked,
						 1, residual); 
	else
	    retval = ENOTSUP;
    } else {
	retval = ENOTSUP;
    }
    return retval;
}


krb5_error_code
pkinit_process_identity_option(krb5_context context,
			       int attr,
			       const char *value,
			       pkinit_identity_crypto_context id_cryptoctx)
{
    krb5_error_code retval = 0;

    switch (attr) {
	case PKINIT_ID_OPT_USER_IDENTITY:
	    retval = process_option_identity(context, value, id_cryptoctx);
	    break;
	case PKINIT_ID_OPT_ANCHOR_CAS:
	    retval = process_option_ca_crl(context, value, id_cryptoctx,
					   CATYPE_ANCHORS);
	    break;
	case PKINIT_ID_OPT_INTERMEDIATE_CAS:
	    retval = process_option_ca_crl(context, value, id_cryptoctx,
					   CATYPE_INTERMEDIATES);
	    break;
	case PKINIT_ID_OPT_CRLS:
	    retval = process_option_ca_crl(context, value, id_cryptoctx,
					   CATYPE_CRLS);
	    break;
	case PKINIT_ID_OPT_OCSP:
	    /* XXX Silently ignore this if specified? retval = ENOTSUP; */
	    break;
	default:
	    retval = EINVAL;
	    break;
    }
    return retval;
}

krb5_error_code
create_issuerAndSerial(krb5_context context,
		       pkinit_plg_crypto_context plg_cryptoctx,
		       pkinit_req_crypto_context req_cryptoctx,
		       pkinit_identity_crypto_context id_cryptoctx,
		       unsigned char **out,
		       int *out_len)
{
    unsigned char *p = NULL;
    PKCS7_ISSUER_AND_SERIAL *is = NULL;
    int len = 0;
    krb5_error_code retval = ENOMEM;
    X509 *cert = req_cryptoctx->received_cert;

    *out = NULL;
    *out_len = 0;
    if (req_cryptoctx->received_cert == NULL)
	return 0;

    is = PKCS7_ISSUER_AND_SERIAL_new();
    X509_NAME_set(&is->issuer, X509_get_issuer_name(cert));
    M_ASN1_INTEGER_free(is->serial);
    is->serial = M_ASN1_INTEGER_dup(X509_get_serialNumber(cert));
    len = i2d_PKCS7_ISSUER_AND_SERIAL(is, NULL);
    if ((p = *out = (unsigned char *)malloc((size_t) len)) == NULL)
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

static int
pkcs7_decrypt(krb5_context context,
	      pkinit_identity_crypto_context id_cryptoctx,
	      PKCS7 *p7,
	      BIO *data)
{
    BIO *tmpmem = NULL;
    int retval = 0, i = 0;
    char buf[4096];

    if(p7 == NULL)
	return 0;

    if(!PKCS7_type_is_enveloped(p7)) {
	pkiDebug("wrong pkcs7 content type\n");
	return 0;
    }

    if(!(tmpmem = pkcs7_dataDecode(context, id_cryptoctx, p7))) {
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

krb5_error_code
pkinit_process_td_trusted_certifiers(
    krb5_context context,
    pkinit_plg_crypto_context plg_cryptoctx,
    pkinit_req_crypto_context req_cryptoctx,
    pkinit_identity_crypto_context id_cryptoctx,
    krb5_external_principal_identifier **krb5_trusted_certifiers,
    int td_type)
{
    krb5_error_code retval = ENOMEM;
    STACK_OF(X509_NAME) *sk_xn = NULL;
    X509_NAME *xn = NULL;
    PKCS7_ISSUER_AND_SERIAL *is = NULL;
    ASN1_OCTET_STRING *id = NULL;
    const unsigned char *p = NULL;
    char buf[256];
    int i = 0;

    if (td_type == TD_TRUSTED_CERTIFIERS)
	pkiDebug("received trusted certifiers\n");
    else
	pkiDebug("received invalid certificate\n");

    sk_xn = sk_X509_NAME_new_null();
    while(krb5_trusted_certifiers[i] != NULL) {
	if (krb5_trusted_certifiers[i]->subjectName.data != NULL) {
	    p = krb5_trusted_certifiers[i]->subjectName.data;
	    xn = d2i_X509_NAME(NULL, &p,
		krb5_trusted_certifiers[i]->subjectName.length);
	    if (xn == NULL)
		goto cleanup;
	    X509_NAME_oneline(xn, buf, 256);
	    if (td_type == TD_TRUSTED_CERTIFIERS)
		pkiDebug("#%d cert = %s is trusted by kdc\n", i, buf);
	    else
		pkiDebug("#%d cert = %s is invalid\n", i, buf);
		sk_X509_NAME_push(sk_xn, xn);
	}

	if (krb5_trusted_certifiers[i]->issuerAndSerialNumber.data != NULL) {
	    p = krb5_trusted_certifiers[i]->issuerAndSerialNumber.data;
	    is = d2i_PKCS7_ISSUER_AND_SERIAL(NULL, &p,
		krb5_trusted_certifiers[i]->issuerAndSerialNumber.length);
	    if (is == NULL)
		goto cleanup;
	    X509_NAME_oneline(is->issuer, buf, 256);
	    if (td_type == TD_TRUSTED_CERTIFIERS)
		pkiDebug("#%d issuer = %s serial = %ld is trusted bu kdc\n", i,
			 buf, ASN1_INTEGER_get(is->serial));
	    else
		pkiDebug("#%d issuer = %s serial = %ld is invalid\n", i, buf,
			 ASN1_INTEGER_get(is->serial));
	    PKCS7_ISSUER_AND_SERIAL_free(is);
	}

	if (krb5_trusted_certifiers[i]->subjectKeyIdentifier.data != NULL) {
	    p = krb5_trusted_certifiers[i]->subjectKeyIdentifier.data;
	    id = d2i_ASN1_OCTET_STRING(NULL, &p,
		krb5_trusted_certifiers[i]->subjectKeyIdentifier.length);
	    if (id == NULL)
		goto cleanup;
	    /* XXX */
	    ASN1_OCTET_STRING_free(id);
	}
	i++;
    }
    /* XXX Since we not doing anything with received trusted certifiers
     * return an error. this is the place where we can pick a different
     * client certificate based on the information in td_trusted_certifiers
     */
    retval = KRB5KDC_ERR_PREAUTH_FAILED;
cleanup:
    if (sk_xn != NULL)
	sk_X509_NAME_pop_free(sk_xn, X509_NAME_free);

    return retval;
}

static BIO *
pkcs7_dataDecode(krb5_context context,
		 pkinit_identity_crypto_context id_cryptoctx,
		 PKCS7 *p7)
{
    int i = 0, jj = 0, tmp_len = 0;
    BIO *out=NULL,*etmp=NULL,*bio=NULL;
    unsigned char *tmp=NULL;
    ASN1_OCTET_STRING *data_body=NULL;
    const EVP_CIPHER *evp_cipher=NULL;
    EVP_CIPHER_CTX *evp_ctx=NULL;
    X509_ALGOR *enc_alg=NULL;
    STACK_OF(PKCS7_RECIP_INFO) *rsk=NULL;
    X509_ALGOR *xalg=NULL;
    PKCS7_RECIP_INFO *ri=NULL;
    X509 *cert = sk_X509_value(id_cryptoctx->my_certs,
	id_cryptoctx->cert_index);

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

    if (cert) {
	for (i=0; i<sk_PKCS7_RECIP_INFO_num(rsk); i++) {
	    int tmp_ret = 0;
	    ri=sk_PKCS7_RECIP_INFO_value(rsk,i);
	    tmp_ret = X509_NAME_cmp(ri->issuer_and_serial->issuer,
				    cert->cert_info->issuer);
	    if (!tmp_ret) {
		tmp_ret = M_ASN1_INTEGER_cmp(cert->cert_info->serialNumber,
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

    if (cert == NULL) {
	for (i=0; i<sk_PKCS7_RECIP_INFO_num(rsk); i++) {
	    ri=sk_PKCS7_RECIP_INFO_value(rsk,i);
	    jj = pkinit_decode_data(context, id_cryptoctx,
		M_ASN1_STRING_data(ri->enc_key),
		M_ASN1_STRING_length(ri->enc_key), &tmp, &tmp_len);
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
	jj = pkinit_decode_data(context, id_cryptoctx,
	    M_ASN1_STRING_data(ri->enc_key), M_ASN1_STRING_length(ri->enc_key),
	    &tmp, &tmp_len);
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
get_filename(char **name, char *env_name, int type)
{
    char *ev;

    if ((*name = (char *) malloc(1024)) == NULL)
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
void
print_dh(DH * dh, unsigned char *msg)
{
    BIO *bio_err = NULL;

    bio_err = BIO_new(BIO_s_file());
    BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (msg)
	BIO_puts(bio_err, (const char *)msg);
    if (dh)
	DHparams_print(bio_err, dh);

    BN_print(bio_err, dh->q);
    BIO_puts(bio_err, (const char *)"\n");
    BIO_free(bio_err);

}

void
print_pubkey(BIGNUM * key, unsigned char *msg)
{
    BIO *bio_err = NULL;

    bio_err = BIO_new(BIO_s_file());
    BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (msg)
	BIO_puts(bio_err, (const char *)msg);
    if (key)
	BN_print(bio_err, key);
    BIO_puts(bio_err, "\n");

    BIO_free(bio_err);

}

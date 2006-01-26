/*
 * lib/krb4/prot_common.c
 *
 * Copyright 2001 by the Massachusetts Institute of Technology.  All
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
 * Contains some common code used by multiple encoders/decoders.
 */

#include "krb.h"
#include "prot.h"
#include <string.h>

/*
 * encode_naminstrlm
 *
 * Takes input string triplet of a principal, encodes into PKT.
 * Assumes that input strings are properly terminated.  If CHKLEN is
 * non-zero, validate input string lengths against their respective
 * limits.  The pointer P is the address of the moving pointer used by
 * the caller, and is updated here.
 *
 * Returns zero on success, non-zero on failure.
 *
 * PKT->LENGTH is NOT updated.  The caller must update it.
 */
int KRB5_CALLCONV
krb4prot_encode_naminstrlm(char *name, char *inst, char *realm,
			   int chklen, /* check input str len? */
			   KTEXT pkt, /* buffer to encode into */
			   unsigned char **p /* moving pointer */)
{
    size_t namelen, instlen, realmlen;

    namelen = strlen(name) + 1;
    instlen = strlen(inst) + 1;
    realmlen = strlen(realm) + 1;
    if (chklen && (namelen > ANAME_SZ || instlen > INST_SZ
		   || realmlen > REALM_SZ))
	return KRB4PROT_ERR_OVERRUN;
    if (*p - pkt->dat < namelen + instlen + realmlen)
	return KRB4PROT_ERR_OVERRUN;
    memcpy(*p, name, namelen);
    *p += namelen;
    memcpy(*p, inst, instlen);
    *p += namelen;
    memcpy(*p, realm, realmlen);
    *p += namelen;
    return KRB4PROT_OK;
}

/*
 * decode_naminstrlm
 *
 * Grabs a string triplet corresponding to a principal.  The input
 * buffer PKT should have its length properly set.  The pointer P is
 * the address of the moving pointer used by the caller, and will be
 * updated.  If any input pointer is NULL, merely skip the string.
 *
 * The output strings NAME, INST, and REALM are assumed to be of the
 * correct sizes (ANAME_SZ, INST_SZ, REALM_SZ).
 *
 * Returns 0 on success, non-zero on failure.
 */
int KRB5_CALLCONV
krb4prot_decode_naminstrlm(KTEXT pkt, /* buffer to decode from */
			   unsigned char **p, /* moving pointer */
			   char *name, char *inst, char *realm)
{
    int len;

#define PKT_REMAIN (pkt->length - (*p - pkt->dat))
    if (PKT_REMAIN <= 0)
	return KRB4PROT_ERR_UNDERRUN;
    len = krb4int_strnlen((char *)*p, PKT_REMAIN) + 1;
    if (len == 0 || len > ANAME_SZ)
	return KRB4PROT_ERR_OVERRUN;
    if (name != NULL)
	memcpy(name, *p, (size_t)len);
    *p += len;

    if (PKT_REMAIN <= 0)
	return KRB4PROT_ERR_UNDERRUN;
    len = krb4int_strnlen((char *)*p, PKT_REMAIN) + 1;
    if (len <= 0 || len > INST_SZ)
	return KRB4PROT_ERR_OVERRUN;
    if (name != NULL)
	memcpy(inst, *p, (size_t)len);
    *p += len;

    if (PKT_REMAIN <= 0)
	return KRB4PROT_ERR_UNDERRUN;
    len = krb4int_strnlen((char *)*p, PKT_REMAIN) + 1;
    if (len <= 0 || len > REALM_SZ)
	return KRB4PROT_ERR_OVERRUN;
    if (realm != NULL)
	memcpy(realm, *p, (size_t)len);
    *p += len;
    return KRB4PROT_OK;
#undef PKT_REMAIN
}

int KRB5_CALLCONV
krb4prot_decode_header(KTEXT pkt,
		       int *pver, int *msgtype, int *le)
{
    unsigned char *p;

    p = pkt->dat;
    if (pkt->length < 2)
	return KRB4PROT_ERR_UNDERRUN;
    *pver = *p++;
    *msgtype = *p++;
    *le = *msgtype & 1;
    *msgtype &= ~1;
    return KRB4PROT_OK;
}

/*
 * lib/krb4/decomp_tkt.c
 *
 * Copyright 1985, 1986, 1987, 1988, 2000, 2001 by the Massachusetts
 * Institute of Technology.  All Rights Reserved.
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
 */

#include "des.h"
#include "krb.h"
#include "prot.h"
#include <string.h>
#include <krb5.h>
#include "krb54proto.h"
#include "port-sockets.h"

#ifdef KRB_CRYPT_DEBUG
extern int krb_debug;
#endif

static int dcmp_tkt_int (KTEXT tkt, unsigned char *flags, 
				   char *pname, char *pinstance, char *prealm,
				   unsigned KRB4_32 *paddress, C_Block session,
				   int *life, unsigned KRB4_32 *time_sec, 
				   char *sname, char *sinstance, C_Block key, 
				   Key_schedule key_s, krb5_keyblock *k5key);
/*
 * This routine takes a ticket and pointers to the variables that
 * should be filled in based on the information in the ticket.  It
#ifndef NOENCRYPTION
 * decrypts the ticket using the given key, and 
#endif
 * fills in values for its arguments.
 *
 * Note: if the client realm field in the ticket is the null string,
 * then the "prealm" variable is filled in with the local realm (as
 * defined by KRB_REALM).
 *
 * If the ticket byte order is different than the host's byte order
 * (as indicated by the byte order bit of the "flags" field), then
 * the KDC timestamp "time_sec" is byte-swapped.  The other fields
 * potentially affected by byte order, "paddress" and "session" are
 * not byte-swapped.
 *
 * The routine returns KFAILURE if any of the "pname", "pinstance",
 * or "prealm" fields is too big, otherwise it returns KSUCCESS.
 *
 * The corresponding routine to generate tickets is create_ticket.
 * When changes are made to this routine, the corresponding changes
 * should also be made to that file.
 *
 * See create_ticket.c for the format of the ticket packet.
 */

int KRB5_CALLCONV		/* XXX should this be exported on win32? */
decomp_ticket(tkt, flags, pname, pinstance, prealm, paddress, session,
              life, time_sec, sname, sinstance, key, key_s)
    KTEXT tkt;			/* The ticket to be decoded */
    unsigned char *flags;       /* Kerberos ticket flags */
    char *pname;		/* Authentication name */
    char *pinstance;		/* Principal's instance */
    char *prealm;		/* Principal's authentication domain */
    unsigned KRB4_32 *paddress; /* Net address of entity
                                 * requesting ticket */
    C_Block session;		/* Session key inserted in ticket */
    int *life; 		        /* Lifetime of the ticket */
    unsigned KRB4_32 *time_sec; /* Issue time and date */
    char *sname;		/* Service name */
    char *sinstance;		/* Service instance */
    C_Block key;		/* Service's secret key
                                 * (to decrypt the ticket) */
    Key_schedule key_s;		/* The precomputed key schedule */
{
    return
	dcmp_tkt_int(tkt, flags, pname, pinstance, prealm,
		     paddress, session, life, time_sec, sname, sinstance,
		     key, key_s, NULL);
}

int
decomp_tkt_krb5(tkt, flags, pname, pinstance, prealm, paddress, session,
              life, time_sec, sname, sinstance, k5key)
    KTEXT tkt;			/* The ticket to be decoded */
    unsigned char *flags;       /* Kerberos ticket flags */
    char *pname;		/* Authentication name */
    char *pinstance;		/* Principal's instance */
    char *prealm;		/* Principal's authentication domain */
    unsigned KRB4_32 *paddress; /* Net address of entity
                                 * requesting ticket */
    C_Block session;		/* Session key inserted in ticket */
    int *life; 		        /* Lifetime of the ticket */
    unsigned KRB4_32 *time_sec; /* Issue time and date */
    char *sname;		/* Service name */
    char *sinstance;		/* Service instance */
    krb5_keyblock *k5key;	/* krb5 keyblock of service */
{
    C_Block key;		/* placeholder; doesn't get used */
    Key_schedule key_s;		/* placeholder; doesn't get used */

    return
	dcmp_tkt_int(tkt, flags, pname, pinstance, prealm, paddress, session,
		     life, time_sec, sname, sinstance, key, key_s, k5key);
}

static int
dcmp_tkt_int(tkt, flags, pname, pinstance, prealm, paddress, session,
              life, time_sec, sname, sinstance, key, key_s, k5key)
    KTEXT tkt;			/* The ticket to be decoded */
    unsigned char *flags;       /* Kerberos ticket flags */
    char *pname;		/* Authentication name */
    char *pinstance;		/* Principal's instance */
    char *prealm;		/* Principal's authentication domain */
    unsigned KRB4_32 *paddress; /* Net address of entity
                                 * requesting ticket */
    C_Block session;		/* Session key inserted in ticket */
    int *life; 		        /* Lifetime of the ticket */
    unsigned KRB4_32 *time_sec; /* Issue time and date */
    char *sname;		/* Service name */
    char *sinstance;		/* Service instance */
    C_Block key;		/* Service's secret key
                                 * (to decrypt the ticket) */
    Key_schedule key_s;		/* The precomputed key schedule */
    krb5_keyblock *k5key;	/* krb5 keyblock of service */
{
    int tkt_le;			/* little-endian ticket? */
    unsigned char *ptr = tkt->dat;
    int kret, len;
    struct in_addr paddr;

    /* Be really paranoid. */
    if (sizeof(paddr.s_addr) != 4)
	return KFAILURE;

#ifndef NOENCRYPTION
    /* Do the decryption */
#ifdef KRB_CRYPT_DEBUG
    if (krb_debug) {
	FILE *fp;
	char *keybuf[BUFSIZ];	/* Avoid secret stuff in stdio buffers */

	fp = fopen("/kerberos/tkt.des", "wb");
	setbuf(fp, keybuf);
	fwrite(tkt->dat, 1, tkt->length, fp);
	fclose(fp);
	memset(keybuf, 0, sizeof(keybuf));	/* Clear the buffer */
    }
#endif
    if (k5key != NULL) {
	/* block locals */
	krb5_enc_data in;
	krb5_data out;
	krb5_error_code ret;

	in.enctype = k5key->enctype;
	in.kvno = 0;
	in.ciphertext.length = tkt->length;
	in.ciphertext.data = (char *)tkt->dat;
	out.length = tkt->length;
	out.data = malloc((size_t)tkt->length);
	if (out.data == NULL)
	    return KFAILURE;	/* XXX maybe ENOMEM? */

	/* XXX note the following assumes that context arg isn't used  */
	ret =
	    krb5_c_decrypt(NULL, k5key,
			   KRB5_KEYUSAGE_KDC_REP_TICKET, NULL, &in, &out);
	if (ret) {
	    free(out.data);
	    return KFAILURE;
	} else {
	    memcpy(tkt->dat, out.data, out.length);
	    memset(out.data, 0, out.length);
	    free(out.data);
	}
    } else {
	pcbc_encrypt((C_Block *)tkt->dat, (C_Block *)tkt->dat,
		     (long)tkt->length, key_s, (C_Block *)key, 0);
    }
#endif /* ! NOENCRYPTION */
#ifdef KRB_CRYPT_DEBUG
    if (krb_debug) {
	FILE *fp;
	char *keybuf[BUFSIZ];	/* Avoid secret stuff in stdio buffers */

	fp = fopen("/kerberos/tkt.clear", "wb");
	setbuf(fp, keybuf);
	fwrite(tkt->dat, 1, tkt->length, fp);
	fclose(fp);
	memset(keybuf, 0, sizeof(keybuf));	/* Clear the buffer */
    }
#endif

#define TKT_REMAIN (tkt->length - (ptr - tkt->dat))
    kret = KFAILURE;
    if (TKT_REMAIN < 1)
	goto cleanup;
    *flags = *ptr++;
    tkt_le = (*flags >> K_FLAG_ORDER) & 1;

    len = krb4int_strnlen((char *)ptr, TKT_REMAIN) + 1;
    if (len <= 0 || len > ANAME_SZ)
	goto cleanup;
    memcpy(pname, ptr, (size_t)len);
    ptr += len;

    len = krb4int_strnlen((char *)ptr, TKT_REMAIN) + 1;
    if (len <= 0 || len > INST_SZ)
	goto cleanup;
    memcpy(pinstance, ptr, (size_t)len);
    ptr += len;

    len = krb4int_strnlen((char *)ptr, TKT_REMAIN) + 1;
    if (len <= 0 || len > REALM_SZ)
	goto cleanup;
    memcpy(prealm, ptr, (size_t)len);
    ptr += len;

    /*
     * This hack may be needed for some really krb4 servers, such as
     * AFS kaserver (?), that fail to fill in the realm of a ticket
     * under some circumstances.
     */
    if (*prealm == '\0')
	krb_get_lrealm(prealm, 1);

    /*
     * Ensure there's enough remaining in the ticket to get the
     * fixed-size stuff.
     */
    if (TKT_REMAIN < 4 + 8 + 1 + 4)
	goto cleanup;

    memcpy(&paddr.s_addr, ptr, sizeof(paddr.s_addr));
    ptr += sizeof(paddr.s_addr);
    *paddress = paddr.s_addr;

    memcpy(session, ptr, 8); /* session key */
    memset(ptr, 0, 8);
    ptr += 8;
#ifdef notdef /* DONT SWAP SESSION KEY spm 10/22/86 */
    if (tkt_swap_bytes)
        swap_C_Block(session);
#endif

    *life = *ptr++;

    KRB4_GET32(*time_sec, ptr, tkt_le);

    len = krb4int_strnlen((char *)ptr, TKT_REMAIN) + 1;
    if (len <= 0 || len > SNAME_SZ)
	goto cleanup;
    memcpy(sname, ptr, (size_t)len);
    ptr += len;

    len = krb4int_strnlen((char *)ptr, TKT_REMAIN) + 1;
    if (len <= 0 || len > INST_SZ)
	goto cleanup;
    memcpy(sinstance, ptr, (size_t)len);
    ptr += len;
    kret = KSUCCESS;

#ifdef KRB_CRYPT_DEBUG
    if (krb_debug) {
	krb_log("service=%s.%s len(sname)=%d, len(sinstance)=%d",
		sname, sinstance, strlen(sname), strlen(sinstance));
	krb_log("ptr - tkt->dat=%d",(char *)ptr - (char *)tkt->dat);
    }
#endif

cleanup:
    if (kret != KSUCCESS) {
	memset(session, 0, sizeof(session));
	memset(tkt->dat, 0, (size_t)tkt->length);
	return kret;
    }
    return KSUCCESS;
}

/*
 * lib/krb4/cr_ciph.c
 *
 * Copyright 1986, 1987, 1988, 2000 by the Massachusetts Institute of
 * Technology.  All Rights Reserved.
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

#include "krb.h"
#include "prot.h"
#include "des.h"
#include <string.h>

/*
 * This routine is used by the authentication server to create
 * a packet for its client, containing a ticket for the requested
 * service (given in "tkt"), and some information about the ticket,
#ifndef NOENCRYPTION
 * all encrypted in the given key ("key").
#endif
 *
 * Returns KSUCCESS no matter what.
 *
 * The length of the cipher is stored in c->length; the format of
 * c->dat is as follows:
 *
 * 			variable
 * type			or constant	   data
 * ----			-----------	   ----
 * 
 * 
 * 8 bytes		session		session key for client, service
 * 
 * string		service		service name
 * 
 * string		instance	service instance
 * 
 * string		realm		KDC realm
 * 
 * unsigned char	life		ticket lifetime
 * 
 * unsigned char	kvno		service key version number
 * 
 * unsigned char	tkt->length	length of following ticket
 * 
 * data			tkt->dat	ticket for service
 * 
 * 4 bytes		kdc_time	KDC's timestamp
 *
 * <=7 bytes		null		   null pad to 8 byte multiple
 *
 */

int
create_ciph(c, session, service, instance, realm, life, kvno, tkt,
	    kdc_time, key)
    KTEXT           c;		/* Text block to hold ciphertext */
    C_Block         session;	/* Session key to send to user */
    char            *service;	/* Service name on ticket */
    char            *instance;	/* Instance name on ticket */
    char            *realm;	/* Realm of this KDC */
    unsigned long   life;	/* Lifetime of the ticket */
    int             kvno;	/* Key version number for service */
    KTEXT           tkt;	/* The ticket for the service */
    unsigned long   kdc_time;	/* KDC time */
    C_Block         key;	/* Key to encrypt ciphertext with */
{
    unsigned char   *ptr;
    size_t          servicelen, instancelen, realmlen;
    Key_schedule    key_s;

    ptr = c->dat;

    /* Validate lengths. */
    servicelen = strlen(service) + 1;
    instancelen = strlen(instance) + 1;
    realmlen = strlen(realm) + 1;
    if (sizeof(c->dat) / 8 < ((8 + servicelen + instancelen + realmlen
			       + 1 + 1 + 1 + tkt->length
			       + 4 + 7) / 8)
	|| tkt->length > 255 || tkt->length < 0) {
        c->length = 0;
        return KFAILURE;
    }

    memcpy(ptr, session, 8);
    ptr += 8;

    memcpy(ptr, service, servicelen);
    ptr += servicelen;
    memcpy(ptr, instance, instancelen);
    ptr += instancelen;
    memcpy(ptr, realm, realmlen);
    ptr += realmlen;

    *ptr++ = life;
    *ptr++ = kvno;
    *ptr++ = tkt->length;

    memcpy(ptr, tkt->dat, (size_t)tkt->length);
    ptr += tkt->length;

    KRB4_PUT32BE(ptr, kdc_time);

    /* guarantee null padded encrypted data to multiple of 8 bytes */
    memset(ptr, 0, 7);

    c->length = (((ptr - c->dat) + 7) / 8) * 8;

#ifndef NOENCRYPTION
    key_sched(key, key_s);
    pcbc_encrypt((C_Block *)c->dat, (C_Block *)c->dat,
		 (long)c->length, key_s, (C_Block*)key, ENCRYPT);
    memset(key_s, 0, sizeof(key_s));
#endif /* NOENCRYPTION */

    return KSUCCESS;
}

/*
 * cr_ciph.c
 *
 * Copyright 1986, 1987, 1988 by the Massachusetts Institute
 * of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

#include "mit-copyright.h"
#include "krb.h"
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
    char            *ptr;
    Key_schedule    key_s;

    ptr = (char *) c->dat;

    if(sizeof(c->dat) / 8 < (8 +
		             strlen(service) + 1 +
		             strlen(instance) + 1 +
		             strlen(realm) + 1 +
			     1 + 1 + 1 +
			     tkt->length + 4 +
			     7) / 8) {
        c->length = 0;
        return(KFAILURE);
    }

    memcpy(ptr, (char *) session, 8);
    ptr += 8;

    (void) strcpy(ptr,service);
    ptr += strlen(service) + 1;

    (void) strcpy(ptr,instance);
    ptr += strlen(instance) + 1;

    (void) strcpy(ptr,realm);
    ptr += strlen(realm) + 1;

    *(ptr++) = (unsigned char) life;
    *(ptr++) = (unsigned char) kvno;
    *(ptr++) = (unsigned char) tkt->length;

    memcpy(ptr, (char *)(tkt->dat), tkt->length);
    ptr += tkt->length;

    memcpy(ptr, (char *) &kdc_time, 4);
    ptr += 4;

    /* guarantee null padded encrypted data to multiple of 8 bytes */
    memset(ptr, 0, 7);

    c->length = (((ptr - (char *) c->dat) + 7) / 8) * 8;

#ifndef NOENCRYPTION
    key_sched(key,key_s);
    pcbc_encrypt((C_Block *)c->dat,(C_Block *)c->dat,
		 (long) c->length,key_s,(C_Block*) key,ENCRYPT);
#endif /* NOENCRYPTION */

    return(KSUCCESS);
}

/* 
 * cr_tkt.c
 *
 * Copyright 1985, 1986, 1987, 1988 by the Massachusetts Institute
 * of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

#include "mit-copyright.h"
#include "des.h"
#include "krb.h"
#include "prot.h"
#include <string.h>
#include <krb5.h>

/*
 * Create ticket takes as arguments information that should be in a
 * ticket, and the KTEXT object in which the ticket should be
 * constructed.  It then constructs a ticket and returns, leaving the
 * newly created ticket in tkt.
#ifndef NOENCRYPTION
 * The data in tkt->dat is encrypted in the server's key.
#endif
 * The length of the ticket is a multiple of
 * eight bytes and is in tkt->length.
 *
 * If the ticket is too long, the ticket will contain nulls.
 * The return value of the routine is undefined.
 *
 * The corresponding routine to extract information from a ticket it
 * decomp_ticket.  When changes are made to this routine, the
 * corresponding changes should also be made to that file.
 *
 * The packet is built in the following format:
 * 
 * 			variable
 * type			or constant	   data
 * ----			-----------	   ----
 *
 * tkt->length		length of ticket (multiple of 8 bytes)
 * 
#ifdef NOENCRYPTION
 * tkt->dat:
#else
 * tkt->dat:		(encrypted in server's key)
#endif
 * 
 * unsigned char	flags		   namely, HOST_BYTE_ORDER
 * 
 * string		pname		   client's name
 * 
 * string		pinstance	   client's instance
 * 
 * string		prealm		   client's realm
 * 
 * 4 bytes		paddress	   client's address
 * 
 * 8 bytes		session		   session key
 * 
 * 1 byte		life		   ticket lifetime
 * 
 * 4 bytes		time_sec	   KDC timestamp
 * 
 * string		sname		   service's name
 * 
 * string		sinstance	   service's instance
 * 
 * <=7 bytes		null		   null pad to 8 byte multiple
 *
 */
int
krb_create_ticket(tkt, flags, pname, pinstance, prealm, paddress,
		  session, life, time_sec, sname, sinstance, key, k5key)
    KTEXT   tkt;                /* Gets filled in by the ticket */
    unsigned char flags;        /* Various Kerberos flags */
    char    *pname;             /* Principal's name */
    char    *pinstance;         /* Principal's instance */
    char    *prealm;            /* Principal's authentication domain */
    long    paddress;           /* Net address of requesting entity */
    char    *session;           /* Session key inserted in ticket */
    short   life;               /* Lifetime of the ticket */
    long    time_sec;           /* Issue time and date */
    char    *sname;             /* Service Name */
    char    *sinstance;         /* Instance Name */
    C_Block key;                /* Service's secret key */
{
    return krb_cr_tkt_int(tkt, flags, pname, pinstance, prealm, paddress,
			  session, life, time_sec, sname, sinstance,
			  key, NULL);
}

int
krb_cr_tkt_krb5(tkt, flags, pname, pinstance, prealm, paddress,
		  session, life, time_sec, sname, sinstance, k5key)
    KTEXT   tkt;                /* Gets filled in by the ticket */
    unsigned char flags;        /* Various Kerberos flags */
    char    *pname;             /* Principal's name */
    char    *pinstance;         /* Principal's instance */
    char    *prealm;            /* Principal's authentication domain */
    long    paddress;           /* Net address of requesting entity */
    char    *session;           /* Session key inserted in ticket */
    short   life;               /* Lifetime of the ticket */
    long    time_sec;           /* Issue time and date */
    char    *sname;             /* Service Name */
    char    *sinstance;         /* Instance Name */
    krb5_keyblock *k5key;	/* NULL if not present */
{
    C_Block key;

    return krb_cr_tkt_int(tkt, flags, pname, pinstance, prealm, paddress,
			  session, life, time_sec, sname, sinstance,
			  key, k5key);
}

static int
krb_cr_tkt_int(tkt, flags, pname, pinstance, prealm, paddress,
	       session, life, time_sec, sname, sinstance, key, k5key)
    KTEXT   tkt;                /* Gets filled in by the ticket */
    unsigned char flags;        /* Various Kerberos flags */
    char    *pname;             /* Principal's name */
    char    *pinstance;         /* Principal's instance */
    char    *prealm;            /* Principal's authentication domain */
    long    paddress;           /* Net address of requesting entity */
    char    *session;           /* Session key inserted in ticket */
    short   life;               /* Lifetime of the ticket */
    long    time_sec;           /* Issue time and date */
    char    *sname;             /* Service Name */
    char    *sinstance;         /* Instance Name */
    C_Block key;                /* Service's secret key */
    krb5_keyblock *k5key;	/* NULL if not present */
{
    Key_schedule key_s;
    register char *data;        /* running index into ticket */

    tkt->length = 0;            /* Clear previous data  */
    flags |= HOST_BYTE_ORDER;   /* ticket byte order   */
    memcpy((char *) (tkt->dat), (char *) &flags, sizeof(flags));
    data = ((char *)tkt->dat) + sizeof(flags);
    (void) strcpy(data, pname);
    data += 1 + strlen(pname);
    (void) strcpy(data, pinstance);
    data += 1 + strlen(pinstance);
    (void) strcpy(data, prealm);
    data += 1 + strlen(prealm);
    memcpy(data, (char *) &paddress, 4);
    data += 4;

    memcpy(data, (char *) session, 8);
    data += 8;
    *(data++) = (char) life;
    /* issue time */
    memcpy(data, (char *) &time_sec, 4);
    data += 4;
    (void) strcpy(data, sname);
    data += 1 + strlen(sname);
    (void) strcpy(data, sinstance);
    data += 1 + strlen(sinstance);

    /* guarantee null padded ticket to multiple of 8 bytes */
    memset(data, 0, 7);
    tkt->length = ((data - ((char *)tkt->dat) + 7)/8)*8;

    /* Check length of ticket */
    if (tkt->length > (sizeof(KTEXT_ST) - 7)) {
        memset(tkt->dat, 0, tkt->length);
        tkt->length = 0;
        return KFAILURE /* XXX */;
    }

#ifndef NOENCRYPTION
    /* Encrypt the ticket in the services key */
    if (k5key != NULL) {
	/* block locals */
	krb5_data in;
	krb5_enc_data out;
	krb5_error_code ret;
	size_t enclen;

	in.length = tkt->length;
	in.data = tkt->dat;
	/* XXX assumes context arg is ignored */
	ret = krb5_c_encrypt_length(NULL, k5key->enctype,
				    (size_t)in.length, &enclen);
	if (ret)
	    return KFAILURE;
	out.ciphertext.length = enclen;
	out.ciphertext.data = malloc(enclen);
	if (out.ciphertext.data == NULL)
	    return KFAILURE;	/* XXX maybe ENOMEM? */

	/* XXX assumes context arg is ignored */
	ret = krb5_c_encrypt(NULL, k5key, KRB5_KEYUSAGE_KDC_REP_TICKET,
			     NULL, &in, &out);
	if (ret) {
	    free(out.ciphertext.data);
	    return KFAILURE;
	} else {
	    tkt->length = out.ciphertext.length;
	    memcpy(tkt->dat, out.ciphertext.data, out.ciphertext.length);
	    memset(out.ciphertext.data, 0, out.ciphertext.length);
	    free(out.ciphertext.data);
	}
    } else {
	key_sched(key,key_s);
	pcbc_encrypt((C_Block *)tkt->dat,(C_Block *)tkt->dat,
		     (long) tkt->length,key_s,(C_Block *)key,1);
    }
#endif /* !NOENCRYPTION */
    return 0;
}

/*
 * g_in_tkt.c
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
#include "prot.h"

#include <string.h>

extern int	swap_bytes;

/* Define a couple of function types including parameters.  These
   are needed on MS-Windows to convert arguments of the function pointers
   to the proper types during calls.  These declarations are found
   in <krb-sed.h>, but the code below is too opaque if you can't also
   see them here.  */
#ifndef	KEY_PROC_TYPE_DEFINED
typedef int (*key_proc_type) PROTOTYPE ((char *, char *, char *,
					     char *, C_Block));
#endif
#ifndef	DECRYPT_TKT_TYPE_DEFINED
typedef int (*decrypt_tkt_type) PROTOTYPE ((char *, char *, char *, char *,
				     key_proc_type, KTEXT *));
#endif

/*
 * decrypt_tkt(): Given user, instance, realm, passwd, key_proc
 * and the cipher text sent from the KDC, decrypt the cipher text
 * using the key returned by key_proc.
 */

static int
decrypt_tkt(user, instance, realm, arg, key_proc, cipp)
  char *user;
  char *instance;
  char *realm;
  char *arg;
  key_proc_type key_proc;
  KTEXT *cipp;
{
    KTEXT cip = *cipp;
    C_Block key;		/* Key for decrypting cipher */
    Key_schedule key_s;

#ifndef NOENCRYPTION
    /* Attempt to decrypt it */
#endif
    
    /* generate a key from the supplied arg or password.  */
    
    {
	register int rc;
	rc = (*key_proc) (user,instance,realm,arg,key);
	if (rc)
	    return(rc);
    }
    
#ifndef NOENCRYPTION
    key_sched(key,key_s);
    pcbc_encrypt((C_Block *)cip->dat,(C_Block *)cip->dat,
		 (long) cip->length,key_s,(C_Block *)key,0);
#endif /* !NOENCRYPTION */
    /* Get rid of all traces of key */
    memset((char *)key, 0,sizeof(key));
    memset((char *)key_s, 0,sizeof(key_s));

    return(0);
}

/*
 * krb_get_in_tkt() gets a ticket for a given principal to use a given
 * service and stores the returned ticket and session key for future
 * use.
 *
 * The "user", "instance", and "realm" arguments give the identity of
 * the client who will use the ticket.  The "service" and "sinstance"
 * arguments give the identity of the server that the client wishes
 * to use.  (The realm of the server is the same as the Kerberos server
 * to whom the request is sent.)  The "life" argument indicates the
 * desired lifetime of the ticket; the "key_proc" argument is a pointer
 * to the routine used for getting the client's private key to decrypt
 * the reply from Kerberos.  The "decrypt_proc" argument is a pointer
 * to the routine used to decrypt the reply from Kerberos; and "arg"
 * is an argument to be passed on to the "key_proc" routine.
 *
 * If all goes well, krb_get_in_tkt() returns INTK_OK, otherwise it
 * returns an error code:  If an AUTH_MSG_ERR_REPLY packet is returned
 * by Kerberos, then the error code it contains is returned.  Other
 * error codes returned by this routine include INTK_PROT to indicate
 * wrong protocol version, INTK_BADPW to indicate bad password (if
 * decrypted ticket didn't make sense), INTK_ERR if the ticket was for
 * the wrong server or the ticket store couldn't be initialized.
 *
 * The format of the message sent to Kerberos is as follows:
 *
 * Size			Variable		Field
 * ----			--------		-----
 *
 * 1 byte		KRB_PROT_VERSION	protocol version number
 * 1 byte		AUTH_MSG_KDC_REQUEST |	message type
 *			HOST_BYTE_ORDER		local byte order in lsb
 * string		user			client's name
 * string		instance		client's instance
 * string		realm			client's realm
 * 4 bytes		tlocal.tv_sec		timestamp in seconds
 * 1 byte		life			desired lifetime
 * string		service			service's name
 * string		sinstance		service's instance
 */

int
krb_mk_in_tkt_preauth(user, instance, realm, service, sinstance, life,
		      preauth_p, preauth_len, cip)
    char *user;
    char *instance;
    char *realm;
    char *service;
    char *sinstance;
    int life;
    char *preauth_p;
    int   preauth_len;
    KTEXT cip;
{
    KTEXT_ST pkt_st;
    KTEXT pkt = &pkt_st;	/* Packet to KDC */
    KTEXT_ST rpkt_st;
    KTEXT rpkt = &rpkt_st;	/* Returned packet */
    unsigned char *v = pkt->dat; /* Prot vers no */
    unsigned char *t = (pkt->dat+1); /* Prot msg type */

    int msg_byte_order;
    int kerror;
#if 0
    unsigned long exp_date;
#endif
    unsigned long rep_err_code;
    unsigned int t_switch;
    unsigned KRB4_32 t_local;	/* Must be 4 bytes long for memcpy below! */

    /* BUILD REQUEST PACKET */

    /* Set up the fixed part of the packet */
    *v = (unsigned char) KRB_PROT_VERSION;
    *t = (unsigned char) AUTH_MSG_KDC_REQUEST;
    *t |= HOST_BYTE_ORDER;

    /* Now for the variable info */
    (void) strcpy((char *)(pkt->dat+2),user); /* aname */
    pkt->length = 3 + strlen(user);
    (void) strcpy((char *)(pkt->dat+pkt->length),
		  instance);	/* instance */
    pkt->length += 1 + strlen(instance);
    (void) strcpy((char *)(pkt->dat+pkt->length),realm); /* realm */
    pkt->length += 1 + strlen(realm);

    /* timestamp */
    t_local = TIME_GMT_UNIXSEC;
    memcpy((char *)(pkt->dat+pkt->length), (char *)&t_local, 4);
    pkt->length += 4;

    *(pkt->dat+(pkt->length)++) = (char) life;
    (void) strcpy((char *)(pkt->dat+pkt->length),service);
    pkt->length += 1 + strlen(service);
    (void) strcpy((char *)(pkt->dat+pkt->length),sinstance);

    pkt->length += 1 + strlen(sinstance);

    if (preauth_len)
	memcpy((char *)(pkt->dat+pkt->length), preauth_p, preauth_len);
    pkt->length += preauth_len;

    rpkt->length = 0;

    /* SEND THE REQUEST AND RECEIVE THE RETURN PACKET */

    if (kerror = send_to_kdc(pkt, rpkt, realm)) return(kerror);

    /* check packet version of the returned packet */
    if (pkt_version(rpkt) != KRB_PROT_VERSION)
        return(INTK_PROT);

    /* Check byte order */
    msg_byte_order = pkt_msg_type(rpkt) & 1;
    swap_bytes = 0;
    if (msg_byte_order != HOST_BYTE_ORDER) {
        swap_bytes++;
    }

    /* This used to be
         switch (pkt_msg_type(rpkt) & ~1) {
       but SCO 3.2v4 cc compiled that incorrectly.  */
    t_switch = pkt_msg_type(rpkt);
    t_switch &= ~1;
    switch (t_switch) {
    case AUTH_MSG_KDC_REPLY:
        break;
    case AUTH_MSG_ERR_REPLY:
        memcpy((char *) &rep_err_code, pkt_err_code(rpkt), 4);
        if (swap_bytes) swap_u_long(rep_err_code);
        return((int)rep_err_code);
    default:
        return(INTK_PROT);
    }

    /* EXTRACT INFORMATION FROM RETURN PACKET */

#if 0
    /* not used */
    /* get the principal's expiration date */
    memcpy((char *) &exp_date, pkt_x_date(rpkt), sizeof(exp_date));
    if (swap_bytes) swap_u_long(exp_date);
#endif

    /* Extract the ciphertext */
    cip->length = pkt_clen(rpkt);       /* let clen do the swap */

    if ((cip->length < 0) || (cip->length > sizeof(cip->dat)))
	return(INTK_ERR);		/* no appropriate error code
					   currently defined for INTK_ */
    /* copy information from return packet into "cip" */
    memcpy((char *)(cip->dat), (char *) pkt_cipher(rpkt), cip->length);

    return INTK_OK;
}


int
krb_parse_in_tkt(user, instance, realm, service, sinstance, life, cip)
    char *user;
    char *instance;
    char *realm;
    char *service;
    char *sinstance;
    int life;
    KTEXT cip;
{
    char *ptr;
    C_Block ses;                /* Session key for tkt */
    int kvno;			/* Kvno for session key */
    char s_name[SNAME_SZ];
    char s_instance[INST_SZ];
    char rlm[REALM_SZ];
    KTEXT_ST tkt_st;
    KTEXT tkt = &tkt_st;	/* Current ticket */
    unsigned long kdc_time;   /* KDC time */
    unsigned KRB4_32 t_local;	/* Must be 4 bytes long for memcpy below! */
    KRB4_32 t_diff;	/* Difference between timestamps */
    int kerror;
    int lifetime;

    ptr = (char *) cip->dat;

    /* extract session key */
    memcpy((char *)ses, ptr, 8);
    ptr += 8;

    if ((strlen(ptr) + (ptr - (char *) cip->dat)) > cip->length)
	return(INTK_BADPW);

    /* extract server's name */
    (void) strncpy(s_name,ptr, sizeof(s_name)-1);
    s_name[sizeof(s_name)-1] = '\0';
    ptr += strlen(s_name) + 1;

    if ((strlen(ptr) + (ptr - (char *) cip->dat)) > cip->length)
	return(INTK_BADPW);

    /* extract server's instance */
    (void) strncpy(s_instance,ptr, sizeof(s_instance)-1);
    s_instance[sizeof(s_instance)-1] = '\0';
    ptr += strlen(s_instance) + 1;

    if ((strlen(ptr) + (ptr - (char *) cip->dat)) > cip->length)
	return(INTK_BADPW);

    /* extract server's realm */
    (void) strncpy(rlm,ptr, sizeof(rlm));
    rlm[sizeof(rlm)-1] = '\0';
    ptr += strlen(rlm) + 1;

    /* extract ticket lifetime, server key version, ticket length */
    /* be sure to avoid sign extension on lifetime! */
    lifetime = (unsigned char) ptr[0];
    kvno = (unsigned char) ptr[1];
    tkt->length = (unsigned char) ptr[2];
    ptr += 3;
    
    if ((tkt->length < 0) ||
	((tkt->length + (ptr - (char *) cip->dat)) > cip->length))
	return(INTK_BADPW);

    /* extract ticket itself */
    memcpy((char *)(tkt->dat), ptr, tkt->length);
    ptr += tkt->length;

    if (strcmp(s_name, service) || strcmp(s_instance, sinstance) ||
        strcmp(rlm, realm))	/* not what we asked for */
	return(INTK_ERR);	/* we need a better code here XXX */

    /* check KDC time stamp */
    memcpy((char *)&kdc_time, ptr, 4); /* Time (coarse) */
    if (swap_bytes) swap_u_long(kdc_time);

    ptr += 4;

    t_local = TIME_GMT_UNIXSEC;
    t_diff = t_local - kdc_time;
    if (t_diff < 0) t_diff = -t_diff;	/* Absolute value of difference */
    if (t_diff > CLOCK_SKEW) {
        return(RD_AP_TIME);		/* XXX should probably be better
					   code */
    }

    /* initialize ticket cache */
    if (in_tkt(user,instance) != KSUCCESS)
	return(INTK_ERR);

    /* stash ticket, session key, etc. for future use */
    if (kerror = krb_save_credentials(s_name, s_instance, rlm, ses,
				      lifetime, kvno, tkt, t_local))
	return(kerror);

    return(INTK_OK);
}

int
krb_get_in_tkt_preauth(user, instance, realm, service, sinstance, life,
		       key_proc, decrypt_proc, arg, preauth_p, preauth_len)
    char *user;
    char *instance;
    char *realm;
    char *service;
    char *sinstance;
    int life;
    key_proc_type key_proc;
    decrypt_tkt_type decrypt_proc;
    char *arg;
    char *preauth_p;
    int   preauth_len;
{
    KTEXT_ST cip_st;
    KTEXT cip = &cip_st;	/* Returned Ciphertext */
    int kerror;
    if (kerror = krb_mk_in_tkt_preauth(user, instance, realm, 
				       service, sinstance,
				       life, preauth_p, preauth_len, cip))
	return kerror;

    /* Attempt to decrypt the reply. */
    if (decrypt_proc == NULL)
	decrypt_tkt (user, instance, realm, arg, key_proc, &cip);
    else
	(*decrypt_proc)(user, instance, realm, arg, key_proc, &cip);
    
    return
	krb_parse_in_tkt(user, instance, realm, service, sinstance, 
			 life, cip);

}

int
krb_get_in_tkt(user, instance, realm, service, sinstance, life,
               key_proc, decrypt_proc, arg)
    char *user;
    char *instance;
    char *realm;
    char *service;
    char *sinstance;
    int life;
    key_proc_type key_proc;
    decrypt_tkt_type decrypt_proc;
    char *arg;
{
    return krb_get_in_tkt_preauth(user, instance, realm,
				  service, sinstance, life,
			   	  key_proc, decrypt_proc, arg, (char *)0, 0);

}


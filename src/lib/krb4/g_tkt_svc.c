/* 
 * g_tkt_svc.c
 *
 * Gets a ticket for a service.  Adopted from KClient.
 */

#include <string.h>
#include "krb.h"
#include "port-sockets.h"

/* FIXME -- this should probably be calling mk_auth nowadays.  */
#define	KRB_SENDAUTH_VERS "AUTHV0.1" 	/* MUST be KRB_SENDAUTH_VLEN chars */


static int
ParseFullName(name, instance, realm, fname)
	char *name;
	char *instance;
	char *realm;
	char *fname;
{
	int err;
	
	if (!*fname) return KNAME_FMT;					/* null names are not OK */
	*instance = '\0';
	err = kname_parse(name,instance,realm,fname);
	if (err) return err;
	if (!*name) return KNAME_FMT;					/* null names are not OK */
	if (!*realm) { 
		if ((err = krb_get_lrealm (realm, 1)))
			return err;
		if (!*realm) return KNAME_FMT;		/* FIXME -- should give better error */
	}
	return KSUCCESS;
}



static void
CopyTicket(dest, src, numBytes, version, includeVersion)
	char *dest;
	KTEXT src;
	unsigned long *numBytes;
	char *version;
	int includeVersion;
{
	unsigned long tkt_len;
	unsigned long nbytes = 0;
		
    /* first put version info into the buffer */
    if (includeVersion) {
		(void) strncpy(dest, KRB_SENDAUTH_VERS, KRB_SENDAUTH_VLEN);
		(void) strncpy(dest+KRB_SENDAUTH_VLEN, version, KRB_SENDAUTH_VLEN);
		nbytes = 2*KRB_SENDAUTH_VLEN;
	}
    
    /* put ticket length into buffer */
    tkt_len = htonl((unsigned long) src->length);
	(void) memcpy((char *)(dest+nbytes), (char *) &tkt_len, sizeof(tkt_len));
    nbytes += sizeof(tkt_len);

    /* put ticket into buffer */
    (void) memcpy ((char *)(dest+nbytes), (char *) src->dat, src->length);
    nbytes += src->length;
    
    *numBytes = nbytes;
}


static int
CredIsExpired( cr )
     CREDENTIALS *cr;
{
    KRB4_32 now;

    /* This routine is for use with clients only in order to determine
       if a credential is still good.
       Note: twice CLOCK_SKEW was added to age of ticket so that we could 
       be more sure that the ticket was good. 
       FIXME:  I think this is a bug -- should use the same algorithm
       everywhere to determine ticket expiration.   */

    now = TIME_GMT_UNIXSEC;	
    return now + 2 * CLOCK_SKEW > krb_life_to_time(cr->issue_date,
						   cr->lifetime);
}


/*
 * Gets a ticket and returns it to application in buf
	  -> service		Formal Kerberos name of service
	  -> buf		Buffer to receive ticket
	  -> checksum		checksum for this service
	 <-> buflen		length of ticket buffer (must be at least
					1258 bytes)
	 <-  sessionKey		for internal use
	 <-  schedule		for internal use

 * Result is:
 *   GC_NOTKT		if there is no matching TGT in the cache
 *   MK_AP_TGTEXP	if the matching TGT is expired
 * Other errors possible.  These could cause a dialogue with the user
 * to get a new TGT.
 */ 

int KRB5_CALLCONV
krb_get_ticket_for_service (serviceName, buf, buflen, checksum, sessionKey,
		schedule, version, includeVersion)
	char *serviceName;
	char *buf;
	unsigned KRB4_32 *buflen;
	int checksum;
	des_cblock sessionKey;
	Key_schedule schedule;
	char *version;
	int includeVersion;
{
	char service[SNAME_SZ];
	char instance[INST_SZ];
	char realm[REALM_SZ];
	int err;
	char lrealm[REALM_SZ];
	CREDENTIALS cr;
	
	service[0] = '\0';
	instance[0] = '\0';
	realm[0] = '\0';
	
	/* parse out service name */
	
	err = ParseFullName(service, instance, realm, serviceName);
	if (err)
		return err;

    if ((err = krb_get_tf_realm(TKT_FILE, lrealm)) != KSUCCESS)
		return(err);

 	/* Make sure we have an intial ticket for the user in this realm 
 	   Check local realm, not realm for service since krb_mk_req will
 	   get additional krbtgt if necessary. This is so that inter-realm
 	   works without asking for a password twice.
 	   FIXME gnu - I think this is a bug.  We should allow direct
 	   authentication to the desired realm, regardless of what the "local"
 	   realm is.   I fixed it.   FIXME -- not quite right.   */
 	err = krb_get_cred (KRB_TICKET_GRANTING_TICKET, realm, lrealm, &cr);
 	if (err) 
 		return err;

	err = CredIsExpired(&cr);
  	if (err)
  		return RD_AP_EXP;		/* Expired ticket */
	
	/* Get a ticket for the service */
	err = krb_mk_req(&(cr.ticket_st),service,instance,realm,checksum);
	if (err)
		return err;
	
	CopyTicket(buf, &(cr.ticket_st), buflen, version, includeVersion);
	
	/* get the session key for later use in deciphering the server response */
	err = krb_get_cred(service,instance,realm,&cr);
	if (err)
		return err;
	memcpy((char *)sessionKey, (char *)cr.session, sizeof(C_Block));
  	err = key_sched(sessionKey, schedule);
	if (err)
		return KFAILURE;		/* Bad DES key for some reason (FIXME better error) */
	
	else
		return KSUCCESS;
	
}



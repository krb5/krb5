/* 
 * mac_stubs.c
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * Macintosh oopserating system stub interface for Kerberos.
 * Applications call these routines, which then call the driver to do the work.
 */

#include "krb.h"
#include "krb_driver.h"	/* Mac driver interface */

#include <string.h>
#include <stddef.h>
#include <Files.h>
#include <Devices.h>

/* We export the driver reference under the name mac_stubs_kdriver,
   but for convenience throughout this code, we call it "kdriver",
   which was its name when it was static.  */
short mac_stubs_kdriver = 0;		/* .Kerberos driver ref */
#define	kdriver mac_stubs_kdriver

ParamBlockRec pb[1];
struct krbHiParmBlock khipb[1];
struct krbParmBlock klopb[1];

short lowcall (long cscode, krbParmBlock *klopb, short kdriver)
{
	short s;
	ParamBlockRec pb;
	
	memset (&pb, 0, sizeof(ParamBlockRec));
	*(long *)pb.cntrlParam.csParam = (long)klopb;
	pb.cntrlParam.ioCompletion = nil;
	pb.cntrlParam.ioCRefNum = kdriver;
	pb.cntrlParam.csCode = cscode;
	
	if (s = PBControl(&pb, false))
		return KFAILURE;
	if (s = pb.cntrlParam.ioResult)
		return -(s - cKrbKerberosErrBlock);	/* Restore krb err code from driver err */

	return KSUCCESS;
}


short hicall (long cscode, krbHiParmBlock *khipb, short kdriver)
{
	short s;
	ParamBlockRec pb;
	memset(&pb, 0, sizeof(ParamBlockRec));
	*(long *)pb.cntrlParam.csParam = (long)khipb;
	pb.cntrlParam.ioCompletion = nil;
	pb.cntrlParam.ioCRefNum = kdriver;

	pb.cntrlParam.csCode = cscode;
	if (s = PBControl(&pb, false))
		return KFAILURE;
	if (s = pb.cntrlParam.ioResult)
		return -(s - cKrbKerberosErrBlock);	/* Restore krb err code from driver err */

	return KSUCCESS;
}


int INTERFACE
krb_start_session (x)
	char *x;
{
	short s;
	
	/*
	 * Open the .Kerberos driver if not already open
	 */
	if (!kdriver) {
		s = OpenDriver("\p.Kerberos", &kdriver);
		if (s) {
			return KFAILURE;	/* Improve this error code */
		}
	}

	return KSUCCESS;
}


int INTERFACE
krb_end_session (x)
	char *x;
{
	short s;

#if 0 /* This driver doesn't want to be closed.  FIXME, is this OK? */
	if (kdriver) {
		s = CloseDriver(kdriver);
		if (s)
			return KFAILURE;
		kdriver = 0;
	}
#endif
	return KSUCCESS;
}


char * INTERFACE
krb_realmofhost (host)
	char *host;
{
	short s;
	ParamBlockRec pb;
	static char realm[REALM_SZ];

	memset(klopb, 0, sizeof(*klopb));
	klopb->host = host;
	klopb->uRealm = realm;
	
	/* FIXME jcm - no error handling for return value of lowcall in krb_realmofhost */
	s = lowcall (cKrbGetRealm , klopb, kdriver);

	return realm;
}

int INTERFACE
krb_get_lrealm (realm, n)
	char *realm;
	int n;
{
	short s;
	ParamBlockRec pb;

	if (n != 1)
		return KFAILURE;

	memset(klopb, 0, sizeof(*klopb));
	klopb->uRealm = realm;

	s = lowcall (cKrbGetLocalRealm, klopb, kdriver);
	return s;
		
}


int INTERFACE
kname_parse (name, instance, realm, fullname)
	char *name, *instance, *realm, *fullname;
{
	short s;
	ParamBlockRec pb;

	memset(klopb, 0, sizeof(*klopb));
	klopb->uName = name;
	klopb->uInstance = instance;
	klopb->uRealm = realm;
	klopb->fullname = fullname;

	s = lowcall (cKrbKnameParse, klopb, kdriver);
	return s;
}

const char* INTERFACE
krb_get_err_text (error_code)
	int error_code;
{
	short s;
	
	memset(klopb, 0, sizeof(*klopb));
	klopb->admin = error_code;	
	s = lowcall (cKrbGetErrText, klopb, kdriver);
	if (s != KSUCCESS)
		return "Error in get_err_text";	
	return klopb->uName;
}


int INTERFACE
krb_get_pw_in_tkt(user,instance,realm,service,sinstance,life,password)
    char *user, *instance, *realm, *service, *sinstance;
    int life;
    char *password;
{
	short s;
	
	memset(klopb, 0, sizeof(*klopb));
	klopb->uName = user;	
	klopb->uInstance = instance;
	klopb->uRealm = realm;
	klopb->sName = service;
	klopb->sInstance = sinstance;
	klopb->admin = life;
	klopb->fullname = password;
	
	s = lowcall (cKrbGetPwInTkt, klopb, kdriver);
	return s;
}


/* FIXME:  For now, we handle the preauth version exactly the same
   as the non-preauth.   */
krb_get_pw_in_tkt_preauth(user,instance,realm,service,sinstance,life,password)
    char *user, *instance, *realm, *service, *sinstance;
    int life;
    char *password;
{
	short s;
	
	memset(klopb, 0, sizeof(*klopb));
	klopb->uName = user;	
	klopb->uInstance = instance;
	klopb->uRealm = realm;
	klopb->sName = service;
	klopb->sInstance = sinstance;
	klopb->admin = life;
	klopb->fullname = password;
	
	s = lowcall (cKrbGetPwInTkt, klopb, kdriver);
	return s;
}



char* INTERFACE
krb_get_default_user (void)
{
	short s;
	static char return_name[MAX_K_NAME_SZ];
	
	memset(khipb, 0, sizeof(*khipb));
	khipb->user = return_name;
	s = hicall (cKrbGetUserName, khipb, kdriver);
	if (s != KSUCCESS)
		return 0;
	return return_name;
}


int INTERFACE
krb_set_default_user (uName)
	char* uName;
{
	short s;
	
	memset(khipb, 0, sizeof(*khipb));
	khipb->user = uName;
	s = hicall (cKrbSetUserName, khipb, kdriver);
	return s;
}

int INTERFACE
krb_get_cred (name, instance, realm, cr)
	char *name;
	char *instance;
	char *realm;
	CREDENTIALS *cr;
{
	short s;
	
	memset(klopb, 0, sizeof(*klopb));
	
	strcpy(cr->service, name);
	strcpy(cr->instance, instance);
	strcpy(cr->realm, realm);
	
	klopb->cred = cr;

	s = lowcall (cKrbGetCredentials, klopb, kdriver);
	return s;
}

int INTERFACE
krb_save_credentials (sname, sinstance, srealm, session, 
			lifetime, kvno,ticket, issue_date)
	char *sname;		/* service name */
	char *sinstance;	/* service instance */
	char *srealm;		/* service realm */
	C_Block session;	/* Session key */
	int lifetime;		/* Lifetime */
	int kvno;			/* Key version number */
    KTEXT ticket; 	    /* The ticket itself */
	long issue_date;	/* The issue time */
	
{
	short s;
	CREDENTIALS cr;
	
	strcpy(cr.service, sname);
	strcpy(cr.instance, sinstance);
	strcpy(cr.realm, srealm);
	memcpy(cr.session, session, sizeof(C_Block));
	cr.lifetime = lifetime;
	cr.kvno = kvno;
	cr.ticket_st = *ticket;
	cr.issue_date = issue_date;
	
	memset(klopb, 0, sizeof(*klopb));
	klopb->cred = &cr;

	s = lowcall (cKrbAddCredentials, klopb, kdriver);
	return s;
}


int INTERFACE
krb_delete_cred (sname, sinstance, srealm)
	char *sname;
	char *sinstance;
	char *srealm;
{
	short s;
	
	memset(klopb, 0, sizeof(*klopb));
	
	klopb->sName = sname;
	klopb->sInstance = sinstance;
	klopb->sRealm = srealm;
	
	s = lowcall (cKrbDeleteCredentials, klopb, kdriver);
	return s;
}

int INTERFACE
dest_tkt (cachename)
	char *cachename;		/* This parameter is ignored. */
{
	short s;
	
	memset(klopb, 0, sizeof(*klopb));
	s = lowcall (cKrbDeleteAllSessions, klopb, kdriver);
	return s;
}

/* 
 *	returns service name, service instance and realm of the nth credential. 
 *  credential numbering is 1 based.
 */

int INTERFACE
krb_get_nth_cred (sname, sinstance, srealm, n)
	char *sname;
	char *sinstance;
	char *srealm;
	int n;
{
	short s;
	
	memset(klopb, 0, sizeof(*klopb));
	
	klopb->sName = sname;
	klopb->sInstance = sinstance;
	klopb->sRealm = srealm;
	klopb->itemNumber = &n;
	
	s = lowcall (cKrbGetNthCredentials, klopb, kdriver);
	return s;
}

/*
 * Return the number of credentials in the current credential cache (ticket cache).
 * On error, returns -1. 
 */
int INTERFACE
krb_get_num_cred ()
{
	int s;
	int n;
	
	memset(klopb, 0, sizeof(*klopb));
	klopb->itemNumber = &n;
	
	s = lowcall (cKrbGetNumCredentials, klopb, kdriver);
	if (s) 
		return -1;
	return *(klopb->itemNumber);
}



/* GetNthRealmMap
   yields the Nth mapping of a net or host to a Kerberos realm 
	  -> itemNumber 	which mapping, traditionally the first
	  -> host	   		host or net
	  -> uRealm    		pointer to buffer that will receive realm name
*/

OSErr INTERFACE
GetNthRealmMap(n, netorhost, realm)
	int n;
	char *netorhost;
	char *realm;
{
	int s;
	memset(klopb, 0, sizeof(*klopb));
	klopb->itemNumber = &n;
	klopb->host = netorhost;
	klopb->uRealm = realm;
	
	s = lowcall (cKrbGetNthRealmMap, klopb, kdriver);
	return s;
}

/* GetNthServerMap
   yields Nth realm-server mapping
   -> itemNumber		which mapping should be returned
   -> uRealm			pointer to buffer that will receive realm name	
   -> host				pointer to buffer that will receive server name
   -> admin				pointer to admin flag
 */
	
OSErr	INTERFACE
GetNthServerMap(n, realm, server, admin)	
    int n;
    char *realm;
    char *server; 
    int *admin;
{
	int s;
	memset(klopb, 0, sizeof(*klopb));
	klopb->itemNumber = &n;
	klopb->uRealm = realm;
	klopb->host = server;
	klopb->adminReturn = admin;

	s = lowcall (cKrbGetNthServerMap, klopb, kdriver);
	return s;
}



/* krb_get_ticket_for_service
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

int INTERFACE
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
	short s;

	if (includeVersion)
		return KFAILURE;		/* Not implmented in the kclient driver iface */
	
	memset(khipb, 0, sizeof(*khipb));
	khipb->service = serviceName;
	khipb->buf = buf;
	khipb->buflen = *buflen;
	khipb->checksum = checksum;

	s = hicall (cKrbGetTicketForService, khipb, kdriver);
	/* These are ARRAYS in the hiparmblock, for some reason! */
	memcpy (sessionKey, khipb->sessionKey, sizeof (khipb[0].sessionKey));
	memcpy (schedule,   khipb->schedule,   sizeof (khipb[0].schedule));
	*buflen = khipb->buflen;
	return s;
}


/* 	krb_get_tf_fullname -- return name, instance and realm of the
	principal in the current ticket file. The ticket file name is not 
	currently used for anything since there is only one credentials 
	cache/ticket file
*/

int INTERFACE
krb_get_tf_fullname (tktfile, name, instance, realm)
  char *tktfile;
  char *name;
  char *instance;
  char *realm;

{
	short s;
	memset (klopb, 0, sizeof(*klopb));
	klopb->fullname = tktfile;
	klopb->uName = name;
	klopb->uInstance = instance;
	klopb->uRealm = realm;
	
	s = lowcall (cKrbGetTfFullname, klopb, kdriver);
	return s;
}



#if 0
	xbzero(khipb, sizeof(krbHiParmBlock));
	khipb->service = (char *)cannon;
	khipb->buf = (char *)buf;				/* where to build it */
	khipb->checksum = 0;
	khipb->buflen = sizeof(buf);
	if (s = hicall(cKrbGetTicketForService, khipb, kdriver))
		return s;
	xbcopy(khipb->sessionKey, sessionKey, sizeof(sessionKey));	/* save the session key */
	/*
	 * cKrbGetTicketForService put a longword buffer length into the buffer
	 * which we don't want, so we ignore it.
     * Make room for first 3 bytes which preceed the auth data.
	 */
	cp = &buf[4-3];						/* skip long, make room for 3 bytes */
	cp[0] = tp[0];						/* copy type and modifier */
	cp[1] = tp[1];
	cp[2] = KRB_AUTH;					/* suboption command */
	len = khipb->buflen - sizeof(long) + 3; /* data - 4 + 3 */

#endif /* 0 */

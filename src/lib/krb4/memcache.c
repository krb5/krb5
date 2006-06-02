/*
 * memcache.c
 *
 * Kerberos credential cache
 * Originally coded by Tim Miller / Brown University as KRB_Store.c
 * Mods 1/92 By Peter Bosanko
 *
 * Modified May-June 1994 by Julia Menapace and John Gilmore
 * of Cygnus Support.
 *
 * This file incorporates replacements for the Unix files
 * in_tkt.c, dest_tkt.c, tf_util.c, and tkt_string.c.
 */

#include "krb.h"
#include "krb4int.h"
#include "autoconf.h"

#ifdef _WIN32
#include <errno.h>

typedef DWORD OSErr;
#define noErr 0
#define cKrbCredsDontExist 12001
#define cKrbSessDoesntExist 12002
#define memFullErr ENOMEM
#endif

#ifndef unix
#ifdef _AIX
#define unix
#endif
#endif

#ifdef unix
/* Unix interface to memory cache Mac functions.  */

#include <stdio.h>
#include <errno.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#else
extern char *malloc (), *realloc ();
#endif

typedef int OSErr;
#define noErr 0
#define memFullErr ENOMEM

#endif /* unix */

#include "memcache.h"


/* Lower level data structures  */

static	int		fNumSessions = 0;
static	Session		**fSessions = 0;

#ifndef _WIN32
#define change_cache()
#endif

#if defined (_WIN32) || defined (unix)
/* Fake Mac handles up for general use.  */
#define	Handle	char **
#define	Size	int

static OSErr memerror = noErr;

/*
 * Simulates Macintosh routine by allocating a block of memory
 * and a pointer to that block of memory.  If the requested block
 * size is 0, then we just allocate the indirect pointer and 0
 * it, otherwise we allocate an indirect pointer and place a pointer
 * to the actual allocated block in the indirect pointer location.
 */
Handle 
NewHandleSys(s)
	int s;
{
	Handle h;

	h = (char **) malloc(sizeof(char *));

	if (h == NULL) {
		memerror = memFullErr;
		return (NULL);
	}

	if (s > 0) {
		*h = malloc(s);

		if (*h == NULL) {
			free(h);
			memerror = memFullErr;
			return (NULL);
		}
	}
	else
		*h = NULL;

	memerror = noErr;

	return h;
}

/*
 * Frees allocated indirect pointer and the block of memory it points
 * to.  If the indirect pointer is NULL, then the block is considered
 * to have 0 length.
 */
void
DisposHandle(h)
	Handle h;
{
	if (*h != NULL)
		free(*h);
	free(h);
}

/*
 * Resizes a block of memory pointed to by and indirect pointer.  The
 * indirect pointer is updated when the block of memory is reallocated.
 * If the indirect pointer is 0, then the block of memory is allocated
 * rather than reallocated.  If the size requested is 0, then the block
 * is deallcated rather than reallocated.
 */
void
SetHandleSize(h, s)
	Handle h;
	int s;
{
	if (*h != NULL) {
		if (s > 0) {
			*h = realloc(*h, s);
			if (*h == NULL) {
				memerror = memFullErr;
				return;
			}
		}
		else {
			free(*h);
			*h = NULL;
		}
	}

	else {
		if (s > 0) {
			*h = malloc(s);
			if (*h == NULL) {
				memerror = memFullErr;
				return;
			}
		}
	}

	memerror = noErr;
}

OSErr
MemError()
{
	return memerror;
}

#endif /* Windows || unix */

#ifdef _WIN32

/*
 * change_cache should be called after the cache changes.
 * If the session count is > 0 it forces the DLL to stay in
 * memory even after the calling program exits providing cross
 * session ticket cacheing.  Also a notification message is
 * is posted out to all top level Windows so that they may
 * recheck the cache based on the changes made.  The
 * krb_get_notifcation_message routine will return the
 * current notificaiton message for the system which an
 * application can expect to get.
 */
void
change_cache()
{
	char fname[260];
	static BOOL locked = FALSE;

	if (fNumSessions > 0 && !locked) {
		GetModuleFileName(get_lib_instance(), fname, sizeof(fname));
		LoadLibrary(fname);
		locked = TRUE;
	}

	else if (fNumSessions == 0 && locked) {
		FreeLibrary(get_lib_instance());
		locked = FALSE;
	}

	PostMessage(HWND_BROADCAST, krb_get_notification_message(), 0, 0);
}


/*
 * Returns a system wide unique notification message.  This
 * message will be broadcast to all top level windows when
 * the credential cache changes.
 */
unsigned int
krb_get_notification_message(void)
{
	static UINT message = 0;

	if (message == 0)
		message = RegisterWindowMessage(WM_KERBEROS_CHANGED);

	return message;
}


#endif /* Windows */


/* The low level routines in this file are capable of storing
   tickets for multiple "sessions", each led by a different
   ticket-granting ticket.  For now, since the top level code
   doesn't know how to handle that, we are short-cutting all
   that with a fixed top level identifying tag for the (one)
   session supported. 

   FIXME jcm - Force one named cache for now for compatibility with
   Cygnus source tree.  Figure out later how to access the multiple
   cache functionality in KClient.
 */

char uname[] = "Fixed User";
char uinstance[] = "Fixed Instance";
char urealm[] = "Fixed Realm";

static char curr_auth_uname [ANAME_SZ];
static char curr_auth_uinst [INST_SZ];


/*
    in_tkt() is used to initialize the ticket cache.
    It inits the driver's credentials storage, by deleting any tickets.  
    in_tkt() returns KSUCCESS on success, or KFAILURE if something goes wrong.

    User name, instance and realm are not currently being stored in
    the credentials cache because currently we are forcing a single
    named cache by using a fixed user name,inst,and realm in the
    memcache accessor routines.

    FIXME jcm - needed while stubbing out multi-caching with fixed
    user etc...  Store currently authenticated user name and instance
    in this file.  We will use this information to fill out the p_user
    and p_inst fields in the credential.

    FIXME jcm - more kludges: make sure default user name matches the
    current credentials cache.  Telnet asks for default user name.  It
    may have last been set to another user name programmatically or
    via ResEdit.

 */
int KRB5_CALLCONV
in_tkt(pname,pinst)
    char *pname;
    char *pinst;
{
  int retval;
	
  strncpy (curr_auth_uname, pname, ANAME_SZ);
  strncpy (curr_auth_uinst, pinst, INST_SZ);
	
  krb_set_default_user (pname);
	
  retval = dest_tkt();
  if (!retval) 
    return retval;
  else 	
    return KSUCCESS;
	
}

int KRB5_CALLCONV
krb_in_tkt(pname, pinst, prealm)
    char *pname;
    char *pinst;
    char *prealm;
{
    return in_tkt(pname, pinst);
}

/*
 * dest_tkt() is used to destroy the ticket store upon logout.
 * If the ticket file does not exist, dest_tkt() returns RET_TKFIL.
 * Otherwise the function returns RET_OK on success, KFAILURE on
 * failure.
 *
 */
int KRB5_CALLCONV
dest_tkt()
{
 	/* 	
		FIXME jcm - Force one named cache for now for
		compatibility with Cygnus source tree.  Figure out
		later how to access the multiple cache functionality in
		KClient.
	*/
	OSErr err;
 
	err = DeleteSession(uname, uinstance, urealm);
 
	change_cache();
 
	switch(err) {
		case noErr:	
			return RET_OK;
		case cKrbSessDoesntExist:
			return RET_TKFIL;
		default:
			return KFAILURE;
		}
	}


int	dest_all_tkts()		
{
	int	i=0;
	char	name[ANAME_SZ], inst[INST_SZ], realm[REALM_SZ];
	int ndeletes=0;
	int err=0;

	(void) GetNumSessions(&i);
	if(!i) return RET_TKFIL;

	for( ; i; i--) {
		if(!GetNthSession(i, name, inst, realm)) {
			if (err = DeleteSession(name, inst, realm))
				break;
			ndeletes++;
			}
		else {
			err = KFAILURE;
			break;
			}
		}

	if (ndeletes > 0)
		change_cache();

	if (err)
		return KFAILURE;
	else
		return KSUCCESS;
	}


/* krb_get_tf_realm -- return the realm of the current ticket file. */
int KRB5_CALLCONV
krb_get_tf_realm (tktfile, lrealm)
	char *tktfile;
	char *lrealm;		/* Result stored through here */
{
	
	return krb_get_tf_fullname(tktfile, (char*) 0, (char*) 0 , lrealm);
}


/* krb_get_tf_fullname -- return name, instance and realm of the
principal in the current ticket file. */
int KRB5_CALLCONV
krb_get_tf_fullname (tktfile, name, instance, realm)
  char *tktfile;
  char *name;
  char *instance;
  char *realm;
  
{
	OSErr err;

/* 
	Explaining this ugly hack:
	uname, uinstance, and urealm in the session record are "fixed" 
	to short circuit multicache functionality, yielding only one 
	session/cache for all cases.  This was done under protest to remain 
	API compatable with UNIX. The principal's and service realm are 
	always the same and are stored in the same field of the credential. 
	Principal's name and instance are stored neither in the session 
	record or the credentials cache but in the file static variables 
	curr_auth_uname, and curr_auth_uinst as set by in_tkt from its 
	arguments pname and pinst.  
	
   FIXME for multiple sessions -- keep track of which one is
   the "current" session, as picked by the user.  tktfile not
   used for anything right now...
*/
	   
	err = GetNthCredentials(uname, uinstance, urealm, name,
				instance, realm, 1);
				
	if (err != noErr) 
		return NO_TKT_FIL;
	
	if (name)
		strcpy(name, curr_auth_uname);	
	if (instance)
		strcpy(instance, curr_auth_uinst);

	return KSUCCESS;
	
}


/*
 * krb_get_cred takes a service name, instance, and realm, and a
 * structure of type CREDENTIALS to be filled in with ticket
 * information.  It then searches the ticket file for the appropriate
 * ticket and fills in the structure with the corresponding
 * information from the file.  If successful, it returns KSUCCESS.
 * On failure it returns a Kerberos error code.
 */
int KRB5_CALLCONV
krb_get_cred (service, instance, realm, c)
	char *service;		/* Service name */
	char *instance;		/* Instance */
	char *realm;		/* Authorization domain */
	CREDENTIALS *c;		/* Credentials struct */
{
	strcpy(c->service, service);
	strcpy(c->instance, instance);
	strcpy(c->realm, realm);

	/* 	
		FIXME jcm - Force one named cache for now for
		compatibility with Cygnus source tree.  Figure out
		later how to access the multiple cache functionality
		from KClient.
	*/

	switch(GetCredentials(uname, uinstance, urealm, c)) {
		case noErr:
			return KSUCCESS;
		case cKrbCredsDontExist:
		case cKrbSessDoesntExist: 
			return GC_NOTKT;
		default:
			return KFAILURE;
		}
}

/*
 * This routine takes a ticket and associated info and 
 * stores them in the ticket cache.  The peer
 * routine for extracting a ticket and associated info from the
 * ticket cache is krb_get_cred().  When changes are made to
 * this routine, the corresponding changes should be made
 * in krb_get_cred() as well.
 *
 * Returns KSUCCESS if all goes well, otherwise KFAILURE.
 */

int
krb4int_save_credentials_addr(sname, sinst, srealm, session, 
			      lifetime, kvno, ticket, issue_date, laddr)

	char* sname;		/* Service name */
	char* sinst;		/* Instance */	
	char* srealm;		/* Auth domain */
	C_Block session;	/* Session key */
	int lifetime;		/* Lifetime */
	int kvno;		/* Key version number */
    	KTEXT ticket; 		/* The ticket itself */
	KRB4_32 issue_date;	/* The issue time */
	KRB_UINT32 laddr;
{
	CREDENTIALS	cr;

	strcpy(cr.service, sname);
	strcpy(cr.instance, sinst);
	strcpy(cr.realm, srealm);
	memcpy((void*)cr.session, (void*)session, sizeof(C_Block));
	cr.lifetime = lifetime;
	cr.kvno = kvno;
	cr.ticket_st = *ticket;
	cr.issue_date = issue_date;
	strcpy(cr.pname, curr_auth_uname);	/* FIXME for mult sessions */
	strcpy(cr.pinst, curr_auth_uinst);	/* FIXME for mult sessions */

	if(AddCredentials(uname, uinstance, urealm, &cr)) return KFAILURE;
	change_cache();
	return KSUCCESS;
}

int KRB5_CALLCONV
krb_save_credentials(
    char	*name,
    char	*inst,
    char	*realm,
    C_Block	session,
    int		lifetime,
    int		kvno,
    KTEXT	ticket,
    KRB4_32	issue_date)
{
    return krb4int_save_credentials_addr(name, inst, realm, session,
					 lifetime, kvno, ticket,
					 issue_date, 0);
}


int
krb_delete_cred (sname, sinstance, srealm)
	char *sname;
	char *sinstance;
	char *srealm;
{
	
    if (DeleteCredentials (uname, uinstance, urealm, sname, sinstance, srealm))
	return KFAILURE;

	change_cache();

	return KSUCCESS;
	
  /*
    FIXME jcm - translate better between KClient internal OSErr errors 
    (eg. cKrbCredsDontExist) and kerberos error codes (eg. GC_NOTKT)
    */
}	

int
krb_get_nth_cred (sname, sinstance, srealm, n)
	char *sname;
	char *sinstance;
	char *srealm;
	int n;
{	
    if (GetNthCredentials(uname, uinstance, urealm, sname, sinstance, srealm, n))
	return KFAILURE;
    else
	return KSUCCESS;
}

/*
 * Return the number of credentials in the current credential cache (ticket cache).
 * On error, returns -1. 
 */
int
krb_get_num_cred ()
{
  int n;
  int s;

  s = GetNumCredentials(uname, uinstance, urealm, &n);
  if (s) return -1;
  else return n;
}



/* Lower level routines */

OSErr	GetNumSessions(n)
     int *n;
{
	*n = fNumSessions;
	return 0;
	}

/* n starts at 1, not 0 */
OSErr
GetNthSession(n, name, instance, realm)
     const int n;
     char *name;
     char *instance;
     char *realm;
{
	Session	*sptr;

	if(n > fNumSessions || !fSessions) return cKrbSessDoesntExist;

	sptr = (*fSessions) + n-1;
	if (name)	strcpy(name, sptr->name);
	if (instance)	strcpy(instance, sptr->instance);
	if (realm)	strcpy(realm, sptr->realm);

	return noErr;
	}

OSErr	DeleteSession(name, instance, realm)
     const char *name;
     const char *instance;
     const char *realm;
{
	int		i;
	Session	*sptr;
	Handle	creds;

	if(!fNumSessions || !fSessions) return cKrbSessDoesntExist;

	sptr = *fSessions;

	for(i = 0; i < fNumSessions; i++) {
		if(!strcmp(sptr[i].name, name) &&
			!strcmp(sptr[i].instance, instance) &&
			!strcmp(sptr[i].realm, realm)) {
			break;
			}
		}

	if(i == fNumSessions) return cKrbSessDoesntExist;

	fNumSessions--;

	creds = (Handle) sptr[i].creds;

	for( ; i < fNumSessions; i++) {
		strcpy(sptr[i].name, sptr[i+1].name);
		strcpy(sptr[i].instance, sptr[i+1].instance);
		strcpy(sptr[i].realm, sptr[i+1].realm);
		}

	SetHandleSize((Handle) fSessions, fNumSessions * sizeof(Session));
	if(creds) DisposHandle(creds);

	return MemError();
	}

OSErr	GetCredentials(name, instance, realm, cr)
     const char *name;
     const char *instance;
     const char *realm;
     CREDENTIALS *cr;
{
	int		i;
	Session	*sptr;
	CREDENTIALS	*cptr;
	
	if(!fNumSessions || !fSessions) return cKrbSessDoesntExist;

	sptr = *fSessions;

	for(i = 0; i < fNumSessions; i++) {
		if(!strcmp(sptr[i].name, name) &&
			!strcmp(sptr[i].instance, instance) &&
			!strcmp(sptr[i].realm, realm)) {
			break;
			}
		}

	if(i == fNumSessions) return cKrbSessDoesntExist;

	sptr = sptr + i;

	if(!sptr->numcreds || !sptr->creds) return cKrbCredsDontExist;

	cptr = *(sptr->creds);

	for(i = 0; i < sptr->numcreds; i++) {
		if(!strcmp(cptr[i].service, cr->service) &&
			!strcmp(cptr[i].instance, cr->instance) &&
			!strcmp(cptr[i].realm, cr->realm)) {
			break;
			}
		}

	if(i == sptr->numcreds) return cKrbCredsDontExist;

	*cr = cptr[i];
	return noErr;
	}

OSErr	AddCredentials(name, instance, realm, cr)
     const char *name;
     const char *instance;
     const char *realm;
     const CREDENTIALS *cr;
{
	Session	*sptr;
	Handle	creds;
	int		i, thesess;
	CREDENTIALS	*cptr;

	/* find the appropriate session, or create it if it doesn't exist */
	if(!fSessions) {
		fSessions = (Session**) NewHandleSys(0);
		if(MemError()) return MemError();
		fNumSessions = 0;
		}

	sptr = *fSessions;

	for(thesess = 0; thesess < fNumSessions; thesess++) {
		if(!strcmp(sptr[thesess].name, name) &&
			!strcmp(sptr[thesess].instance, instance) &&
			!strcmp(sptr[thesess].realm, realm)) {
			break;
			}
		}

	sptr = (*fSessions) + thesess;

	if(thesess == fNumSessions) {	/* doesn't exist, create it */
		fNumSessions++;
		SetHandleSize((Handle) fSessions, fNumSessions * sizeof(Session));
		if(MemError()) return MemError();

		/* fSessions may have been moved, so redereference */
		sptr = (*fSessions) + thesess;
		strcpy(sptr->name, (char *)name);
		strcpy(sptr->instance, (char *)instance);
		strcpy(sptr->realm, (char *)realm);
		sptr->numcreds = 0;
		sptr->creds = 0;
		}

		/* if the session has no assoc creds, create storage for them so rest of algorithm
			doesn't break */
	if(!sptr->numcreds || !sptr->creds) {
		creds = NewHandleSys((Size) 0);
		if(MemError()) return MemError();

		/* rederef */ 
		sptr = (*fSessions) + thesess;
		sptr->creds = (CREDENTIALS **)creds;
		sptr->numcreds = 0;
		}

		/* find creds if we already have an instance of them, or create a new slot for them
			if we don't */
	cptr = *(sptr->creds);

	for(i = 0; i < sptr->numcreds; i++) {
		if(!strcmp(cptr[i].service, cr->service) &&
			!strcmp(cptr[i].instance, cr->instance) &&
			!strcmp(cptr[i].realm, cr->realm)) {
			break;
			}
		}

	if(i == sptr->numcreds) {
		sptr->numcreds++;
		SetHandleSize((Handle)sptr->creds, sptr->numcreds * sizeof(CREDENTIALS));
		if(MemError()) return MemError();

		/* rederef */
		sptr = (*fSessions) + thesess;
		cptr = *(sptr->creds);
		}

		/* store them (possibly replacing previous creds if they already exist) */
	cptr[i] = *cr;
	return noErr;
	}

OSErr
DeleteCredentials (uname, uinst, urealm, sname, sinst, srealm)
     const char *uname;
     const char *uinst;
     const char *urealm;
     const char *sname;
     const char *sinst;
     const char *srealm;
{
	int		i;
	Session	*sptr;
	CREDENTIALS	*cptr;

	if(!fNumSessions || !fSessions) return cKrbSessDoesntExist;

	sptr = *fSessions;

	for(i = 0; i < fNumSessions; i++) {
		if(!strcmp(sptr[i].name, uname) &&
			!strcmp(sptr[i].instance, uinstance) &&
			!strcmp(sptr[i].realm, urealm)) {
			break;
			}
		}

	if(i == fNumSessions) return cKrbSessDoesntExist;

	sptr = sptr + i;

	if(!sptr->numcreds || !sptr->creds) return cKrbCredsDontExist;

	cptr = *(sptr->creds);

	for(i = 0; i < sptr->numcreds; i++) {
		if(!strcmp(cptr[i].service, sname) &&
			!strcmp(cptr[i].instance, sinst) &&
			!strcmp(cptr[i].realm, srealm)) {
			break;
			}
		}

	if(i == sptr->numcreds) return cKrbCredsDontExist;

	sptr->numcreds--;

	for( ; i < sptr->numcreds; i++) {
		cptr[i] = cptr[i+1];
		}

	SetHandleSize((Handle) sptr->creds, sptr->numcreds * sizeof(CREDENTIALS));

	return MemError();
	}

OSErr	GetNumCredentials(name, instance, realm, n)
     const char *name;
     const char *instance;
     const char *realm;
     int *n;
{
	int		i;
	Session	*sptr;

	if(!fNumSessions || !fSessions) {
		*n = 0;
		return cKrbSessDoesntExist;
		}

	sptr = *fSessions;

	for(i = 0; i < fNumSessions; i++) {
		if(!strcmp(sptr[i].name, name) &&
			!strcmp(sptr[i].instance, instance) &&
			!strcmp(sptr[i].realm, realm)) {
			break;
			}
		}

	if(i == fNumSessions) {
		*n = 0;
		return cKrbCredsDontExist;
		}

	*n = sptr[i].numcreds;
	return noErr;
	}

/* returns service name, service instance and realm of the nth credential. */
/* n starts at 1, not 0 */
OSErr
GetNthCredentials(uname, uinstance, urealm, sname, sinst, srealm, n)
     const char *uname;
     const char *uinstance;
     const char *urealm;
     char *sname;
     char *sinst;
     char *srealm;
     const int n;
{
	int		i;
	Session	*sptr;
	CREDENTIALS	*cptr;

	if(!fNumSessions || !fSessions) return cKrbSessDoesntExist;

	sptr = *fSessions;

	for(i = 0; i < fNumSessions; i++) {
		if(!strcmp(sptr[i].name, uname) &&
			!strcmp(sptr[i].instance, uinstance) &&
			!strcmp(sptr[i].realm, urealm)) {
			break;
			}
		}

	if(i == fNumSessions) return cKrbSessDoesntExist;

	sptr = (*fSessions) + i;

	if(n > sptr->numcreds || !sptr->creds) return cKrbCredsDontExist;

	cptr = (*(sptr->creds)) + n-1;

	/* 
	   check for null pointers cuz. some callers don't provide  
	   storage for all this info, eg. Kerb_get_tf_fullname. 
	*/
	
	if (sname) 
		strcpy(sname, cptr->service);
	if (sinst)
		strcpy(sinst, cptr->instance);
	if (srealm)
		strcpy(srealm, cptr->realm);
	return noErr;
}

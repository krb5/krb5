/*
 * mac_store.c
 *
 * Kerberos configuration store
 * Originally coded by Tim Miller / Brown University as KRB_Store.c
 * Mods 1/92 By Peter Bosanko
 *
 * Modified May-June 1994 by Julia Menapace and John Gilmore
 * of Cygnus Support.
 *
 * This file incorporates replacements for the Unix files
 * g_admhst.c, g_krbhst.c, realmofhost.c, and g_krbrlm.c.
 */

/* Headers from in_tkt.c, merged in by gnu FIXME */
#include <types.h>

/* Headers from store.c from KClient */
#include <string.h>
#include <traps.h>
#include <gestaltEqu.h>
#include <Folders.h>
#include <Resources.h>
#include <Memory.h>
#include <Files.h>

#include "krb.h"
#include "mac_store.h"	/* includes memcache.h */
#include "krb_driver.h"

#define	prefname	"\pKerberos Client Preferences"
const	OSType	preftype = 'PREF';
const	OSType	prefcrea	= 'krbL';
const	OSType	unametype = 'UNam';
const	OSType	lrealmtype = 'LRlm';
const	OSType	templatetype = 'TMPL';
const	OSType	realmmaptype = 'RMap';
const	OSType	servermaptype = 'SMap';
#define kNumTemplates 4
#define kFirstTemplate 128
#define kMapResNum 1024


/* Lower level routines and data structures  */


/* Need to check this in each high-level routine, and call init_store
   if not set.  */
static	int		initialized_store = 0;		

static	char		fLRealm[REALM_SZ] = "";
static	Handle		fRealmMap = 0;
static	Handle		fServerMap = 0;
static	short		fPrefVRefNum;
static	long		fPrefDirID;
OSErr			fConstructErr = -1;

/* Current default user name (for prompts, etc).  */

static char gUserName[MAX_K_NAME_SZ]; 


/* Routines for dealing with the realm versus host database */

/*
 * krb_get_admhst
 *
 * Given a Kerberos realm, find a host on which the Kerberos database
 * administration server can be found.
 *
 * krb_get_admhst takes a pointer to be filled in, a pointer to the name
 * of the realm for which a server is desired, and an integer n, and
 * returns (in h) the nth administrative host entry from the configuration
 * file (KRB_CONF, defined in "krb.h") associated with the specified realm.
 * If ATHENA_CONF_FALLBACK is defined, also look in old location.
 *
 * On error, get_admhst returns KFAILURE. If all goes well, the routine
 * returns KSUCCESS.
 *
 * For the format of the KRB_CONF file, see comments describing the routine
 * krb_get_krbhst().
 *
 * This is a temporary hack to allow us to find the nearest system running
 * a Kerberos admin server.  In the long run, this functionality will be
 * provided by a nameserver.  (HAH!)
 */
int
krb_get_admhst (h, r, n)
	char *h;
	char *r;
	int n;
{
	if (!initialized_store) 
		if (init_store())
			return KFAILURE;
	if(GetNthServer(n, r, 1, h)) return KFAILURE;
	else return KSUCCESS;
}

/*
 * Given a Kerberos realm, find a host on which the Kerberos authenti-
 * cation server can be found.
 *
 * krb_get_krbhst takes a pointer to be filled in, a pointer to the name
 * of the realm for which a server is desired, and an integer, n, and
 * returns (in h) the nth entry from the configuration information
 * associated with the specified realm.
 *
 * If no info is found, krb_get_krbhst returns KFAILURE.  If n=1 and the
 * configuration file does not exist, krb_get_krbhst will return KRB_HOST
 * (defined in "krb.h").  If all goes well, the routine returnes
 * KSUCCESS.
 *
 * This is a temporary hack to allow us to find the nearest system running
 * kerberos.  In the long run, this functionality will be provided by a
 * nameserver.  (AH SO!)
 */
int	krb_get_krbhst(h, r, n)
	char *h;
	char *r;
	int n;
{
	if (!initialized_store) 
		if (init_store())
			return KFAILURE;
	if (GetNthServer(n, r, 0, h)) return KFAILURE;
	else return KSUCCESS;
}


/*
 * krb_get_lrealm takes a pointer to a string, and a number, n.  It fills
 * in the string, r, with the name of the local realm specified in
 * the local Kerberos configuration.
 * It returns 0 (KSUCCESS) on success, and KFAILURE on failure.  If the
 * config info does not exist, and if n=1, a successful return will occur
 * with r = KRB_REALM (also defined in "krb.h").  [FIXME -- not implem.]
 *
 * NOTE: for archaic & compatibility reasons, this routine will only return
 * valid results when n = 1.
 */

int	krb_get_lrealm(char *r, int n)
{
	if (!initialized_store) 
		if (init_store())
			return KFAILURE;
	if (n != 1)
		return KFAILURE;
	if (GetLocalRealm(r))
		return KFAILURE;
	return KSUCCESS;
}


/*
 * krb_realmofhost.
 * Given a fully-qualified domain-style primary host name,
 * return the name of the Kerberos realm for the host.
 * If the hostname contains no discernable domain, or an error occurs,
 * return the local realm name, as supplied by get_krbrlm().
 * If the hostname contains a domain, but no translation is found,
 * the hostname's domain is converted to upper-case and returned.
 *
 * In the database,
 * domain_name should be of the form .XXX.YYY (e.g. .LCS.MIT.EDU)
 * host names should be in the usual form (e.g. FOO.BAR.BAZ)
 */

char *krb_realmofhost(char *host)
{
	static char	realm[REALM_SZ];
	
	if (!initialized_store) 
		if (init_store())
			return 0;

	/* Store realm string through REALM pointer arg */
	GetRealm(host, realm);	
	return realm;
}


char * INTERFACE
krb_get_default_user (void)
{
    if (!initialized_store)
	if (init_store())
	    return 0;

    return gUserName;
}


int INTERFACE
krb_set_default_user (uName)
    char* uName;
{
    if (!initialized_store)
	if (init_store())
	    return KFAILURE;

    if( strcmp( gUserName, uName ) != 0 ) {
	strcpy( gUserName, uName );
	if (WriteUser() != 0)
	    return KFAILURE;
    }
    return KSUCCESS;
}



void GetPrefsFolder(short *vRefNumP, long *dirIDP)
{
	Boolean hasFolderMgr = false;
	long feature;
/*	
	FIXME Error:   ‘_GestaltDispatch’ has not been declared - not needed now? - jcm
	if (TrapAvailable(_GestaltDispatch)) 
*/
	if (Gestalt(gestaltFindFolderAttr, &feature) == noErr) hasFolderMgr = true;
	if (!hasFolderMgr) {
		GetSystemFolder(vRefNumP, dirIDP);
		return;
		}
	else {
		if (FindFolder(kOnSystemDisk, kPreferencesFolderType, kDontCreateFolder, vRefNumP, dirIDP) != noErr) {
			*vRefNumP = 0;
			*dirIDP = 0;
			}
		}
	}


/*
    init_store() is used to initialize the config store.  It opens the
    driver preferences file and reads the local realm, user name, and
    realm and server maps from resources in the prefs file into driver
    storage.  If the preferences file doesn't exist, init_store creates it.
    Returns 0 on success, or 1 if something goes wrong.
 */
int
init_store()
{
	short refnum;
	Handle	temp;
	int hasPrefFile;
	
	/* If a prefs file exists, load from it, otherwise load defaults from self */
	GetPrefsFolder(&fPrefVRefNum, &fPrefDirID);
	refnum = HOpenResFile(fPrefVRefNum, fPrefDirID, (unsigned char *)prefname, fsRdPerm);
	hasPrefFile = (refnum != -1); 		// did we open it?
	
	temp = GetResource(lrealmtype, kMapResNum);
	if(ResError() || !temp) {
		if(refnum != -1) CloseResFile(refnum);
		fConstructErr = cKrbCorruptedFile;
		return 1;
	}
	strcpy(fLRealm, *temp);
	ReleaseResource(temp);
	
	temp = GetResource(unametype, kMapResNum);
	if(ResError() || !temp) {
		if(refnum != -1) CloseResFile(refnum);
		fConstructErr = cKrbCorruptedFile;
		return 1;
	}
	strcpy(gUserName, *temp);
	ReleaseResource(temp);
	
	fRealmMap = GetResource(realmmaptype, kMapResNum);
	if(ResError() || !fRealmMap) {
		if(refnum != -1) CloseResFile(refnum);
		*fLRealm = 0;
		fConstructErr = cKrbCorruptedFile;
		return 1;
	}
	DetachResource(fRealmMap);
	
	fServerMap = GetResource(servermaptype, kMapResNum);
	if(ResError() || !fServerMap) {
		if(refnum != -1) CloseResFile(refnum);
		*fLRealm = 0;
		DisposeHandle(fRealmMap);
		fRealmMap = 0;
		fConstructErr = cKrbCorruptedFile;
		return 1;
	}
	DetachResource(fServerMap);
	
	if(refnum != -1) CloseResFile(refnum);
	fConstructErr = noErr;
	
	if (!hasPrefFile) {
		fConstructErr = CreatePrefFile();		// make prefs file if we need to
	}
	
	initialized_store = 1;
	return 0;
}


/****************Private routines******************/

OSErr	OpenPrefsFile(short *refnum)
{
	*refnum = HOpenResFile(fPrefVRefNum, fPrefDirID, (unsigned char *)prefname, fsRdWrPerm);
	
	if(ResError()) {	/* doesn't exist, create it */
		FInfo	fndrinfo;
		
		HCreateResFile(fPrefVRefNum, fPrefDirID, (unsigned char *)prefname);
		if(ResError()) {
			return ResError();
			}
		*refnum = HOpenResFile(fPrefVRefNum, fPrefDirID, (unsigned char *)prefname, fsRdWrPerm);
		if(ResError()) {
			return ResError();
			}
		HGetFInfo(fPrefVRefNum, fPrefDirID, (unsigned char *)prefname, &fndrinfo); 
		fndrinfo.fdCreator = prefcrea;
		fndrinfo.fdType = preftype;
		HSetFInfo(fPrefVRefNum, fPrefDirID, (unsigned char *)prefname, &fndrinfo); 
		}
	
	return noErr;
	}



OSErr	CreatePrefFile()
{
	short	refnum, i;
	OSErr	err;
	Handle	tmpls[ kNumTemplates ];

	// Get all the templates for ResEdit
	for( i = 0; i < kNumTemplates; i++ ) {
		tmpls[i] = GetResource( templatetype, kFirstTemplate + i );
		if( ResError() || !tmpls[i] ) return cKrbCorruptedFile;
	}
	
	err = OpenPrefsFile( &refnum );
	if( err ) return err;
	
	// write out the templates
	for( i = 0; i < kNumTemplates && !err; i++ ) {
		short	tmplid;
		ResType	theType;
		Str255	resName;

		GetResInfo( tmpls[i], &tmplid, &theType, resName );
		err = WritePref( refnum, tmpls[i], templatetype, tmplid, resName );	
		ReleaseResource( tmpls[i] );
	}

	if( !err )
		err = WritePref( refnum, fRealmMap, realmmaptype, kMapResNum, "\p" );	
	if( !err )
		err = WritePref( refnum, fServerMap, servermaptype, kMapResNum, "\p" );	
	if( !err )
		err = WritePrefStr( refnum, fLRealm, lrealmtype, kMapResNum, "\p" );	
	if( !err )
		err = WritePrefStr( refnum, gUserName, unametype, kMapResNum, "\p" );	

	CloseResFile( refnum );
	if( !err ) err = ResError();
	return err;
}

OSErr	WriteUser()
{
	short	refnum;
	OSErr	err;

	err = OpenPrefsFile( &refnum );
	if( err ) return err;

	err = WritePrefStr( refnum, gUserName, unametype, kMapResNum, "\p" );	

	CloseResFile( refnum );
	if( !err ) err = ResError();
	return err;
}

OSErr	WritePref( short refnum, Handle dataHandle, OSType mapType, short resID, Str255 resName )
{
	OSErr	err;
	Handle	resHandle;

	resHandle = Get1Resource( mapType, resID );
	if( !resHandle ) {								// create a new resource:
		resHandle = dataHandle;
		err = HandToHand( &resHandle );				// copy the data handle
		if( err != noErr ) return err;

		AddResource( resHandle, mapType, resID, resName );
		if( ( err = ResError() ) != noErr ) {
			DisposHandle( resHandle );
			return err;
		}
		SetResAttrs( resHandle, resSysHeap | GetResAttrs( resHandle ) );
	}
	else {											/* modify an existing resource: */
		Size handleSize = GetHandleSize( dataHandle );
		SetHandleSize( resHandle, handleSize );
		if( ( err = MemError() ) != noErr ) {
			ReleaseResource( resHandle );
			return err;
		}
		BlockMove( *dataHandle, *resHandle, handleSize );
		ChangedResource( resHandle );
		if( ( err = ResError() ) != noErr ) {
			ReleaseResource( resHandle );
			return err;
		}
	}

	UpdateResFile( refnum );
	err = ResError();
	ReleaseResource( resHandle );
	return err;
}

OSErr	WritePrefStr( short refnum, char *dataString, OSType mapType, short resID, Str255 resName )
{
	OSErr		err;
	Handle	dataHandle;

	err = PtrToHand( dataString, &dataHandle, strlen( dataString ) + 1 );
	if( err == noErr ) {
		err = WritePref( refnum, dataHandle, mapType, resID, resName );
		DisposHandle( dataHandle );
	}
	return err;
}
	
OSErr	WriteRealmMap()
{
	short	refnum;
	OSErr	err;
	
	err = OpenPrefsFile( &refnum );
	if( err ) return err;
		
 	err = WritePref( refnum, fRealmMap, realmmaptype, kMapResNum, "\p" );	

	CloseResFile( refnum );
	if( !err ) err = ResError();
	return err;
}

OSErr	WriteServerMap()
{
	short	refnum;
	OSErr	err;
	
	err = OpenPrefsFile(&refnum);
	if( err ) return err;
	
	err = WritePref( refnum, fServerMap, servermaptype, kMapResNum,"\p" );	

	CloseResFile( refnum );
	if( !err ) err = ResError();
	return err;
}

OSErr	GetLocalRealm(char *lrealm)
{
	if (!initialized_store)
		init_store();
	
	strcpy(lrealm, fLRealm);
	return noErr;
	}

OSErr	SetLocalRealm( const char *lrealm )
{
	short	refnum;
	OSErr	err;
		
	if (!initialized_store)
		init_store();
	
	strcpy( fLRealm, (char *) lrealm );
	
	err = OpenPrefsFile( &refnum );
	if( err ) return err;
	
	err = WritePrefStr( refnum, fLRealm, lrealmtype, kMapResNum, "\p" );	

	CloseResFile( refnum );
	if( !err ) err = ResError();
	return err;
}

OSErr	GetRealm(const char *host, char *realm)
{
	int	numrealms;
	char	*curnetorhost, *currealm;
	char	*domain;
	
	if (!initialized_store)
		init_store();
	
	numrealms = *((short *)*fRealmMap);
	GetLocalRealm(realm);
	
	domain = strchr( host, '.');
	if(!domain) return noErr;
	
	curnetorhost = (*fRealmMap) + 2;
	currealm = strchr(curnetorhost, '\0') + 1;
	for( ; numrealms > 0; numrealms--) {
		if(!strcasecmp(curnetorhost, host)) {
			strcpy(realm, currealm);
			return noErr;
			}
		if(!strcasecmp(curnetorhost, domain)) {
			strcpy(realm, currealm);
			}
		
		if(numrealms > 1) {
			curnetorhost = strchr(currealm, '\0') + 1;
			currealm = strchr(curnetorhost, '\0') + 1;
			}
		}
	
	return noErr;
	}

OSErr	AddRealmMap(const char *netorhost, const char *realm)
{
	int	numrealms;
	char	*curptr;
	
	SetHandleSize(fRealmMap, strlen(netorhost)+1 + strlen(realm)+1 +
										GetHandleSize(fRealmMap));
	if(MemError()) return MemError();
	
	numrealms = ++(*((short *)*fRealmMap));
	
	for(curptr = (*fRealmMap)+2; numrealms > 1; numrealms--) {
		curptr = strchr(curptr, '\0') + 1;
		curptr = strchr(curptr, '\0') + 1;
		}
	
	strcpy(curptr, netorhost);
	curptr = strchr(curptr, '\0') + 1;
	strcpy(curptr, realm);
	
	return WriteRealmMap();
	}

OSErr	DeleteRealmMap(const char *netorhost)
{
	int	numrealms = *((short *)*fRealmMap);
	char	*curptr, *fromptr, *nextptr;
		
	for(curptr = (*fRealmMap)+2; numrealms > 0; numrealms--) {
		if(!strcasecmp(curptr, netorhost)) break;	/* got it! */
		
		curptr = strchr(curptr, '\0') + 1;
		curptr = strchr(curptr, '\0') + 1;
		}
	
	if(numrealms == 0) return cKrbMapDoesntExist;
	
	*(short*)*fRealmMap -= 1;
	
	if(numrealms > 1) {
		fromptr = strchr(curptr, '\0') + 1;
		fromptr = strchr(fromptr, '\0') + 1;
		}
	
	for( ; numrealms > 1; numrealms--) {
		nextptr = strchr(fromptr, '\0') + 1;
		strcpy(curptr, fromptr);
		curptr = strchr(curptr, '\0') + 1;
		fromptr = nextptr;
		
		nextptr = strchr(fromptr, '\0') + 1;
		strcpy(curptr, fromptr);
		curptr = strchr(curptr, '\0') + 1;
		fromptr = nextptr;
		}
	
	SetHandleSize(fRealmMap, curptr-(*fRealmMap));
	if(MemError()) return MemError();
	return WriteRealmMap();
	}

OSErr	GetNthRealmMap(const int n, char *netorhost, char *realm)
{
	int	i;
	char	*curptr;
	
	if(n > *(short*)*fRealmMap) return cKrbMapDoesntExist;
	
	for(curptr = (*fRealmMap) + 2, i = 1; i < n; i++) {
		curptr = strchr(curptr, '\0') + 1;
		curptr = strchr(curptr, '\0') + 1;
		}
	
	strcpy(netorhost, curptr);
	curptr = strchr(curptr, '\0') + 1;
	strcpy(realm, curptr);
	
	return noErr;
	}

OSErr	GetNthServer(const int n, const char *realm, const int mustadmin,
										char *server)
{
	int	numservers = *(short*)*fServerMap, i = 0;
	char	*currealm, *curserver;
	
	currealm = (*fServerMap) + 2;
	curserver = strchr(currealm, '\0') + 1 + 1;
	for( ; numservers > 0; numservers--) {
		if(!strcmp(currealm, realm)) {
			if(!mustadmin || *(curserver-1)) i++;
			if(i >= n) {
				strcpy(server, curserver);
				return noErr;
				}
			}
		
		if(numservers > 1) {
			currealm = strchr(curserver, '\0') + 1;
			curserver = strchr(currealm, '\0') + 1 + 1;
			}
		}

	return cKrbMapDoesntExist;
	}

OSErr	AddServerMap(const char *realm, const char *server,
										const int isadmin)
{
	int	numservers;
	char	*curptr;
	
	SetHandleSize(fServerMap, strlen(realm)+1 + 1 + strlen(server)+1 +
										GetHandleSize(fServerMap));
	if(MemError()) return MemError();
	
	numservers = ++(*((short *)*fServerMap));
	
	for(curptr = (*fServerMap)+2; numservers > 1; numservers--) {
		curptr = strchr(curptr, '\0') + 1 + 1;
		curptr = strchr(curptr, '\0') + 1;
		}
	
	strcpy(curptr, realm);
	curptr = strchr(curptr, '\0') + 1;
	*curptr = (char) isadmin;
	curptr++;
	strcpy(curptr, server);
	
	return WriteServerMap();
	}

OSErr	DeleteServerMap(const char *realm, const char *server)
{
	int	numservers = *((short *)*fServerMap);
	char	*curptr, *fromptr, *nextptr;
		
	for(curptr = (*fServerMap)+2; numservers > 0; numservers--) {
		if(!strcmp(curptr, realm)) {
			nextptr = strchr(curptr, '\0') + 1 + 1;
			if(!strcasecmp(nextptr, server)) {
				break;	/* got it! */
				}
			}
		
		curptr = strchr(curptr, '\0') + 1 + 1;
		curptr = strchr(curptr, '\0') + 1;
		}
	
	if(numservers == 0) return cKrbMapDoesntExist;
	
	*(short*)*fServerMap -= 1;
	
	if(numservers > 1) {
		fromptr = strchr(curptr, '\0') + 1 + 1;
		fromptr = strchr(fromptr, '\0') + 1;
		}
	
	for( ; numservers > 1; numservers--) {
		nextptr = strchr(fromptr, '\0') + 1;
		strcpy(curptr, fromptr);
		curptr = strchr(curptr, '\0') + 1;
		fromptr = nextptr;
		
		*curptr = *fromptr;
		curptr++;
		fromptr++;
		
		nextptr = strchr(fromptr, '\0') + 1;
		strcpy(curptr, fromptr);
		curptr = strchr(curptr, '\0') + 1;
		fromptr = nextptr;
		}
	
	SetHandleSize(fServerMap, curptr-(*fServerMap));
	if(MemError()) return MemError();
	return WriteServerMap();
	}

OSErr	GetNthServerMap(const int n, char *realm, char *server, int *admin)
{
	int	i;
	char	*curptr;
	
	if(n > *(short*)*fServerMap) return cKrbMapDoesntExist;
	
	for(curptr = (*fServerMap) + 2, i = 1; i < n; i++) {
		curptr = strchr(curptr, '\0') + 1 + 1;
		curptr = strchr(curptr, '\0') + 1;
		}
	
	strcpy(realm, curptr);
	curptr = strchr(curptr, '\0') + 1;
	*admin = *curptr;
	curptr++;
	strcpy(server, curptr);
	
	return noErr;
}

/*
	store.h
		Kerberos credential store
		Originally coded by Tim Miller / Brown University
		Mods 1/92 By Peter Bosanko

		Modified May 1994 by Julia Menapace and John Gilmore, Cygnus
		Support.
*/

#include "memcache.h"

extern	OSErr		fConstructErr;

		OSErr	CreatePrefFile();
		OSErr	WriteUser();		/* saves gUserName to prefs file  */

		/* Used internally...  */
		OSErr	WritePref(short refnum, Handle dataHandle, OSType mapType, short resID,
							Str255 resName);
		OSErr	WritePrefStr(short refnum, char *dataString, OSType mapType, short resID,
							Str255 resName);

			/*** Realm info routines: ***/
		OSErr	GetLocalRealm(char *lrealm);	/* stuffs local realm in lrealm */
		OSErr	SetLocalRealm(const char *lrealm);	/* sets local realm */

		OSErr	GetRealm(const char *host, char *realm);	/* yields realm for given
												host's net name */
		OSErr	AddRealmMap(const char *netorhost, const char *realm);	/* says hosts
												with this name or in this domain (if
												begins with period) map to this realm
												(provided no more specific map is
												found) */
		OSErr	DeleteRealmMap(const char *netorhost);	/* deletes realm map for the
												net or net hostname */
		OSErr	GetNthRealmMap(const int n, char *netorhost, char *realm);	/* yields
												the Nth mapping of a net or host to
												a kerberos realm */

		OSErr	GetNthServer(const int n, const char *realm, const int mustadmin,
								char *server);	/* yields Nth (administrating if
													mustadmin is true) server for
													the given realm */
		OSErr	AddServerMap(const char *realm, const char *server,
								const int isadmin);	/* says this server services this
												realm (administratively if isadmin) */
		OSErr	DeleteServerMap(const char *realm, const char *server);	/* deletes
												the map of this realm to this server */
		OSErr	GetNthServerMap(const int n, char *realm, char *server, int *admin);
											/* yields Nth realm-server mapping */

		OSErr		OpenPrefsFile(short *refnum);	/* open (create if necessary) prefs file
																for writing */
		OSErr		WriteRealmMap();
		OSErr		WriteServerMap();

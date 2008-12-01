/*
	memcache.h
		Kerberos credential store in memory
		Originally coded by Tim Miller / Brown University
		Mods 1/92 By Peter Bosanko

		Modified May-June 1994 by Julia Menapace and John Gilmore,
		Cygnus Support.
*/

struct Session {
	char		name[ANAME_SZ];
	char		instance[INST_SZ];
	char		realm[REALM_SZ];
	int		numcreds;
	CREDENTIALS	**creds;
};
typedef struct Session Session;

OSErr GetNumSessions(int *n);
OSErr GetNthSession(const int n, char *name, char *instance, char *realm);
OSErr DeleteSession(const char *name, const char *instance, const char *realm);
OSErr GetCredentials(const char *name, const char *instance, const char *realm,
		     CREDENTIALS *cr);	
/* name, instance, and realm of service wanted should be set in *cr
   before calling */
OSErr AddCredentials(const char *name, const char *instance, const char *realm,
		     const CREDENTIALS *cr);
OSErr DeleteCredentials(const char *uname, const char *uinst,
			const char *urealm, const char *sname,
			const char *sinst, const char *srealm);
OSErr GetNumCredentials(const char *name, const char *instance,
			const char *realm, int *n);
OSErr GetNthCredentials(const char *uname, const char *uinst,
			const char *urealm, char *sname, char *sinst,
			char *srealm, const int n);

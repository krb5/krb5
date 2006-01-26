/*
 * win_store.c
 *
 * Kerberos configuration storage management routines.
 *
 * Originally coded by John Rivlin / Fusion Software, Inc.
 *
 * This file incorporates replacements for the following Unix files:
 *   g_cnffil.c
 */

#include "krb.h"
#include "k5-int.h"
#include <stdio.h>
#include <assert.h>

krb5_context krb5__krb4_context = 0;

char *
krb__get_srvtabname(default_srvtabname)
	const char *default_srvtabname;
{
	const char* names[3];
	char **full_name = 0, **cpp;
	krb5_error_code retval;
	char *retname;

	if (!krb5__krb4_context) {
		retval = krb5_init_context(&krb5__krb4_context);
		if (!retval)
			return NULL;
	}
	names[0] = "libdefaults";
	names[1] = "krb4_srvtab";
	names[2] = 0;
	retval = profile_get_values(krb5__krb4_context->profile, names, 
				    &full_name);
	if (retval == 0 && full_name && full_name[0]) {
		retname = strdup(full_name[0]);
		for (cpp = full_name; *cpp; cpp++) 
			krb5_xfree(*cpp);
		krb5_xfree(full_name);
	} else {
		retname = strdup(default_srvtabname);
	}
	return retname;
}

/*
 * Returns an open file handle to the configuration file.  This
 * file was called "krb.conf" on Unix.  Here we search for the entry
 * "krb.conf=" in the "[FILES]" section of the "kerberos.ini" file
 * located in the Windows directory.  If the entry doesn't exist in
 * the kerberos.ini file, then "krb.con" in the Windows directory is
 * used in its place.
 */
FILE*
krb__get_cnffile()
{
	FILE *cnffile = 0;
	char cnfname[FILENAME_MAX];
	char defname[FILENAME_MAX];
	UINT rc;

	defname[sizeof(defname) - 1] = '\0';
	rc = GetWindowsDirectory(defname, sizeof(defname) - 1);
	assert(rc > 0);

	strncat(defname, "\\", sizeof(defname) - 1 - strlen(defname));

	strncat(defname, DEF_KRB_CONF, sizeof(defname) - 1 - strlen(defname));

	cnfname[sizeof(cnfname) - 1] = '\0';
	GetPrivateProfileString(INI_FILES, INI_KRB_CONF, defname,
		cnfname, sizeof(cnfname) - 1, KERBEROS_INI);

	cnffile = fopen(cnfname, "r");

	return cnffile;
}


/*
 * Returns an open file handle to the realms file.  This
 * file was called "krb.realms" on Unix.  Here we search for the entry
 * "krb.realms=" in the "[FILES]" section of the "kerberos.ini" file
 * located in the Windows directory.  If the entry doesn't exist in
 * the kerberos.ini file, then "krb.rea" in the Windows directory is
 * used in its place.
 */
FILE*
krb__get_realmsfile()
{
	FILE *realmsfile = 0;
	char realmsname[FILENAME_MAX];
	char defname[FILENAME_MAX];
	UINT rc;

	defname[sizeof(defname) - 1] = '\0';
	rc = GetWindowsDirectory(defname, sizeof(defname) - 1);
	assert(rc > 0);

	strncat(defname, "\\", sizeof(defname) - 1 - strlen(defname));

	strncat(defname, DEF_KRB_REALMS, sizeof(defname) - 1 - strlen(defname));

	defname[sizeof(defname) - 1] = '\0';
	GetPrivateProfileString(INI_FILES, INI_KRB_REALMS, defname,
		realmsname, sizeof(realmsname) - 1, KERBEROS_INI);

	realmsfile = fopen(realmsname, "r");

	return realmsfile;
}


/*
 * Returns the current default user.  This information is stored in
 * the [DEFAULTS] section of the "kerberos.ini" file located in the
 * Windows directory.
 */
char * KRB5_CALLCONV
krb_get_default_user()
{
	static char username[ANAME_SZ];

	GetPrivateProfileString(INI_DEFAULTS, INI_USER, "",
		username, sizeof(username), KERBEROS_INI);

	return username;
}


/*
 * Sets the default user name stored in the "kerberos.ini" file.
 */
int KRB5_CALLCONV
krb_set_default_user(username)
	char *username;
{
	BOOL rc;

	rc = WritePrivateProfileString(INI_DEFAULTS, INI_USER,
		username, KERBEROS_INI);

	if (rc)
		return KSUCCESS;
	else
		return KFAILURE;
}

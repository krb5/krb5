/*
 * lib/krb4/RealmsConfig-glue.c
 *
 * Copyright 1985-2002 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * These calls implement the layer of Kerberos v4 library which
 * accesses realms configuration by calling into the Kerberos Profile
 * library.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#if TARGET_OS_MAC
#include <CoreServices/CoreServices.h>
#endif

#include "profile.h"
#include "krb.h"
#include "krb4int.h"
#include "port-sockets.h"

#if USE_CCAPI
#include <Kerberos/CredentialsCache.h>
#endif

#define KRB5_PRIVATE 1
/* For krb5_get_default_config_files and krb5_free_config_files */
#include "krb5.h"
#undef KRB5_PRIVATE

/* These two *must* be kept in sync to avoid buffer overflows. */
#define SCNSCRATCH	"%1023s"
#define SCRATCHSZ	1024
#if SCRATCHSZ < MAXHOSTNAMELEN
#error "SCRATCHSZ must be at least MAXHOSTNAMELEN"
#endif

/*
 * Returns to the caller an initialized profile using the same files
 * as Kerberos4Lib would.
 */
int KRB5_CALLCONV
krb_get_profile(profile_t* profile)
{
    int			retval = KSUCCESS;
    profile_filespec_t	*files = NULL;

    /* Use krb5 to get the config files */
    retval = krb5_get_default_config_files(&files);

    if (retval == KSUCCESS) {
	retval = profile_init((const_profile_filespec_t *)files, profile);
    }

    if (files) {
	krb5_free_config_files(files);
    }

    if (retval == ENOENT) {
	/* No edu.mit.Kerberos file */
	return KFAILURE;
    }

    if ((retval == PROF_SECTION_NOTOP) ||
	(retval == PROF_SECTION_SYNTAX) ||
	(retval == PROF_RELATION_SYNTAX) ||
	(retval == PROF_EXTRA_CBRACE) ||
	(retval == PROF_MISSING_OBRACE)) {
	/* Bad config file format */
	return retval;
    }

    return retval;
}

/* Caller must ensure that n >= 1 and that pointers are non-NULL. */
static int
krb_prof_get_nth(
    char	*ret,
    size_t	retlen,
    const char	*realm,
    int		n,
    const char	*sec,
    const char	*key)
{
    int		result;
    long	profErr;
    profile_t	profile = NULL;
    const	char *names[4];
    void	*iter = NULL;
    char	*name = NULL;
    char	*value = NULL;
    int		i;

    result = KFAILURE;

    profErr = krb_get_profile(&profile);
    if (profErr) {
	/*
	 * Can krb_get_profile() return errors that change PROFILE?
	 */
	goto cleanup;
    }
    names[0] = sec;
    names[1] = realm;
    names[2] = key;
    names[3] = NULL;
    profErr = profile_iterator_create(profile, names,
				      PROFILE_ITER_RELATIONS_ONLY, &iter);
    if (profErr)
	goto cleanup;

    result = KSUCCESS;
    for (i = 1; i <= n; i++) {
	if (name != NULL)
	    profile_release_string(name);
	if (value != NULL)
	    profile_release_string(value);
	name = value = NULL;

	profErr = profile_iterator(&iter, &name, &value);
	if (profErr || (name == NULL)) {
	    result = KFAILURE;
	    break;
	}
    }
    if (result == KSUCCESS) {
	/* Return error rather than truncating. */
	if (strlen(value) >= retlen)
	    result = KFAILURE;
	else
	    strncpy(ret, value, retlen);
    }
cleanup:
    if (name != NULL)
	profile_release_string(name);
    if (value != NULL)
	profile_release_string(value);
    if (iter != NULL)
	profile_iterator_free(&iter);
    if (profile != NULL)
	profile_abandon(profile);
    return result;
}

/*
 * Index -> realm name mapping
 *
 * Not really. The original implementation has a cryptic comment
 * indicating that the function can only work for n = 1, and always
 * returns the default realm. I don't know _why_ that's the case, but
 * I have to do it that way...
 *
 * Old description from g_krbrlm.c:
 *
 * krb_get_lrealm takes a pointer to a string, and a number, n.  It fills
 * in the string, r, with the name of the nth realm specified on the
 * first line of the kerberos config file (KRB_CONF, defined in "krb.h").
 * It returns 0 (KSUCCESS) on success, and KFAILURE on failure.  If the
 * config file does not exist, and if n=1, a successful return will occur
 * with r = KRB_REALM (also defined in "krb.h").
 *
 * NOTE: for archaic & compatibility reasons, this routine will only return
 * valid results when n = 1.
 *
 * For the format of the KRB_CONF file, see comments describing the routine
 * krb_get_krbhst().  This will also look in KRB_FB_CONF is
 * ATHENA_CONF_FALLBACK is defined.
 */
int KRB5_CALLCONV
krb_get_lrealm(
    char	*realm,
    int		n)
{
    long	profErr = 0;
    char	*realmString = NULL;
    char	*realmStringV4 = NULL;
    profile_t	profile = NULL;
    int		result;
    FILE	*cnffile = NULL;
    char	scratch[SCRATCHSZ];

    if (n != 1 || realm == NULL)
	return KFAILURE;

    result = KFAILURE;		/* Start out with failure. */

    profErr = krb_get_profile(&profile);
    if (profErr)
	goto cleanup;

    profErr = profile_get_string(profile, REALMS_V4_PROF_LIBDEFAULTS_SECTION,
				 REALMS_V4_DEFAULT_REALM, NULL, NULL,
				 &realmString);
    if (profErr || realmString == NULL)
	goto cleanup;

    if (strlen(realmString) >= REALM_SZ)
	goto cleanup;
    strncpy(realm, realmString, REALM_SZ);
    /*
     * Step 2: the default realm is actually v5 realm, so we have to
     * check for the case where v4 and v5 realms are different.
     */
    profErr = profile_get_string(profile, "realms", realm, "v4_realm",
				 NULL, &realmStringV4);
    if (profErr || realmStringV4 == NULL)
	goto cleanup;

    if (strlen(realmStringV4) >= REALM_SZ)
	goto cleanup;
    strncpy(realm, realmStringV4, REALM_SZ);
    result = KSUCCESS;
cleanup:
    if (realmString != NULL)
	profile_release_string(realmString);
    if (realmStringV4 != NULL)
	profile_release_string(realmStringV4);
    if (profile != NULL)
	profile_abandon(profile);

    if (result == KSUCCESS)
	return result;
    /*
     * Do old-style config file lookup.
     */
    do {
	cnffile = krb__get_cnffile();
	if (cnffile == NULL)
	    break;
	if (fscanf(cnffile, SCNSCRATCH, scratch) == 1) {
	    if (strlen(scratch) >= REALM_SZ)
		result = KFAILURE;
	    else {
		strncpy(realm, scratch, REALM_SZ);
		result = KSUCCESS;
	    }
	}
	fclose(cnffile);
    } while (0);
    if (result == KFAILURE && strlen(KRB_REALM) < REALM_SZ) {
	strncpy(realm, KRB_REALM, REALM_SZ);
	result = KSUCCESS;
    }
    return result;
}

/*
 * Realm, index -> admin KDC mapping
 *
 * Old description from g_admhst.c:
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
 * provided by a nameserver.
 */
int KRB5_CALLCONV
krb_get_admhst(
    char	*host,
    char	*realm,
    int		n)
{
    int		result;
    int		i;
    FILE	*cnffile;
    char	linebuf[BUFSIZ];
    char	trealm[SCRATCHSZ];
    char	thost[SCRATCHSZ];
    char	scratch[SCRATCHSZ];

    if (n < 1 || host == NULL || realm == NULL)
	return KFAILURE;

    result = krb_prof_get_nth(host, MAXHOSTNAMELEN, realm, n,
			      REALMS_V4_PROF_REALMS_SECTION,
			      REALMS_V4_PROF_ADMIN_KDC);
    if (result == KSUCCESS)
	return result;

    /*
     * Do old-style config file lookup.
     */
    cnffile = krb__get_cnffile();
    if (cnffile == NULL)
	return KFAILURE;
    result = KSUCCESS;
    for (i = 0; i < n;) {
	if (fgets(linebuf, BUFSIZ, cnffile) == NULL) {
	    result = KFAILURE;
	    break;
	}
	if (!strchr(linebuf, '\n')) {
	    result = KFAILURE;
	    break;
	}
	/*
	 * Need to scan for a token after 'admin' to make sure that
	 * admin matched correctly.
	 */
	if (sscanf(linebuf, SCNSCRATCH " " SCNSCRATCH " admin " SCNSCRATCH,
		   trealm, thost, scratch) != 3)
	    continue;
	if (!strcmp(trealm, realm))
	    i++;
    }
    fclose(cnffile);
    if (result == KSUCCESS && strlen(thost) < MAXHOSTNAMELEN)
	strncpy(host, thost, MAXHOSTNAMELEN);
    else
	result = KFAILURE;
    return result;
}

/*
 * Realm, index -> kpasswd KDC mapping
 */
int KRB5_CALLCONV
krb_get_kpasswdhst(
    char	*host,
    char	*realm,
    int		n)
{
    if (n < 1 || host == NULL || realm == NULL)
	return KFAILURE;

    return krb_prof_get_nth(host, MAXHOSTNAMELEN, realm, n,
			    REALMS_V4_PROF_REALMS_SECTION,
			    REALMS_V4_PROF_KPASSWD_KDC);
}

static int
get_krbhst_default(h, r, n)
    char *h;
    char *r;
    int n;
{
    if (n != 1)
	return KFAILURE;
    if (strlen(KRB_HOST) + 1 + strlen(r) >= MAXHOSTNAMELEN)
	return KFAILURE;
    /* KRB_HOST.REALM (ie. kerberos.CYGNUS.COM) */
    strncpy(h, KRB_HOST, MAXHOSTNAMELEN);
    strcat(h, ".");
    strcat(h, r);
    return KSUCCESS;
}

/*
 * Realm, index -> KDC mapping
 *
 * Old description from g_krbhst.c:
 *
 * Given a Kerberos realm, find a host on which the Kerberos authenti-
 * cation server can be found.
 *
 * krb_get_krbhst takes a pointer to be filled in, a pointer to the name
 * of the realm for which a server is desired, and an integer, n, and
 * returns (in h) the nth entry from the configuration file (KRB_CONF,
 * defined in "krb.h") associated with the specified realm.
 *
 * On end-of-file, krb_get_krbhst returns KFAILURE.  If n=1 and the
 * configuration file does not exist, krb_get_krbhst will return KRB_HOST
 * (also defined in "krb.h").  If all goes well, the routine returnes
 * KSUCCESS.
 *
 * The KRB_CONF file contains the name of the local realm in the first
 * line (not used by this routine), followed by lines indicating realm/host
 * entries.  The words "admin server" following the hostname indicate that
 * the host provides an administrative database server.
 * This will also look in KRB_FB_CONF if ATHENA_CONF_FALLBACK is defined.
 *
 * For example:
 *
 *	ATHENA.MIT.EDU
 *	ATHENA.MIT.EDU kerberos-1.mit.edu admin server
 *	ATHENA.MIT.EDU kerberos-2.mit.edu
 *	LCS.MIT.EDU kerberos.lcs.mit.edu admin server
 *
 * This is a temporary hack to allow us to find the nearest system running
 * kerberos.  In the long run, this functionality will be provided by a
 * nameserver.
 */
int KRB5_CALLCONV
krb_get_krbhst(
    char	*host,
    const char	*realm,
    int		n)
{
    int		result;
    int		i;
    FILE	*cnffile;
    char	linebuf[BUFSIZ];
    char	tr[SCRATCHSZ];
    char	scratch[SCRATCHSZ];

    if (n < 1 || host == NULL || realm == NULL)
	return KFAILURE;

    result = krb_prof_get_nth(host, MAXHOSTNAMELEN, realm, n,
			      REALMS_V4_PROF_REALMS_SECTION,
			      REALMS_V4_PROF_KDC);
    if (result == KSUCCESS)
	return result;
    /*
     * Do old-style config file lookup.
     */
    do {
	cnffile = krb__get_cnffile();
	if (cnffile == NULL)
	    break;
	/* Skip default realm name. */
	if (fscanf(cnffile, SCNSCRATCH, tr) == EOF) {
	    fclose(cnffile);
	    break;
	}
	result = KSUCCESS;
	for (i = 0; i < n;) {
	    if (fgets(linebuf, BUFSIZ, cnffile) == NULL) {
		result = KFAILURE;
		break;
	    }
	    if (!strchr(linebuf, '\n')) {
		result = KFAILURE;
		break;
	    }
	    if ((sscanf(linebuf, SCNSCRATCH " " SCNSCRATCH,
			tr, scratch) != 2))
		continue;
	    if (!strcmp(tr, realm))
		i++;
	}
	fclose(cnffile);
	if (result == KSUCCESS && strlen(scratch) < MAXHOSTNAMELEN)
	    strncpy(host, scratch, MAXHOSTNAMELEN);
	else
	    result = KFAILURE;
    } while (0);
    if (result == KFAILURE)
	result = get_krbhst_default(host, realm, n);
    return result;
}

#if USE_CCAPI
/*
 * Realm -> string_to_key mapping
 */
int KRB5_CALLCONV
krb_get_stk(
    KRB_UINT32	*type,
    char	*realm)
{
    long	profErr = 0;
    const char	*names[] = {REALMS_V4_PROF_REALMS_SECTION, NULL,
			    REALMS_V4_PROF_STK, NULL};
    profile_t	profile = NULL;
    void	*iter = NULL;
    char	*name = NULL;
    char	*value = NULL;
    int		found = 0;

    names[1] = realm;

    profErr = krb_get_profile(&profile);
    if (profErr) {
	goto cleanup;
    }

    profErr = profile_iterator_create(profile, names,
				      PROFILE_ITER_RELATIONS_ONLY, &iter);
    if (profErr) {
	goto cleanup;
    }

    profErr = profile_iterator(&iter, &name, &value);
    if (profErr) {
	goto cleanup;
    }

    if (name != NULL) {
	if (!strncmp(value, REALMS_V4_MIT_STK, strlen(REALMS_V4_MIT_STK))) {
	    *type = cc_v4_stk_des;
	    found = 1;
	} else if (!strncmp(value, REALMS_V4_AFS_STK,
			    strlen(REALMS_V4_AFS_STK))) {
	    *type = cc_v4_stk_afs;
	    found = 1;
	} else if (!strncmp(value, REALMS_V4_COLUMBIA_STK,
			    strlen(REALMS_V4_COLUMBIA_STK))) {
	    *type = cc_v4_stk_columbia_special;
	    found = 1;
	}
    }

cleanup:
    if (name != NULL)
	profile_release_string(name);
    if (value != NULL)
	profile_release_string(value);
    if (iter != NULL)
	profile_iterator_free(&iter);
    if (profile != NULL)
	profile_abandon(profile);

    /* If this fails, we just rely on autodetecting the realm */
    if (!found) {
	*type = cc_v4_stk_unknown;
    }
    return KSUCCESS;
}
#endif /* USE_CCAPI */

/*
 * Hostname -> realm name mapping
 *
 * Old description from realmofhost.c:
 *
 * Given a fully-qualified domain-style primary host name,
 * return the name of the Kerberos realm for the host.
 * If the hostname contains no discernable domain, or an error occurs,
 * return the local realm name, as supplied by get_krbrlm().
 * If the hostname contains a domain, but no translation is found,
 * the hostname's domain is converted to upper-case and returned.
 *
 * The format of each line of the translation file is:
 * domain_name kerberos_realm
 * -or-
 * host_name kerberos_realm
 *
 * domain_name should be of the form .XXX.YYY (e.g. .LCS.MIT.EDU)
 * host names should be in the usual form (e.g. FOO.BAR.BAZ)
 */
char * KRB5_CALLCONV
krb_realmofhost(char *host)
{
    /* Argh! */
    static char	realm[REALM_SZ];
    char	*lhost;
    const char	*names[] = {REALMS_V4_PROF_DOMAIN_SECTION, NULL, NULL};
    char	**values = NULL;
    profile_t	profile = NULL;
    long	profErr;
    char	hostname[MAXHOSTNAMELEN];
    char	*p;
    char	*domain;
    FILE	*trans_file = NULL;
    int		retval;
    char	thost[SCRATCHSZ];
    char	trealm[SCRATCHSZ];
    struct hostent	*h;

    /* Return local realm if all else fails */
    krb_get_lrealm(realm, 1);

    /* Forward-resolve in case domain is missing. */
    h = gethostbyname(host);
    if (h == NULL)
	lhost = host;
    else
	lhost = h->h_name;

    if (strlen(lhost) >= MAXHOSTNAMELEN)
	return realm;
    strncpy(hostname, lhost, MAXHOSTNAMELEN);

    /* Remove possible trailing dot. */
    p = strrchr(hostname, '.');
    if (p != NULL && p[1] == '\0')
	*p = '\0';
    domain = strchr(hostname, '.');
    /*
     * If the hostname is just below the top, e.g., CYGNUS.COM, then
     * we special-case it; if someone really wants a realm called COM
     * they will just have to specify it properly.
     */
    if (domain != NULL) {
	domain++;
	p = strchr(domain, '.');
	if (p == NULL)
	    domain = lhost;
	if (strlen(domain) < REALM_SZ) {
	    strncpy(realm, domain, REALM_SZ);
	    /* Upcase realm name. */
	    for (p = hostname; *p != '\0'; p++) {
		if (*p > 0 && islower((unsigned char)*p))
		    *p = toupper((unsigned char)*p);
	    }
	}
    }
    /* Downcase hostname. */
    for (p = hostname; *p != '\0'; p++) {
	if (*p > 0 && isupper((unsigned char)*p))
	    *p = tolower((unsigned char)*p);
    }

    profErr = krb_get_profile(&profile);
    if (profErr)
	goto cleanup;

    for (domain = hostname; domain != NULL && *domain != '\0';) {
	names[1] = domain;
	values = NULL;
	profErr = profile_get_values(profile, names, &values);
	if (!profErr && strlen(values[0]) < REALM_SZ) {
	    /* Found, return it */
	    strncpy(realm, values[0], REALM_SZ);
	    profile_free_list(values);
	    break;
	} else {
	    /* Skip over leading dot. */
	    if (*domain == '.')
		domain++;
	    domain = strchr(domain, '.');
	}
	profile_free_list(values);
    }
cleanup:
    if (profile != NULL)
	profile_abandon(profile);

    trans_file = krb__get_realmsfile();
    if (trans_file == NULL)
	return realm;
    domain = strchr(hostname, '.');
    for (;;) {
	retval = fscanf(trans_file, SCNSCRATCH " " SCNSCRATCH,
			thost, trealm);
	if (retval == EOF)
	    break;
	if (retval != 2 || strlen(trealm) >= REALM_SZ)
	    continue;		/* Ignore malformed lines. */
	/* Attempt to match domain. */
	if (*thost == '.') {
	    if (domain && !strcasecmp(thost, domain)) {
		strncpy(realm, trealm, REALM_SZ);
		continue;	/* Try again for an exact match. */
	    }
	} else {
	    /* Hostname must match exactly. */
	    if (!strcasecmp(thost, hostname)) {
		strncpy(realm, trealm, REALM_SZ);
		break;
	    }
	}
    }
    fclose(trans_file);
    return realm;
}

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

#include "profile.h"
#include "krb.h"
#include "krb4int.h"
#include "k5-int.h"		/* for accessor, addrlist stuff */
#include "port-sockets.h"

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
	/* Don't strncpy because retlen is a guess for some callers */
	if (strlen(value) >= retlen)
	    result = KFAILURE;
	else
	    strcpy(ret, value);
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
    int         result = KSUCCESS;
    profile_t   profile = NULL;
    char       *profileDefaultRealm = NULL;
    char      **profileV4Realms = NULL;
    int         profileHasDefaultRealm = 0;
    int         profileDefaultRealmIsV4RealmInProfile = 0;
    char        krbConfLocalRealm[REALM_SZ];
    int         krbConfHasLocalRealm = 0;

    if ((realm == NULL) || (n != 1)) { result = KFAILURE; }

    if (result == KSUCCESS) {
        /* Some callers don't check the return value so we initialize
         * to an empty string in case it never gets filled in. */
        realm [0] = '\0';  
    }
    
    if (result == KSUCCESS) {
        int profileErr = krb_get_profile (&profile);

        if (!profileErr) {
            /* Get the default realm from the profile */
            profileErr = profile_get_string(profile, REALMS_V4_PROF_LIBDEFAULTS_SECTION,
                                            REALMS_V4_DEFAULT_REALM, NULL, NULL,
                                            &profileDefaultRealm);
            if (profileDefaultRealm == NULL) { profileErr = KFAILURE; }
        }

        if (!profileErr) {
            /* If there is an equivalent v4 realm to the default realm, use that instead */
            char *profileV4EquivalentRealm = NULL;

            if (profile_get_string (profile, "realms", profileDefaultRealm, "v4_realm", NULL,
                                    &profileV4EquivalentRealm) == 0 &&
                profileV4EquivalentRealm != NULL) {

                profile_release_string (profileDefaultRealm);
                profileDefaultRealm = profileV4EquivalentRealm;
            }
        }

        if (!profileErr) {
            if (strlen (profileDefaultRealm) < REALM_SZ) {
                profileHasDefaultRealm = 1;  /* a reasonable default realm */
            } else {
                profileErr = KFAILURE;
            }
        }

        if (!profileErr) {
            /* Walk through the v4 realms list looking for the default realm */
            const char *profileV4RealmsList[] = { REALMS_V4_PROF_REALMS_SECTION, NULL };

            if (profile_get_subsection_names (profile, profileV4RealmsList,
                                              &profileV4Realms) == 0 &&
                profileV4Realms != NULL) {

                char **profileRealm;
                for (profileRealm = profileV4Realms; *profileRealm != NULL; profileRealm++) {
                    if (strcmp (*profileRealm, profileDefaultRealm) == 0) {
                        /* default realm is a v4 realm */
                        profileDefaultRealmIsV4RealmInProfile = 1;
                        break;
                    }
                }
            }
        }
    }
    
    if (result == KSUCCESS) {
        /* Try to get old-style config file lookup for fallback. */
        FILE	*cnffile = NULL;
        char	scratch[SCRATCHSZ];

        cnffile = krb__get_cnffile();
        if (cnffile != NULL) {
            if (fscanf(cnffile, SCNSCRATCH, scratch) == 1) {
                if (strlen(scratch) < REALM_SZ) {
                    strncpy(krbConfLocalRealm, scratch, REALM_SZ);
                    krbConfHasLocalRealm = 1;
                }
            }
            fclose(cnffile);
        }
    }

    if (result == KSUCCESS) {
        /*
         * We want to favor the profile value over the krb.conf value
         * but not stop suppporting its use with a v5-only profile. 
         * So we only use the krb.conf realm when the default profile
         * realm doesn't exist in the v4 realm section of the profile.
         */
        if (krbConfHasLocalRealm && !profileDefaultRealmIsV4RealmInProfile) {
            strncpy (realm, krbConfLocalRealm, REALM_SZ);
        } else if (profileHasDefaultRealm) {
            strncpy (realm, profileDefaultRealm, REALM_SZ);
        } else {
            result = KFAILURE;  /* No default realm */
        }
    }

    if (profileDefaultRealm != NULL) { profile_release_string (profileDefaultRealm); }
    if (profileV4Realms     != NULL) { profile_free_list (profileV4Realms); }
    if (profile             != NULL) { profile_abandon (profile); }

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
    if (result == KSUCCESS && strlen(thost) < MAX_HSTNM)
	strcpy(host, thost);
    else
	result = KFAILURE;
    return result;
}

/*
 * Realm, index -> kpasswd KDC mapping
 */
int
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
#ifdef KRB5_DNS_LOOKUP
static struct {
    time_t when;
    char realm[REALM_SZ+1];
    struct srv_dns_entry *srv;
} dnscache = { 0, { 0 }, 0 };
#define DNS_CACHE_TIMEOUT	60 /* seconds */
#endif

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
#ifdef KRB5_DNS_LOOKUP
    time_t now;
#endif

    if (n < 1 || host == NULL || realm == NULL)
	return KFAILURE;

#ifdef KRB5_DNS_LOOKUP
    /* We'll only have this realm's info in the DNS cache if there is
       no data in the local config files.

       XXX The files could've been updated in the last few seconds.
       Do we care?  */
    if (!strncmp(dnscache.realm, realm, REALM_SZ)
	&& (time(&now), abs(dnscache.when - now) < DNS_CACHE_TIMEOUT)) {
	struct srv_dns_entry *entry;

    get_from_dnscache:
	/* n starts at 1, addrs indices run 0..naddrs */
	for (i = 1, entry = dnscache.srv; i < n && entry; i++)
	    entry = entry->next;
	if (entry == NULL)
	    return KFAILURE;
	if (strlen(entry->host) + 6 >= MAXHOSTNAMELEN)
	    return KFAILURE;
	snprintf(host, MAXHOSTNAMELEN, "%s:%d", entry->host, entry->port);
	return KSUCCESS;
    }
#endif

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
	if (result == KSUCCESS && strlen(scratch) < MAXHOSTNAMELEN) {
	    strcpy(host, scratch);
	    return KSUCCESS;
	}
	if (i > 0)
	    /* Found some, but not as many as requested.  */
	    return KFAILURE;
    } while (0);
#ifdef KRB5_DNS_LOOKUP
    do {
	krb5int_access k5;
	krb5_error_code err;
	krb5_data realmdat;
	struct srv_dns_entry *srv;

	err = krb5int_accessor(&k5, KRB5INT_ACCESS_VERSION);
	if (err)
	    break;

	if (k5.use_dns_kdc(krb5__krb4_context)) {
	    realmdat.data = realm;
	    realmdat.length = strlen(realm);
	    err = k5.make_srv_query_realm(&realmdat, "_kerberos-iv", "_udp",
					  &srv);
	    if (err)
		break;

	    if (srv == 0)
		break;

	    if (dnscache.srv)
		k5.free_srv_dns_data(dnscache.srv);
	    dnscache.srv = srv;
	    strncpy(dnscache.realm, realm, REALM_SZ);
	    dnscache.when = now;
	    goto get_from_dnscache;
	}
    } while (0);
#endif
    return KFAILURE;
}

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
    strcpy(hostname, lhost);

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

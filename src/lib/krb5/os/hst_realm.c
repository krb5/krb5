/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/os/hst_realm.c */
/*
 * Copyright 1990,1991,2002,2008,2009 by the Massachusetts Institute of
 * Technology.  All Rights Reserved.
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
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * krb5_get_host_realm()
 * krb5_get_fallback_host_realm()
 * krb5int_clean_hostname()
 * krb5_free_host_realm()
 */


/*
  Figures out the Kerberos realm names for host, filling in a
  pointer to an argv[] style list of names, terminated with a null pointer.

  If host is NULL, the local host's realms are determined.

  If there are no known realms for the host, the filled-in pointer is set
  to NULL.

  The pointer array and strings pointed to are all in allocated storage,
  and should be freed by the caller when finished.

  returns system errors
*/

/*
 * Implementation notes:
 *
 * this implementation only provides one realm per host, using the same
 * mapping file used in kerberos v4.

 * Given a fully-qualified domain-style primary host name,
 * return the name of the Kerberos realm for the host.
 * If the hostname contains no discernable domain, or an error occurs,
 * return the local realm name, as supplied by krb5_get_default_realm().
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


#include "k5-int.h"
#include "os-proto.h"
#include <ctype.h>
#include <stdio.h>
#ifdef HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "fake-addrinfo.h"

static krb5_error_code
domain_heuristic(krb5_context context, const char *domain,
                 char **realm, int limit);

#ifdef KRB5_DNS_LOOKUP
#include "dnsglue.h"
#else
#ifndef MAXDNAME
#define MAXDNAME (16 * MAXHOSTNAMELEN)
#endif /* MAXDNAME */
#endif /* KRB5_DNS_LOOKUP */

krb5_error_code krb5int_translate_gai_error (int);

static krb5_error_code
get_fq_hostname(char *buf, size_t bufsize, const char *name)
{
    struct addrinfo *ai, hints;
    int err;

    memset (&hints, 0, sizeof (hints));
    hints.ai_flags = AI_CANONNAME | AI_ADDRCONFIG;
    err = getaddrinfo (name, 0, &hints, &ai);
    if (err)
        return krb5int_translate_gai_error (err);
    if (ai->ai_canonname == NULL) {
        freeaddrinfo(ai);
        return KRB5_EAI_FAIL;
    }
    strncpy (buf, ai->ai_canonname, bufsize);
    buf[bufsize-1] = 0;
    freeaddrinfo (ai);
    return 0;
}

/* Get the local host name, try to make it fully-qualified.
   Always return a null-terminated string.
   Might return an error if gethostname fails.  */
krb5_error_code
krb5int_get_fq_local_hostname(char *buf, size_t bufsiz)
{
    buf[0] = 0;
    if (gethostname (buf, bufsiz) == -1)
        return SOCKET_ERRNO;
    buf[bufsiz - 1] = 0;
    return get_fq_hostname (buf, bufsiz, buf);
}

krb5_error_code KRB5_CALLCONV
krb5_get_host_realm(krb5_context context, const char *host, char ***realmsp)
{
    char **retrealms;
    char *realm, *cp, *temp_realm;
    krb5_error_code retval;
    char local_host[MAXDNAME+1];

    TRACE_GET_HOST_REALM(context, host);

    retval = krb5int_clean_hostname(context, host, local_host, sizeof local_host);
    if (retval)
        return retval;

    /*
      Search for the best match for the host or domain.
      Example: Given a host a.b.c.d, try to match on:
      1) A.B.C.D
      2) .B.C.D
      3) B.C.D
      4) .C.D
      5) C.D
      6) .D
      7) D
    */

    cp = local_host;
    TRACE_GET_HOST_REALM_LOCALHOST(context, local_host);
    realm = (char *)NULL;
    temp_realm = 0;
    while (cp) {
        TRACE_GET_HOST_REALM_DOMAIN_REALM_MAP(context, cp);
        retval = profile_get_string(context->profile, KRB5_CONF_DOMAIN_REALM, cp,
                                    0, (char *)NULL, &temp_realm);
        if (retval)
            return retval;
        if (temp_realm != (char *)NULL)
            break;      /* Match found */

        /* Setup for another test */
        if (*cp == '.') {
            cp++;
        } else {
            cp = strchr(cp, '.');
        }
    }
    if (temp_realm) {
        TRACE_GET_HOST_REALM_TEMP_REALM(context, temp_realm);
        realm = strdup(temp_realm);
        if (!realm) {
            profile_release_string(temp_realm);
            return ENOMEM;
        }
        profile_release_string(temp_realm);
    }

    if (realm == (char *)NULL) {
        if (!(cp = strdup(KRB5_REFERRAL_REALM)))
            return ENOMEM;
        realm = cp;
    }

    if (!(retrealms = (char **)calloc(2, sizeof(*retrealms)))) {
        if (realm != (char *)NULL)
            free(realm);
        return ENOMEM;
    }

    retrealms[0] = realm;
    retrealms[1] = 0;

    TRACE_GET_HOST_REALM_RETURN(context, host, realm);
    *realmsp = retrealms;
    return 0;
}

#if defined(_WIN32) && !defined(__CYGWIN32__)
# ifndef EAFNOSUPPORT
#  define EAFNOSUPPORT WSAEAFNOSUPPORT
# endif
#endif

krb5_error_code
krb5int_translate_gai_error (int num)
{
    switch (num) {
#ifdef EAI_ADDRFAMILY
    case EAI_ADDRFAMILY:
        return EAFNOSUPPORT;
#endif
    case EAI_AGAIN:
        return EAGAIN;
    case EAI_BADFLAGS:
        return EINVAL;
    case EAI_FAIL:
        return KRB5_EAI_FAIL;
    case EAI_FAMILY:
        return EAFNOSUPPORT;
    case EAI_MEMORY:
        return ENOMEM;
#if defined(EAI_NODATA) && EAI_NODATA != EAI_NONAME
    case EAI_NODATA:
        return KRB5_EAI_NODATA;
#endif
    case EAI_NONAME:
        return KRB5_EAI_NONAME;
#if defined(EAI_OVERFLOW)
    case EAI_OVERFLOW:
        return EINVAL;          /* XXX */
#endif
    case EAI_SERVICE:
        return KRB5_EAI_SERVICE;
    case EAI_SOCKTYPE:
        return EINVAL;
#ifdef EAI_SYSTEM
    case EAI_SYSTEM:
        return errno;
#endif
    }
    abort ();
    return -1;
}


/*
 * Ganked from krb5_get_host_realm; handles determining a fallback realm
 * to try in the case where referrals have failed and it's time to go
 * look at TXT records or make a DNS-based assumption.
 */

krb5_error_code KRB5_CALLCONV
krb5_get_fallback_host_realm(krb5_context context,
                             krb5_data *hdata, char ***realmsp)
{
    char **retrealms;
    char *realm, *cp;
    krb5_error_code retval;
    char local_host[MAXDNAME+1], host[MAXDNAME+1];

    /* Convert what we hope is a hostname to a string. */
    memcpy(host, hdata->data, hdata->length);
    host[hdata->length]=0;

    TRACE_GET_FALLBACK_HOST_REALM(context, host);

    retval = krb5int_clean_hostname(context, host, local_host, sizeof local_host);
    if (retval)
        return retval;

    /*
     * Try looking up a _kerberos.<hostname> TXT record in DNS.  This
     * heuristic is turned off by default since, in the absence of
     * secure DNS, it can allow an attacker to control the realm used
     * for a host.
     */
    realm = (char *)NULL;
#ifdef KRB5_DNS_LOOKUP
    if (_krb5_use_dns_realm(context)) {
        cp = local_host;
        do {
            retval = krb5_try_realm_txt_rr("_kerberos", cp, &realm);
            cp = strchr(cp,'.');
            if (cp)
                cp++;
        } while (retval && cp && cp[0]);
    }
#endif /* KRB5_DNS_LOOKUP */

    /*
     * Next try searching the domain components as realms.  This
     * heuristic is also turned off by default.  If DNS lookups for
     * KDCs are enabled (as they are by default), an attacker could
     * control which domain component is used as the realm for a host.
     */
    if (realm == (char *)NULL) {
        int limit;
        errcode_t code;

        code = profile_get_integer(context->profile, KRB5_CONF_LIBDEFAULTS,
                                   KRB5_CONF_REALM_TRY_DOMAINS, 0, -1, &limit);
        if (code == 0) {
            retval = domain_heuristic(context, local_host, &realm, limit);
            if (retval)
                return retval;
        }
    }

    /*
     * The next fallback--and the first one to apply with default
     * configuration--is to use the upper-cased parent domain of the
     * hostname, regardless of whether we can actually look it up as a
     * realm.
     */
    if (realm == (char *)NULL) {
        cp = strchr(local_host, '.');
        if (cp) {
            if (!(realm = strdup(cp + 1)))
                return ENOMEM;
            for (cp = realm; *cp; cp++)
                if (islower((int) (*cp)))
                    *cp = toupper((int) *cp);
        }
    }

    /*
     * The final fallback--used when the fully-qualified hostname has
     * only one component--is to use the local default realm.
     */
    if (realm == (char *)NULL) {
        retval = krb5_get_default_realm(context, &realm);
        if (retval)
            return retval;
    }

    if (!(retrealms = (char **)calloc(2, sizeof(*retrealms)))) {
        if (realm != (char *)NULL)
            free(realm);
        return ENOMEM;
    }

    retrealms[0] = realm;
    retrealms[1] = 0;

    TRACE_GET_FALLBACK_HOST_REALM_RETURN(context, host, realm);
    *realmsp = retrealms;
    return 0;
}

/*
 * Common code for krb5_get_host_realm and krb5_get_fallback_host_realm
 * to do basic sanity checks on supplied hostname.
 */
krb5_error_code
krb5int_clean_hostname(krb5_context context,
                       const char *host, char *local_host, size_t lhsize)
{
    char *cp;
    krb5_error_code retval;
    int l;

    local_host[0]=0;
    if (host) {
        /* Filter out numeric addresses if the caller utterly failed to
           convert them to names.  */
        /* IPv4 - dotted quads only */
        if (strspn(host, "01234567890.") == strlen(host)) {
            /* All numbers and dots... if it's three dots, it's an
               IP address, and we reject it.  But "12345" could be
               a local hostname, couldn't it?  We'll just assume
               that a name with three dots is not meant to be an
               all-numeric hostname three all-numeric domains down
               from the current domain.  */
            int ndots = 0;
            const char *p;
            for (p = host; *p; p++)
                if (*p == '.')
                    ndots++;
            if (ndots == 3)
                return KRB5_ERR_NUMERIC_REALM;
        }
        if (strchr(host, ':'))
            /* IPv6 numeric address form?  Bye bye.  */
            return KRB5_ERR_NUMERIC_REALM;

        /* Should probably error out if strlen(host) > MAXDNAME.  */
        strncpy(local_host, host, lhsize);
        local_host[lhsize - 1] = '\0';
    } else {
        retval = krb5int_get_fq_local_hostname (local_host, lhsize);
        if (retval)
            return retval;
    }

    /* fold to lowercase */
    for (cp = local_host; *cp; cp++) {
        if (isupper((unsigned char) (*cp)))
            *cp = tolower((unsigned char) *cp);
    }
    l = strlen(local_host);
    /* strip off trailing dot */
    if (l && local_host[l-1] == '.')
        local_host[l-1] = 0;

    return 0;
}

/*
 * Walk through the components of a domain.  At each stage determine
 * if a KDC can be located for that domain.  Return a realm
 * corresponding to the upper-cased domain name for which a KDC was
 * found or NULL if no KDC was found.  Stop searching after limit
 * labels have been removed from the domain (-1 means don't search at
 * all, 0 means try only the full domain itself, 1 means also try the
 * parent domain, etc.) or when we reach a parent with only one label.
 */
static krb5_error_code
domain_heuristic(krb5_context context, const char *domain,
                 char **realm, int limit)
{
    krb5_error_code retval = 0, r;
    struct serverlist slist;
    krb5_data drealm;
    char *cp = NULL, *fqdn, *dot;

    *realm = NULL;
    if (limit < 0)
        return 0;

    memset(&drealm, 0, sizeof (drealm));
    fqdn = strdup(domain);
    if (!fqdn) {
        retval = ENOMEM;
        goto cleanup;
    }

    /* Upper case the domain (for use as a realm) */
    for (cp = fqdn; *cp; cp++) {
        if (islower((int)(*cp)))
            *cp = toupper((int)*cp);
    }

    /* Search up to limit parents, as long as we have multiple labels. */
    cp = fqdn;
    while (limit-- >= 0 && (dot = strchr(cp, '.')) != NULL) {

        drealm.length = strlen(cp);
        drealm.data = cp;

        /* Find a kdc based on this part of the domain name. */
        r = k5_locate_kdc(context, &drealm, &slist, FALSE, SOCK_DGRAM);
        if (!r) { /* Found a KDC! */
            k5_free_serverlist(&slist);
            *realm = strdup(cp);
            if (!*realm) {
                retval = ENOMEM;
                goto cleanup;
            }
            break;
        }

        cp = dot + 1;
    }

cleanup:
    free(fqdn);
    return retval;
}

/*
 * Frees the storage taken by a realm list returned by krb5_get_host_realm.
 */

krb5_error_code KRB5_CALLCONV
krb5_free_host_realm(krb5_context context, char *const *realmlist)
{
    /* same format, so why duplicate code? */
    return krb5_free_krbhst(context, realmlist);
}

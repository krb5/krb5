/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/os/hst_realm.c - Hostname to realm translation */
/*
 * Copyright 1990,1991,2002,2008,2009,2013 by the Massachusetts Institute of
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

#include "k5-int.h"
#include "os-proto.h"
#include <ctype.h>

#include "fake-addrinfo.h"

#ifdef KRB5_DNS_LOOKUP
#include "dnsglue.h"
#else
#ifndef MAXDNAME
#define MAXDNAME (16 * MAXHOSTNAMELEN)
#endif /* MAXDNAME */
#endif /* KRB5_DNS_LOOKUP */

#if defined(_WIN32) && !defined(__CYGWIN32__)
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT WSAEAFNOSUPPORT
#endif
#endif

static krb5_error_code
krb5int_translate_gai_error(int num)
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
    abort();
    return -1;
}

/* Get the canonical form of the local host name, using forward
 * canonicalization only. */
krb5_error_code
krb5int_get_fq_local_hostname(char *buf, size_t bufsize)
{
    struct addrinfo *ai, hints;
    int err;

    buf[0] = '\0';
    if (gethostname(buf, bufsize) == -1)
        return SOCKET_ERRNO;

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_CANONNAME | AI_ADDRCONFIG;
    err = getaddrinfo(buf, NULL, &hints, &ai);
    if (err)
        return krb5int_translate_gai_error(err);
    if (ai->ai_canonname == NULL) {
        freeaddrinfo(ai);
        return KRB5_EAI_FAIL;
    }
    if (strlcpy(buf, ai->ai_canonname, bufsize) >= bufsize)
        return ENOMEM;
    freeaddrinfo(ai);
    return 0;
}

/* Return true if name appears to be an IPv4 or IPv6 address. */
static krb5_boolean
is_numeric_address(const char *name)
{
    int ndots = 0;
    const char *p;

    /* If name contains only numbers and three dots, consider it to be an IPv4
     * address. */
    if (strspn(name, "01234567890.") == strlen(name)) {
        for (p = name; *p; p++) {
            if (*p == '.')
                ndots++;
        }
        if (ndots == 3)
            return TRUE;
    }

    /* If name contains a colon, consider it to be an IPv6 address. */
    if (strchr(name, ':') != NULL)
        return TRUE;

    return FALSE;
}

/*
 * Search progressively shorter suffixes of host in the [domain_realms] section
 * of the profile to find the realm.  For example, given a host a.b.c, try to
 * match a.b.c, then .b.c, then b.c, then .c, then c.  If we don't find a
 * match, return success but set *realm_out to NULL.
 */
static krb5_error_code
search_domain_realm(krb5_context context, const char *host, char **realm_out)
{
    krb5_error_code ret;
    const char *p;
    char *prof_realm;

    *realm_out = NULL;
    for (p = host; p != NULL; p = (*p == '.') ? p + 1 : strchr(p, '.')) {
        ret = profile_get_string(context->profile, KRB5_CONF_DOMAIN_REALM, p,
                                 NULL, NULL, &prof_realm);
        if (ret)
            return ret;
        if (prof_realm != NULL) {
            *realm_out = strdup(prof_realm);
            profile_release_string(prof_realm);
            if (*realm_out == NULL)
                return ENOMEM;
            return 0;
        }
    }
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_get_host_realm(krb5_context context, const char *host, char ***realmsp)
{
    char **retrealms, *realm = NULL;
    krb5_error_code ret;
    char cleanname[MAXDNAME + 1];

    *realmsp = NULL;

    ret = k5_clean_hostname(context, host, cleanname, sizeof(cleanname));
    if (ret)
        return ret;

    /* Search the [domain_realm] profile section unless the hostname looks like
     * an IP address. */
    if (!is_numeric_address(cleanname))
        ret = search_domain_realm(context, cleanname, &realm);

    /* If we didn't find a match, return the referral realm. */
    if (realm == NULL) {
        realm = strdup(KRB5_REFERRAL_REALM);
        if (realm == NULL)
            return ENOMEM;
    }

    retrealms = calloc(2, sizeof(*retrealms));
    if (retrealms == NULL) {
        free(realm);
        return ENOMEM;
    }

    retrealms[0] = realm;
    retrealms[1] = 0;

    TRACE_GET_HOST_REALM_RETURN(context, host, realm);
    *realmsp = retrealms;
    return 0;
}

/*
 * Walk through the components of a domain.  At each stage determine if a KDC
 * can be located for that domain.  Return a realm corresponding to the
 * upper-cased domain name for which a KDC was found or NULL if no KDC was
 * found.  Stop searching after limit labels have been removed from the domain
 * (-1 means don't search at all, 0 means try only the full domain itself, 1
 * means also try the parent domain, etc.) or when we reach a parent with only
 * one label.
 */
static krb5_error_code
domain_heuristic(krb5_context context, const char *domain, char **realm,
                 int limit)
{
    krb5_error_code ret = 0, r;
    struct serverlist slist;
    krb5_data drealm;
    char *p = NULL, *fqdn, *dot;

    *realm = NULL;
    if (limit < 0)
        return 0;

    memset(&drealm, 0, sizeof(drealm));
    fqdn = strdup(domain);
    if (fqdn == NULL) {
        ret = ENOMEM;
        goto cleanup;
    }

    /* Upper case the domain (for use as a realm). */
    for (p = fqdn; *p != '\0'; p++) {
        if (islower((unsigned char)*p))
            *p = toupper((unsigned char)*p);
    }

    /* Search up to limit parents, as long as we have multiple labels. */
    p = fqdn;
    while (limit-- >= 0 && (dot = strchr(p, '.')) != NULL) {
        /* Find a KDC based on this part of the domain name. */
        drealm = string2data(p);
        r = k5_locate_kdc(context, &drealm, &slist, FALSE, SOCK_DGRAM);
        if (r == 0) {
            k5_free_serverlist(&slist);
            *realm = strdup(p);
            if (*realm == NULL) {
                ret = ENOMEM;
                goto cleanup;
            }
            break;
        }

        p = dot + 1;
    }

cleanup:
    free(fqdn);
    return ret;
}

/*
 * Determine the fallback realm.  Used by krb5_get_credentials after referral
 * processing has failed, to look at TXT records or make a DNS-based
 * assumption.
 */
krb5_error_code KRB5_CALLCONV
krb5_get_fallback_host_realm(krb5_context context, krb5_data *hdata,
                             char ***realmsp)
{
    char **retrealms, *p, *realm = NULL, *host, cleanname[MAXDNAME + 1];
    krb5_error_code ret;
    int limit;
    errcode_t code;
    krb5_boolean is_numeric;

    *realmsp = NULL;

    /* Convert hdata into a string and clean it up. */
    host = k5memdup0(hdata->data, hdata->length, &ret);
    if (host == NULL)
        return ret;
    ret = k5_clean_hostname(context, host, cleanname, sizeof(cleanname));
    free(host);
    if (ret)
        return ret;
    is_numeric = is_numeric_address(cleanname);

    /*
     * Try looking up a _kerberos.<hostname> TXT record in DNS.  This heuristic
     * is turned off by default since, in the absence of secure DNS, it can
     * allow an attacker to control the realm used for a host.
     */
#ifdef KRB5_DNS_LOOKUP
    if (_krb5_use_dns_realm(context) && !is_numeric) {
        p = cleanname;
        do {
            ret = krb5_try_realm_txt_rr("_kerberos", p, &realm);
            p = strchr(p, '.');
            if (p != NULL)
                p++;
        } while (ret && p != NULL && *p != '\0');
    }
#endif /* KRB5_DNS_LOOKUP */

    /*
     * Next try searching the domain components as realms.  This heuristic is
     * also turned off by default.  If DNS lookups for KDCs are enabled (as
     * they are by default), an attacker could control which domain component
     * is used as the realm for a host.
     */
    if (realm == NULL && !is_numeric) {
        code = profile_get_integer(context->profile, KRB5_CONF_LIBDEFAULTS,
                                   KRB5_CONF_REALM_TRY_DOMAINS, 0, -1, &limit);
        if (code == 0) {
            ret = domain_heuristic(context, cleanname, &realm, limit);
            if (ret)
                return ret;
        }
    }

    /*
     * The next fallback--and the first one to apply with default
     * configuration--is to use the upper-cased parent domain of the hostname,
     * regardless of whether we can actually look it up as a realm.
     */
    if (realm == NULL && !is_numeric) {
        p = strchr(cleanname, '.');
        if (p) {
            realm = strdup(p + 1);
            if (realm == NULL)
                return ENOMEM;
            for (p = realm; *p != '\0'; p++) {
                if (islower((unsigned char)*p))
                    *p = toupper((unsigned char)*p);
            }
        }
    }

    /*
     * The final fallback--used when the fully-qualified hostname has only one
     * component--is to use the local default realm.
     */
    if (realm == NULL) {
        ret = krb5_get_default_realm(context, &realm);
        if (ret)
            return ret;
    }

    retrealms = calloc(2, sizeof(*retrealms));
    if (retrealms == NULL) {
        free(realm);
        return ENOMEM;
    }

    retrealms[0] = realm;
    retrealms[1] = 0;

    TRACE_GET_FALLBACK_HOST_REALM_RETURN(context, host, realm);
    *realmsp = retrealms;
    return 0;
}

/* Common code for krb5_get_host_realm and krb5_get_fallback_host_realm
 * to do basic sanity checks on supplied hostname. */
krb5_error_code
k5_clean_hostname(krb5_context context, const char *host, char *cleanname,
                  size_t lhsize)
{
    char *p;
    krb5_error_code ret;
    size_t l;

    cleanname[0] = '\0';
    if (host) {
        if (strlcpy(cleanname, host, lhsize) >= lhsize)
            return ENOMEM;
    } else {
        ret = krb5int_get_fq_local_hostname(cleanname, lhsize);
        if (ret)
            return ret;
    }

    /* Fold to lowercase. */
    for (p = cleanname; *p; p++) {
        if (isupper((unsigned char)*p))
            *p = tolower((unsigned char)*p);
    }

    /* Strip off trailing dot. */
    l = strlen(cleanname);
    if (l > 0 && cleanname[l - 1] == '.')
        cleanname[l - 1] = '\0';

    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_free_host_realm(krb5_context context, char *const *realmlist)
{
    char *const *p;

    if (realmlist == NULL)
        return 0;
    for (p = realmlist; *p; p++)
        free(*p);
    free((char **)realmlist);
    return 0;
}

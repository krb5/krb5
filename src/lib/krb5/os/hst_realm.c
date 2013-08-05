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
krb5_boolean
k5_is_numeric_address(const char *name)
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

/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/os/hostream_unbound.c - Unbound security-assuring hostrealm module */
/*
 * Copyright (C)2016 Rick van Rein, for SURFnet and the ARPA2.net project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This file implements the built-in unbound module for the hostrealm interface,
 * which uses TXT records in the DNS to securely determine the realm of a host.
 * Unlike the dns builtin module, it uses Unbound's capability of assuring a
 * path from a configured trust anchor (usually the DNS root) down to the data
 * reported.  Also unlike the dns builtin module, it will not iterate to parent
 * names, because that would risk crossing a zone apex (for which the IETF
 * has not agreed on a standard detection method) to realm under separate, and
 * therefore potentially rogue, administrative control.
 *
 * This module implements draft-vanrein-dnstxt-krb1.
 */

#include "k5-int.h"
#include "../../../lib/krb5/os/os-proto.h"
#include <krb5/hostrealm_plugin.h>

#ifdef DNSSEC_IMPL_UNBOUND
#include "../../../lib/krb5/os/dnsglue.h"

#include <unbound.h>

static struct ub_ctx *ubctx = NULL;

/* Initialise module data. */
static krb5_error_code
unbound_init(krb5_context context, krb5_hostrealm_moddata *data) {
    krb5_error_code ret;
    char *tafile = NULL;
    assert (ubctx == NULL);
    ubctx = ub_ctx_create ();
    if (ubctx == NULL) {
        return KRB5KDC_ERR_INVALID_SIG;
    }
    ret = profile_get_string(context->profile,
                             KRB5_CONF_LIBDEFAULTS,
                             KRB5_CONF_DNSSEC_TRUST_ANCHOR_UNBOUND,
                             NULL,
                             "/etc/unbound/root.key",
                             &tafile);
    if (ret != 0)
        return ret;
    if (ub_ctx_add_ta_autr (ubctx, tafile))
        return KRB5KDC_ERR_INVALID_SIG;
    return 0;
}

/* Release resources used by module data. */
static void
unbound_fini(krb5_context context, krb5_hostrealm_moddata data) {
    ub_ctx_delete (ubctx);
    ubctx = NULL;
}

static void
unbound_free_realmlist(krb5_context context, krb5_hostrealm_moddata data,
                       char **list)
{
    int ans;
    if (*list == NULL)
        return;
    for (ans=0; list[ans] != NULL; ans++) {
        free (list [ans]);
    }
    free (list);
}

static krb5_error_code
unbound_do_resolve (krb5_context context, krb5_hostrealm_moddata data,
                    const char *host, char ***realms_out, int insist_dnssec)
{
    krb5_error_code ret = KRB5_PLUGIN_NO_HANDLE;
    int ubrv = -1;
    struct ub_result *ubres = NULL;
    int ans, ansidx;
    char **realms_int = NULL;
    char _kerberos_host [11 + strlen (host)];

    *realms_out = NULL;

    /* Prefix the _kerberos label and perform an IN TXT query */
    strcpy (_kerberos_host, "_kerberos.");
    strcat (_kerberos_host, host);
    ubrv = ub_resolve (ubctx,
                       _kerberos_host, 16 /*TXT*/, 1 /*IN*/,
                       &ubres);
    if (ubrv != 0)
        goto cleanup;

    /* Interpret the security status of the result */
    if (ubres->bogus)
        goto cleanup;
    if (insist_dnssec && !ubres->secure) {
        ret = KRB5KDC_ERR_INVALID_SIG;
        goto cleanup;
    }
    ret = KRB5_ERR_HOST_REALM_UNKNOWN;
    if (ubres->nxdomain)
        goto cleanup;
    if (!ubres->havedata)
        goto cleanup;
    ret = KRB5_REALM_CANT_RESOLVE;
    if (ubres->qtype != 16 /*TXT*/)
        goto cleanup;
    if (ubres->qclass != 1 /*IN*/)
        goto cleanup;

    /* Count the number of entries to facilitate */
    for (ans = 0; ubres->data [ans] != NULL; ans++)
        ;
    realms_int = calloc (ans + 1, sizeof (char *));
    if (realms_int == NULL)
        goto cleanup;

    /* Fill the response structure with the TXT records' first strings */
    /* Treating binary data as string; could check internal \0 and UTF-8 mistakes */
    ansidx = 0;
    for (ans = 0; ubres->data [ans] != NULL; ans++) {
        int anslen = (int) (uint8_t) ubres->data [ans][0];
        // Validate the length of the first <character-string> in the TXT RR
        if (ubres->len [ans] < anslen + 1)
            goto cleanup;
        // Skip any empty strings (ASCII or internationalised)
        if (anslen == 0)
            continue;
        if ((anslen == 3) && (memcmp (ubres->data [ans] + 1, "\x1b%G", 3) == 0))
            continue;
        realms_int [ansidx] = malloc (anslen + 1);
        memcpy (realms_int [ansidx], &ubres->data [ans][1], anslen);
        realms_int [ansidx][anslen] = '\0';
        ansidx++;
    }
    realms_int [ans] = NULL;

    /* Return the (now properly constructed) realm string list */
    *realms_out = realms_int;
    realms_int = NULL;
    ret = 0;

    /* Cleanup any half-done work and return a result */
cleanup:
    if (ubres != NULL)
        ub_resolve_free (ubres);
    if (realms_int != NULL)
        unbound_free_realmlist (context, data, realms_int);
    return ret;
}

/* For host_realm lookup, insist on DNSSEC because the alternative is unsafe.
 * This means that opt-out from DNSSEC will not be tolerated.
 */
static krb5_error_code
unbound_host_realm(krb5_context context, krb5_hostrealm_moddata data,
                   const char *host, char ***realms_out)
{
    return unbound_do_resolve (context, data, host, realms_out, 1);
}

/* The fallback method may be insecure, so we tolerate opt-out from DNSSEC.
 */
static krb5_error_code
unbound_fallback_realm(krb5_context context, krb5_hostrealm_moddata data,
                       const char *host, char ***realms_out)
{
    return unbound_do_resolve (context, data, host, realms_out, 0);
}

/* The default realm is our local responsibility; we tolerate opt-out from DNSSEC.
 * This function can only work if gethostname() returns an FQDN; without that, it
 * has no grounds for securely resolving its own host, let alone its realm.
 */
static krb5_error_code
unbound_default_realm(krb5_context context, krb5_hostrealm_moddata data,
                      char ***realms_out)
{
    krb5_error_code ret;
    char host[MAXDNAME + 2];

    *realms_out = NULL;

    // Ask for our own name without getting out to DNS
    ret = gethostname (host, sizeof (host));
    if (ret != 0)
        return KRB5_PLUGIN_NO_HANDLE;

    // Assure size constraints without cut-off
    host [MAXDNAME + 1] = '\0';
    if (strlen (host) > MAXDNAME)
        return KRB5_PLUGIN_NO_HANDLE;

    // Test whether this looks like a FQDN instead of just a host name
    if (strchr (host, '.') == NULL)
        return KRB5_PLUGIN_NO_HANDLE;

    return unbound_do_resolve (context, data, host, realms_out, 0);
}

krb5_error_code
hostrealm_unbound_initvt(krb5_context context, int maj_ver, int min_ver,
                         krb5_plugin_vtable vtable)
{
    krb5_hostrealm_vtable vt = (krb5_hostrealm_vtable)vtable;
    char *flag;
    krb5_error_code ret;

    // Only service recognisable major versions
    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;

    // When present, the dnssec_lookup_realm flag must be set to "yes" or "true"
    ret = profile_get_string(context->profile,
                             KRB5_CONF_LIBDEFAULTS,
                             KRB5_CONF_DNSSEC_LOOKUP_REALM,
                             NULL,
                             "no",
                             &flag);
    if ((ret == 0) && (strcasecmp (flag, "true") != 0) && (strcasecmp (flag, "yes") != 0))
        return KRB5_PLUGIN_NO_HANDLE;

    // Only fill the functions for minor numbers recognised (given the one major)
    if (min_ver >= 1) {
        vt->name = "unbound";
        vt->init = unbound_init;
        vt->fini = unbound_fini;
        vt->host_realm = unbound_host_realm;
        vt->fallback_realm = unbound_fallback_realm;
        vt->default_realm = unbound_default_realm;
        vt->free_list = unbound_free_realmlist;
    }
    return 0;
}

#else /* DNSSEC_IMPL_UNBOUND */

#if 0 /* ONLY USEFUL FOR BUILTIN MODULES */

krb5_error_code
hostrealm_unbound_initvt(krb5_context context, int maj_ver, int min_ver,
                         krb5_plugin_vtable vtable)
{
    krb5_hostrealm_vtable vt = (krb5_hostrealm_vtable)vtable;

    vt->name = "unbound";
    return 0;
}

#endif /* ONLY USEFUL FOR BUITLIN MODULES */

#endif /* DNSSEC_IMPL_UNBOUND */

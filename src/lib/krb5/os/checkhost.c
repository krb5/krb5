/*
 * Copyright 2014 Red Hat, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "k5-int.h"
#include "k5-utf8.h"

#ifdef PROXY_TLS_IMPL_OPENSSL
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "checkhost.h"

/* Return the passed-in character, lower-cased if it's an ASCII character. */
static inline char
ascii_tolower(char p)
{
    if (KRB5_UPPER(p))
        return p + ('a' - 'A');
    return p;
}

/*
 * Check a single label.  If allow_wildcard is true, and the presented name
 * includes a wildcard, return true and note that we matched a wildcard.
 * Otherwise, for both the presented and expected values, do a case-insensitive
 * comparison of ASCII characters, and a case-sensitive comparison of
 * everything else.
 */
static krb5_boolean
label_match(const char *presented, size_t plen, const char *expected,
            size_t elen, krb5_boolean allow_wildcard, krb5_boolean *wildcard)
{
    unsigned int i;

    if (allow_wildcard && plen == 1 && presented[0] == '*') {
        *wildcard = TRUE;
        return TRUE;
    }

    if (plen != elen)
        return FALSE;

    for (i = 0; i < elen; i++) {
        if (ascii_tolower(presented[i]) != ascii_tolower(expected[i]))
            return FALSE;
    }
    return TRUE;
}

/* Break up the two names and check them, label by label. */
static krb5_boolean
domain_match(const char *presented, size_t plen, const char *expected)
{
    const char *p, *q, *r, *s;
    int n_label;
    krb5_boolean used_wildcard = FALSE;

    n_label = 0;
    p = presented;
    r = expected;
    while (p < presented + plen && *r != '\0') {
        q = memchr(p, '.', plen - (p - presented));
        if (q == NULL)
            q = presented + plen;
        s = r + strcspn(r, ".");
        if (!label_match(p, q - p, r, s - r, n_label == 0, &used_wildcard))
            return FALSE;
        p = q < presented + plen ? q + 1 : q;
        r = *s ? s + 1 : s;
        n_label++;
    }
    if (used_wildcard && n_label <= 2)
        return FALSE;
    if (p == presented + plen && *r == '\0')
        return TRUE;
    return FALSE;
}

/* Fetch the list of subjectAltNames from a certificate. */
static GENERAL_NAMES *
get_cert_sans(X509 *x)
{
    int ext;
    X509_EXTENSION *san_ext;

    ext = X509_get_ext_by_NID(x, NID_subject_alt_name, -1);
    if (ext < 0)
        return NULL;
    san_ext = X509_get_ext(x, ext);
    if (san_ext == NULL)
        return NULL;
    return X509V3_EXT_d2i(san_ext);
}

/* Fetch a CN value from the subjct name field, returning its length, or -1 if
 * there is no subject name or it contains no CN value. */
static ssize_t
get_cert_cn(X509 *x, char *buf, size_t bufsize)
{
    X509_NAME *name;

    name = X509_get_subject_name(x);
    if (name == NULL)
        return -1;
    return X509_NAME_get_text_by_NID(name, NID_commonName, buf, bufsize);
}

/*
 * Return true if the passed-in expected IP address matches any of the names we
 * can recover from the server certificate, false otherwise.
 */
krb5_boolean
k5_check_cert_address(X509 *x, const char *text)
{
    char buf[1024];
    GENERAL_NAMES *sans;
    GENERAL_NAME *san = NULL;
    ASN1_OCTET_STRING *ip;
    krb5_boolean found_ip_san = FALSE, matched = FALSE;
    int n_sans, i;
    size_t name_length;
    union {
        struct in_addr in;
        struct in6_addr in6;
    } name;

    /* Parse the IP address into an octet string. */
    ip = M_ASN1_OCTET_STRING_new();
    if (ip == NULL)
        return FALSE;

    if (inet_aton(text, &name.in) == 1)
        name_length = sizeof(name.in);
    else if (inet_pton(AF_INET6, text, &name.in6) == 1)
        name_length = sizeof(name.in6);
    else
        name_length = 0;

    if (name_length == 0) {
        ASN1_OCTET_STRING_free(ip);
        return FALSE;
    }
    M_ASN1_OCTET_STRING_set(ip, &name, name_length);

    /* Check for matches in ipaddress subjectAltName values. */
    sans = get_cert_sans(x);
    if (sans != NULL) {
        n_sans = sk_GENERAL_NAME_num(sans);
        for (i = 0; i < n_sans; i++) {
            san = sk_GENERAL_NAME_value(sans, i);
            if (san->type != GEN_IPADD)
                continue;
            found_ip_san = TRUE;
            matched = ASN1_OCTET_STRING_cmp(ip, san->d.iPAddress) == 0;
            if (matched)
                break;
        }
        sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
    }
    ASN1_OCTET_STRING_free(ip);

    if (matched)
        return TRUE;
    if (found_ip_san)
        return matched;

    /* Check for a match against the CN value in the peer's subject name. */
    name_length = get_cert_cn(x, buf, sizeof(buf));
    if (name_length >= 0) {
        /* Do a string compare to check if it's an acceptable value. */
        return strlen(text) == name_length &&
               strncmp(text, buf, name_length) == 0;
    }

    /* We didn't find a match. */
    return FALSE;
}

/*
 * Return true if the passed-in expected name matches any of the names we can
 * recover from a server certificate, false otherwise.
 */
krb5_boolean
k5_check_cert_servername(X509 *x, const char *expected)
{
    char buf[1024];
    GENERAL_NAMES *sans;
    GENERAL_NAME *san = NULL;
    unsigned char *dnsname;
    krb5_boolean found_dns_san = FALSE, matched = FALSE;
    int name_length, n_sans, i;

    /* Check for matches in dnsname subjectAltName values. */
    sans = get_cert_sans(x);
    if (sans != NULL) {
        n_sans = sk_GENERAL_NAME_num(sans);
        for (i = 0; i < n_sans; i++) {
            san = sk_GENERAL_NAME_value(sans, i);
            if (san->type != GEN_DNS)
                continue;
            found_dns_san = TRUE;
            dnsname = NULL;
            name_length = ASN1_STRING_to_UTF8(&dnsname, san->d.dNSName);
            if (dnsname == NULL)
                continue;
            matched = domain_match((char *)dnsname, name_length, expected);
            OPENSSL_free(dnsname);
            if (matched)
                break;
        }
        sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
    }

    if (matched)
        return TRUE;
    if (found_dns_san)
        return matched;

    /* Check for a match against the CN value in the peer's subject name. */
    name_length = get_cert_cn(x, buf, sizeof(buf));
    if (name_length >= 0)
        return domain_match(buf, name_length, expected);

    /* We didn't find a match. */
    return FALSE;
}
#endif

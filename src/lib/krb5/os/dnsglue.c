/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/os/dnsglue.c */
/*
 * Copyright 2004, 2009 by the Massachusetts Institute of Technology.
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
 */

#include "k5-int.h"
#include "os-proto.h"

#ifdef KRB5_DNS_LOOKUP

#ifndef _WIN32

#include "dnsglue.h"
#ifdef __APPLE__
#include <dns.h>
#endif

/*
 * Opaque handle
 */
struct k5_dns_state {
    int nclass;
    int ntype;
    uint8_t *ans;
    uint8_t *ansend;
#if HAVE_NS_INITPARSE
    int cur_ans;
    ns_msg msg;
#else
    struct k5input in;
    unsigned short nanswers;
#endif
};

#if !HAVE_NS_INITPARSE
static int initparse(struct k5_dns_state *);
#endif

/*
 * Define macros to use the best available DNS search functions.  INIT_HANDLE()
 * returns true if handle initialization is successful, false if it is not.
 * SEARCH() returns the length of the response or -1 on error.
 * PRIMARY_DOMAIN() returns the first search domain in allocated memory.
 * DECLARE_HANDLE() must be used last in the declaration list since it may
 * evaluate to nothing.
 */

#if defined(__APPLE__)

/* Use the macOS interfaces dns_open, dns_search, and dns_free. */
#define DECLARE_HANDLE(h) dns_handle_t h
#define INIT_HANDLE(h) ((h = dns_open(NULL)) != NULL)
#define SEARCH(h, n, c, t, a, l) dns_search(h, n, c, t, a, l, NULL, NULL)
#define PRIMARY_DOMAIN(h) dns_search_list_domain(h, 0)
#define DESTROY_HANDLE(h) dns_free(h)

#elif HAVE_RES_NINIT && HAVE_RES_NSEARCH

/* Use res_ninit, res_nsearch, and res_ndestroy or res_nclose. */
#define DECLARE_HANDLE(h) struct __res_state h
#define INIT_HANDLE(h) (memset(&h, 0, sizeof(h)), res_ninit(&h) == 0)
#define SEARCH(h, n, c, t, a, l) res_nsearch(&h, n, c, t, a, l)
#define PRIMARY_DOMAIN(h) ((h.dnsrch[0] == NULL) ? NULL : strdup(h.dnsrch[0]))
#if HAVE_RES_NDESTROY
#define DESTROY_HANDLE(h) res_ndestroy(&h)
#else
#define DESTROY_HANDLE(h) res_nclose(&h)
#endif

#else

/* Use res_init and res_search. */
#define DECLARE_HANDLE(h)
#define INIT_HANDLE(h) (res_init() == 0)
#define SEARCH(h, n, c, t, a, l) res_search(n, c, t, a, l)
#define PRIMARY_DOMAIN(h) \
    ((_res.defdname == NULL) ? NULL : strdup(_res.defdname))
#define DESTROY_HANDLE(h)

#endif

int
k5_dns_init(const char *host, int nclass, int ntype,
            struct k5_dns_state **ds_out)
{
    struct k5_dns_state *ds;
    int bufsize, len, ret = -1;
    const int maxlen = 64 * 1024;
    uint8_t *p;
    DECLARE_HANDLE(h);

    *ds_out = NULL;

    ds = malloc(sizeof(*ds));
    if (ds == NULL)
        return -1;

    ds->nclass = nclass;
    ds->ntype = ntype;
    ds->ans = ds->ansend = NULL;

#if HAVE_NS_INITPARSE
    ds->cur_ans = 0;
#endif

    if (!INIT_HANDLE(h))
        return -1;

    len = 0;
    bufsize = 4096;
    do {
        /* Use a buffer size larger than the previously returned length.  (We
         * may go up to 128K to confirm that a 64K answer wasn't truncated.) */
        while (bufsize <= len && bufsize <= maxlen)
            bufsize *= 2;

        p = realloc(ds->ans, bufsize);
        if (p == NULL)
            goto cleanup;
        ds->ans = p;

        len = SEARCH(h, host, ds->nclass, ds->ntype, ds->ans, bufsize);
        if (len < 0 || len > maxlen)
            goto cleanup;

        /* A length equal to bufsize may indicate a truncated reply. */
    } while (len >= bufsize);

    ds->ansend = ds->ans + len;
#if HAVE_NS_INITPARSE
    ret = ns_initparse(ds->ans, len, &ds->msg);
#else
    ret = initparse(ds);
#endif
    if (ret < 0)
        goto cleanup;

    *ds_out = ds;
    ds = NULL;
    ret = 0;

cleanup:
    DESTROY_HANDLE(h);
    k5_dns_fini(ds);
    return ret;
}

#if HAVE_NS_INITPARSE
int
k5_dns_nextans(struct k5_dns_state *ds, struct k5input *ans_out)
{
    int len;
    ns_rr rr;

    k5_input_init(ans_out, NULL, 0);
    while (ds->cur_ans < ns_msg_count(ds->msg, ns_s_an)) {
        len = ns_parserr(&ds->msg, ns_s_an, ds->cur_ans, &rr);
        if (len < 0)
            return -1;
        ds->cur_ans++;
        if (ds->nclass == (int)ns_rr_class(rr) &&
            ds->ntype == (int)ns_rr_type(rr)) {
            k5_input_init(ans_out, ns_rr_rdata(rr), ns_rr_rdlen(rr));
            return 0;
        }
    }
    return 0;
}
#endif

int
k5_dns_expand(struct k5_dns_state *ds, struct k5input *in, char *buf, int len)
{
    int clen;

    if (in->status)
        return -1;

    /* Uncompress the name into buf. */
#if HAVE_NS_NAME_UNCOMPRESS
    clen = ns_name_uncompress(ds->ans, ds->ansend, in->ptr, buf, (size_t)len);
#else
    clen = dn_expand(ds->ans, ds->ansend, in->ptr, buf, len);
#endif

    /* Advance in past the compressed name. */
    (void)k5_input_get_bytes(in, clen);

    return in->status ? -1 : 0;
}

void
k5_dns_fini(struct k5_dns_state *ds)
{
    if (ds == NULL)
        return;
    free(ds->ans);
    free(ds);
}

/*
 * Compat routines for BIND 4
 */
#if !HAVE_NS_INITPARSE

static int
namelen(const uint8_t *ptr, const uint8_t *ans, const uint8_t *ansend)
{
#if HAVE_DN_SKIPNAME
    return dn_skipname(ptr, ansend);
#else
    char host[MAXDNAME];

    return dn_expand(ans, ansend, ptr, host, sizeof(host));
#endif
}

static void
skipname(struct k5_dns_state *ds)
{
    int len;

    if (ds->in.status)
        return;
    len = namelen(ds->in.ptr, ds->ans, ds->ansend);
    if (len < 0)
        k5_input_set_status(&ds->in, EINVAL);
    else
        (void)k5_input_get_bytes(&ds->in, len);
}

/* Prepare to iterate over answer records by reading the reply header and
 * advancing past the questions section. */
static int
initparse(struct k5_dns_state *ds)
{
    uint16_t nqueries, nanswers;

    k5_input_init(&ds->in, ds->ans, ds->ansend - ds->ans);

    /* Skip id and flags. */
    (void)k5_input_get_bytes(&ds->in, 4);

    nqueries = k5_input_get_uint16_be(&ds->in);
    nanswers = k5_input_get_uint16_be(&ds->in);

    /* Skip nscount and arcount. */
    (void)k5_input_get_bytes(&ds->in, 4);

    /* Skip query records. */
    while (nqueries--) {
        /* Skip qname, then qtype and qclass. */
        skipname(ds);
        (void)k5_input_get_bytes(&ds->in, 4);
    }
    ds->nanswers = nanswers;
    return ds->in.status ? -1 : 0;
}

int
k5_dns_nextans(struct k5_dns_state *ds, struct k5input *ans_out)
{
    uint16_t ntype, nclass, rdlen;
    const uint8_t *rdata;

    k5_input_init(ans_out, NULL, 0);
    while (ds->nanswers--) {
        skipname(ds);
        ntype = k5_input_get_uint16_be(&ds->in);
        nclass = k5_input_get_uint16_be(&ds->in);
        /* Skip TTL. */
        (void)k5_input_get_bytes(&ds->in, 4);
        rdlen = k5_input_get_uint16_be(&ds->in);
        rdata = k5_input_get_bytes(&ds->in, rdlen);
        if (rdata == NULL)
            return -1;
        if (nclass == ds->nclass && ntype == ds->ntype) {
            k5_input_init(ans_out, rdata, rdlen);
            return 0;
        }
    }
    return 0;
}

#endif /* !HAVE_NS_INITPARSE */
#endif /* not _WIN32 */

/* Construct a DNS label of the form "prefix[.name.]".  name may be NULL. */
static char *
txt_lookup_name(const char *prefix, const char *name)
{
    struct k5buf buf;

    k5_buf_init_dynamic(&buf);

    if (name == NULL || name[0] == '\0') {
        k5_buf_add(&buf, prefix);
    } else {
        k5_buf_add_fmt(&buf, "%s.%s", prefix, name);

        /*
         * Realm names don't (normally) end with ".", but if the query doesn't
         * end with "." and doesn't get an answer as is, the resolv code will
         * try appending the local domain.  Since the realm names are
         * absolutes, let's stop that.
         *
         * But only if a name has been specified.  If we are performing a
         * search on the prefix alone then the intention is to allow the local
         * domain or domain search lists to be expanded.
         */

        if (buf.len > 0 && ((char *)buf.data)[buf.len - 1] != '.')
            k5_buf_add(&buf, ".");
    }

    return k5_buf_cstring(&buf);
}

/*
 * Try to look up a TXT record pointing to a Kerberos realm
 */

#ifdef _WIN32

#include <windns.h>

krb5_error_code
k5_try_realm_txt_rr(krb5_context context, const char *prefix, const char *name,
                    char **realm)
{
    krb5_error_code ret = 0;
    char *txtname = NULL;
    PDNS_RECORD rr = NULL;
    DNS_STATUS st;

    *realm = NULL;

    txtname = txt_lookup_name(prefix, name);
    if (txtname == NULL)
        return ENOMEM;

    st = DnsQuery_UTF8(txtname, DNS_TYPE_TEXT, DNS_QUERY_STANDARD, NULL,
                       &rr, NULL);
    if (st != ERROR_SUCCESS || rr == NULL) {
        TRACE_TXT_LOOKUP_NOTFOUND(context, txtname);
        ret = KRB5_ERR_HOST_REALM_UNKNOWN;
        goto cleanup;
    }

    *realm = strdup(rr->Data.TXT.pStringArray[0]);
    if (*realm == NULL)
        ret = ENOMEM;
    TRACE_TXT_LOOKUP_SUCCESS(context, txtname, *realm);

cleanup:
    free(txtname);
    if (rr != NULL)
        DnsRecordListFree(rr, DnsFreeRecordList);
    return ret;
}

char *
k5_primary_domain(void)
{
    return NULL;
}

#else /* _WIN32 */

krb5_error_code
k5_try_realm_txt_rr(krb5_context context, const char *prefix, const char *name,
                    char **realm)
{
    krb5_error_code retval = KRB5_ERR_HOST_REALM_UNKNOWN;
    const uint8_t *p;
    char *txtname = NULL;
    int ret, len;
    struct k5_dns_state *ds = NULL;
    struct k5input in = { 0 };

    /*
     * Form our query, and send it via DNS
     */

    txtname = txt_lookup_name(prefix, name);
    if (txtname == NULL)
        return ENOMEM;
    ret = k5_dns_init(txtname, C_IN, T_TXT, &ds);
    if (ret < 0) {
        TRACE_TXT_LOOKUP_NOTFOUND(context, txtname);
        goto errout;
    }

    ret = k5_dns_nextans(ds, &in);
    if (ret < 0 || in.len < 2)
        goto errout;

    len = k5_input_get_byte(&in);
    p = k5_input_get_bytes(&in, len);
    if (len == 0 || p == NULL)
        goto errout;
    *realm = k5memdup0(p, len, &retval);
    if (*realm == NULL)
        goto errout;
    /* Avoid a common error. */
    if ((*realm)[len - 1] == '.')
        (*realm)[len - 1] = '\0';

    TRACE_TXT_LOOKUP_SUCCESS(context, txtname, *realm);

errout:
    k5_dns_fini(ds);
    free(txtname);
    return retval;
}

char *
k5_primary_domain(void)
{
    char *domain;
    DECLARE_HANDLE(h);

    if (!INIT_HANDLE(h))
        return NULL;
    domain = PRIMARY_DOMAIN(h);
    DESTROY_HANDLE(h);
    return domain;
}

#endif /* not _WIN32 */
#endif /* KRB5_DNS_LOOKUP */

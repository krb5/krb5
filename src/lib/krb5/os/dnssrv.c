/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/os/dnssrv.c - Perform DNS SRV queries */
/*
 * Copyright 1990,2000,2001,2002,2003 by the Massachusetts Institute of Technology.
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

#include "autoconf.h"
#ifdef KRB5_DNS_LOOKUP
#include "k5-int.h"
#include "os-proto.h"

/*
 * Lookup a KDC via DNS SRV records
 */

void
krb5int_free_srv_dns_data (struct srv_dns_entry *p)
{
    struct srv_dns_entry *next;
    while (p) {
        next = p->next;
        free(p->host);
        free(p);
        p = next;
    }
}

/* Construct a DNS label of the form "service.[protocol.]realm.".  protocol may
 * and/or sitename be NULL. */
static char *
make_lookup_name(const krb5_data *realm, const char *service,
                 const char *protocol, const char *sitename)
{
    struct k5buf buf;

    if (memchr(realm->data, 0, realm->length))
        return NULL;

    k5_buf_init_dynamic(&buf);
    k5_buf_add_fmt(&buf, "%s.", service);
    if (protocol != NULL)
        k5_buf_add_fmt(&buf, "%s.", protocol);
    if (sitename != NULL)
        k5_buf_add_fmt(&buf, "%s._sites.", sitename);
    k5_buf_add_len(&buf, realm->data, realm->length);

    /*
     * Realm names don't (normally) end with ".", but if the query doesn't end
     * with "." and doesn't get an answer as is, the resolv code will try
     * appending the local domain.  Since the realm names are absolutes, let's
     * stop that.
     */

    if (buf.len > 0 && ((char *)buf.data)[buf.len - 1] != '.')
        k5_buf_add(&buf, ".");

    return k5_buf_cstring(&buf);
}

/* Insert new into the list *head, ordering by priority.  Weight is not
 * currently used. */
static void
place_srv_entry(struct srv_dns_entry **head, struct srv_dns_entry *new)
{
    struct srv_dns_entry *entry;

    if (*head == NULL || (*head)->priority > new->priority) {
        new->next = *head;
        *head = new;
        return;
    }

    for (entry = *head; entry != NULL; entry = entry->next) {
        /*
         * Insert an entry into the next spot if there is no next entry (we're
         * at the end), or if the next entry has a higher priority (lower
         * priorities are preferred).
         */
        if (entry->next == NULL || entry->next->priority > new->priority) {
            new->next = entry->next;
            entry->next = new;
            break;
        }
    }
}

#ifdef _WIN32

#include <windns.h>

krb5_error_code
k5_make_uri_query(krb5_context context, const krb5_data *realm,
                  const char *service, const char *sitename,
                  struct srv_dns_entry **answers)
{
    /* Windows does not currently support the URI record type or make it
     * possible to query for a record type it does not have support for. */
    *answers = NULL;
    return 0;
}

krb5_error_code
krb5int_make_srv_query_realm(krb5_context context, const krb5_data *realm,
                             const char *service, const char *protocol,
                             const char *sitename,
                             struct srv_dns_entry **answers)
{
    char *name = NULL;
    DNS_STATUS st;
    PDNS_RECORD records, rr;
    struct srv_dns_entry *head = NULL, *srv = NULL;

    *answers = NULL;

    name = make_lookup_name(realm, service, protocol, sitename);
    if (name == NULL)
        return 0;

    TRACE_DNS_SRV_SEND(context, name);

    st = DnsQuery_UTF8(name, DNS_TYPE_SRV, DNS_QUERY_STANDARD, NULL, &records,
                       NULL);
    if (st != ERROR_SUCCESS && sitename != NULL) {
        /* Try again without the site name. */
        free(name);
        return krb5int_make_srv_query_realm(context, realm, service, protocol,
                                            NULL, answers);
    }
    if (st != ERROR_SUCCESS)
        return 0;

    for (rr = records; rr != NULL; rr = rr->pNext) {
        if (rr->wType != DNS_TYPE_SRV)
            continue;

        srv = malloc(sizeof(struct srv_dns_entry));
        if (srv == NULL)
            goto cleanup;

        srv->priority = rr->Data.SRV.wPriority;
        srv->weight = rr->Data.SRV.wWeight;
        srv->port = rr->Data.SRV.wPort;
        /* Make sure the name looks fully qualified to the resolver. */
        if (asprintf(&srv->host, "%s.", rr->Data.SRV.pNameTarget) < 0) {
            free(srv);
            goto cleanup;
        }

        TRACE_DNS_SRV_ANS(context, srv->host, srv->port, srv->priority,
                          srv->weight);
        place_srv_entry(&head, srv);
    }

cleanup:
    free(name);
    if (records != NULL)
        DnsRecordListFree(records, DnsFreeRecordList);
    *answers = head;
    return 0;
}

#else /* _WIN32 */

#include "dnsglue.h"

/* Query the URI RR, collecting weight, priority, and target. */
krb5_error_code
k5_make_uri_query(krb5_context context, const krb5_data *realm,
                  const char *service, const char *sitename,
                  struct srv_dns_entry **answers)
{
    char *name = NULL;
    int size, ret;
    uint16_t priority, weight;
    struct k5_dns_state *ds = NULL;
    struct srv_dns_entry *head = NULL, *uri = NULL;
    struct k5input in = { 0 };

    *answers = NULL;

    /* Construct service.realm. */
    name = make_lookup_name(realm, service, NULL, sitename);
    if (name == NULL)
        return 0;

    TRACE_DNS_URI_SEND(context, name);

    size = k5_dns_init(name, C_IN, T_URI, &ds);
    if (size < 0 && sitename != NULL) {
        /* Try again without the site name. */
        free(name);
        return k5_make_uri_query(context, realm, service, NULL, answers);
    }
    if (size < 0)
        goto out;

    for (;;) {
        ret = k5_dns_nextans(ds, &in);
        if (ret < 0 || in.len == 0)
            goto out;

        priority = k5_input_get_uint16_be(&in);
        weight = k5_input_get_uint16_be(&in);
        if (in.status)
            goto out;

        uri = k5alloc(sizeof(*uri), &ret);
        if (uri == NULL)
            goto out;

        uri->priority = priority;
        uri->weight = weight;
        uri->host = k5memdup0(in.ptr, in.len, &ret);
        if (uri->host == NULL) {
            free(uri);
            goto out;
        }

        TRACE_DNS_URI_ANS(context, uri->host, uri->priority, uri->weight);
        place_srv_entry(&head, uri);
    }

out:
    k5_dns_fini(ds);
    free(name);
    *answers = head;
    return 0;
}

/*
 * Do DNS SRV query, return results in *answers.
 *
 * Make a best effort to return all the data we can.  On memory or decoding
 * errors, just return what we've got.  Always return 0, currently.
 */

krb5_error_code
krb5int_make_srv_query_realm(krb5_context context, const krb5_data *realm,
                             const char *service, const char *protocol,
                             const char *sitename,
                             struct srv_dns_entry **answers)
{
    char *name = NULL, host[MAXDNAME];
    int size, ret;
    uint16_t priority, weight, port;
    struct k5_dns_state *ds = NULL;
    struct srv_dns_entry *head = NULL, *srv = NULL;
    struct k5input in = { 0 };

    /*
     * First off, build a query of the form:
     *
     * service.protocol.realm
     *
     * which will most likely be something like:
     *
     * _kerberos._udp.REALM
     *
     */

    name = make_lookup_name(realm, service, protocol, sitename);
    if (name == NULL)
        return 0;

    TRACE_DNS_SRV_SEND(context, name);

    size = k5_dns_init(name, C_IN, T_SRV, &ds);
    if (size < 0 && sitename) {
        /* Try again without the site name. */
        free(name);
        return krb5int_make_srv_query_realm(context, realm, service, protocol,
                                            NULL, answers);
    }
    if (size < 0)
        goto out;

    for (;;) {
        ret = k5_dns_nextans(ds, &in);
        if (ret < 0 || in.len == 0)
            goto out;

        priority = k5_input_get_uint16_be(&in);
        weight = k5_input_get_uint16_be(&in);
        port = k5_input_get_uint16_be(&in);

        /*
         * RFC 2782 says the target is never compressed in the reply;
         * do we believe that?  We need to flatten it anyway, though.
         */
        ret = k5_dns_expand(ds, &in, host, sizeof(host));
        if (ret < 0)
            goto out;

        /*
         * We got everything!  Insert it into our list, but make sure
         * it's in the right order.  Right now we don't do anything
         * with the weight field
         */

        srv = malloc(sizeof(struct srv_dns_entry));
        if (srv == NULL)
            goto out;

        srv->priority = priority;
        srv->weight = weight;
        srv->port = port;
        /* The returned names are fully qualified.  Don't let the
         * local resolver code do domain search path stuff. */
        if (asprintf(&srv->host, "%s.", host) < 0) {
            free(srv);
            goto out;
        }

        TRACE_DNS_SRV_ANS(context, srv->host, srv->port, srv->priority,
                          srv->weight);
        place_srv_entry(&head, srv);
    }

out:
    k5_dns_fini(ds);
    free(name);
    *answers = head;
    return 0;
}

#endif /* not _WIN32 */
#endif /* KRB5_DNS_LOOKUP */

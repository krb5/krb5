/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * stdcc_util.c
 * utility functions used in implementing the ccache api for krb5
 * not publicly exported
 * Frank Dabek, July 1998
 */

#if defined(_WIN32) || defined(USE_CCAPI)

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#if defined(_WIN32)
#include <malloc.h>
#endif

#include "k5-int.h"
#include "stdcc_util.h"
#ifdef _WIN32                   /* it's part of krb5.h everywhere else */
#include "kv5m_err.h"
#endif

#define fieldSize 255

static void
free_cc_array (cc_data **io_cc_array)
{
    if (io_cc_array) {
        unsigned int i;

        for (i = 0; io_cc_array[i]; i++) {
            if (io_cc_array[i]->data) { free (io_cc_array[i]->data); }
            free (io_cc_array[i]);
        }
        free (io_cc_array);
    }
}

static krb5_error_code
copy_cc_array_to_addresses (krb5_context in_context,
                            cc_data **in_cc_array,
                            krb5_address ***out_addresses)
{
    krb5_error_code err = 0;

    if (in_cc_array == NULL) {
        *out_addresses = NULL;

    } else {
        unsigned int count, i;
        krb5_address **addresses = NULL;

        /* get length of array */
        for (count = 0; in_cc_array[count]; count++);
        addresses = (krb5_address **) malloc (sizeof (*addresses) * (count + 1));
        if (!addresses) { err = KRB5_CC_NOMEM; }

        for (i = 0; !err && i < count; i++) {
            addresses[i] = (krb5_address *) malloc (sizeof (krb5_address));
            if (!addresses[i]) { err = KRB5_CC_NOMEM; }

            if (!err) {
                addresses[i]->contents = (krb5_octet *) malloc (sizeof (krb5_octet) *
                                                                in_cc_array[i]->length);
                if (!addresses[i]->contents) { err = KRB5_CC_NOMEM; }
            }

            if (!err) {
                addresses[i]->magic = KV5M_ADDRESS;
                addresses[i]->addrtype = in_cc_array[i]->type;
                addresses[i]->length = in_cc_array[i]->length;
                memcpy (addresses[i]->contents,
                        in_cc_array[i]->data, in_cc_array[i]->length);
            }
        }

        if (!err) {
            addresses[i] = NULL; /* terminator */
            *out_addresses = addresses;
            addresses = NULL;
        }

        if (addresses) { krb5_free_addresses (in_context, addresses); }
    }

    return err;
}

static krb5_error_code
copy_cc_array_to_authdata (krb5_context in_context,
                           cc_data **in_cc_array,
                           krb5_authdata ***out_authdata)
{
    krb5_error_code err = 0;

    if (in_cc_array == NULL) {
        *out_authdata = NULL;

    } else {
        unsigned int count, i;
        krb5_authdata **authdata = NULL;

        /* get length of array */
        for (count = 0; in_cc_array[count]; count++);
        authdata = (krb5_authdata **) malloc (sizeof (*authdata) * (count + 1));
        if (!authdata) { err = KRB5_CC_NOMEM; }

        for (i = 0; !err && i < count; i++) {
            authdata[i] = (krb5_authdata *) malloc (sizeof (krb5_authdata));
            if (!authdata[i]) { err = KRB5_CC_NOMEM; }

            if (!err) {
                authdata[i]->contents = (krb5_octet *) malloc (sizeof (krb5_octet) *
                                                               in_cc_array[i]->length);
                if (!authdata[i]->contents) { err = KRB5_CC_NOMEM; }
            }

            if (!err) {
                authdata[i]->magic = KV5M_AUTHDATA;
                authdata[i]->ad_type = in_cc_array[i]->type;
                authdata[i]->length = in_cc_array[i]->length;
                memcpy (authdata[i]->contents,
                        in_cc_array[i]->data, in_cc_array[i]->length);
            }
        }

        if (!err) {
            authdata[i] = NULL; /* terminator */
            *out_authdata = authdata;
            authdata = NULL;
        }

        if (authdata) { krb5_free_authdata (in_context, authdata); }
    }

    return err;
}

static krb5_error_code
copy_addresses_to_cc_array (krb5_context in_context,
                            krb5_address **in_addresses,
                            cc_data ***out_cc_array)
{
    krb5_error_code err = 0;

    if (in_addresses == NULL) {
        *out_cc_array = NULL;

    } else {
        unsigned int count, i;
        cc_data **cc_array = NULL;

        /* get length of array */
        for (count = 0; in_addresses[count]; count++);
        cc_array = (cc_data **) malloc (sizeof (*cc_array) * (count + 1));
        if (!cc_array) { err = KRB5_CC_NOMEM; }

        for (i = 0; !err && i < count; i++) {
            cc_array[i] = (cc_data *) malloc (sizeof (cc_data));
            if (!cc_array[i]) { err = KRB5_CC_NOMEM; }

            if (!err) {
                cc_array[i]->data = malloc (in_addresses[i]->length);
                if (!cc_array[i]->data) { err = KRB5_CC_NOMEM; }
            }

            if (!err) {
                cc_array[i]->type = in_addresses[i]->addrtype;
                cc_array[i]->length = in_addresses[i]->length;
                memcpy (cc_array[i]->data, in_addresses[i]->contents, in_addresses[i]->length);
            }
        }

        if (!err) {
            cc_array[i] = NULL; /* terminator */
            *out_cc_array = cc_array;
            cc_array = NULL;
        }

        if (cc_array) { free_cc_array (cc_array); }
    }


    return err;
}

static krb5_error_code
copy_authdata_to_cc_array (krb5_context in_context,
                           krb5_authdata **in_authdata,
                           cc_data ***out_cc_array)
{
    krb5_error_code err = 0;

    if (in_authdata == NULL) {
        *out_cc_array = NULL;

    } else {
        unsigned int count, i;
        cc_data **cc_array = NULL;

        /* get length of array */
        for (count = 0; in_authdata[count]; count++);
        cc_array = (cc_data **) malloc (sizeof (*cc_array) * (count + 1));
        if (!cc_array) { err = KRB5_CC_NOMEM; }

        for (i = 0; !err && i < count; i++) {
            cc_array[i] = (cc_data *) malloc (sizeof (cc_data));
            if (!cc_array[i]) { err = KRB5_CC_NOMEM; }

            if (!err) {
                cc_array[i]->data = malloc (in_authdata[i]->length);
                if (!cc_array[i]->data) { err = KRB5_CC_NOMEM; }
            }

            if (!err) {
                cc_array[i]->type = in_authdata[i]->ad_type;
                cc_array[i]->length = in_authdata[i]->length;
                memcpy (cc_array[i]->data, in_authdata[i]->contents, in_authdata[i]->length);
            }
        }

        if (!err) {
            cc_array[i] = NULL; /* terminator */
            *out_cc_array = cc_array;
            cc_array = NULL;
        }

        if (cc_array) { free_cc_array (cc_array); }
    }


    return err;
}


/*
 * copy_cc_credentials_to_krb5_creds
 * - allocate an empty k5 style ticket and copy info from the cc_creds ticket
 */

krb5_error_code
copy_cc_cred_union_to_krb5_creds (krb5_context in_context,
                                  const cc_credentials_union *in_cred_union,
                                  krb5_creds *out_creds)
{
    krb5_error_code err = 0;
    cc_credentials_v5_t *cv5 = NULL;
    krb5_int32 offset_seconds = 0, offset_microseconds = 0;
    krb5_principal client = NULL;
    krb5_principal server = NULL;
    char *ticket_data = NULL;
    char *second_ticket_data = NULL;
    unsigned char *keyblock_contents = NULL;
    krb5_address **addresses = NULL;
    krb5_authdata **authdata = NULL;

    if (in_cred_union->version != cc_credentials_v5) {
        err = KRB5_CC_NOT_KTYPE;
    } else {
        cv5 = in_cred_union->credentials.credentials_v5;
    }

#if TARGET_OS_MAC
    if (!err) {
        err = krb5_get_time_offsets (in_context, &offset_seconds, &offset_microseconds);
    }
#endif

    if (!err) {
        err = krb5_parse_name (in_context, cv5->client, &client);
    }

    if (!err) {
        err = krb5_parse_name (in_context, cv5->server, &server);
    }

    if (!err && cv5->keyblock.data) {
        keyblock_contents = (unsigned char *) malloc (cv5->keyblock.length);
        if (!keyblock_contents) { err = KRB5_CC_NOMEM; }
    }

    if (!err && cv5->ticket.data) {
        ticket_data = (char *) malloc (cv5->ticket.length);
        if (!ticket_data) { err = KRB5_CC_NOMEM; }
    }

    if (!err && cv5->second_ticket.data) {
        second_ticket_data = (char *) malloc (cv5->second_ticket.length);
        if (!second_ticket_data) { err = KRB5_CC_NOMEM; }
    }

    if (!err) {
        /* addresses */
        err = copy_cc_array_to_addresses (in_context, cv5->addresses, &addresses);
    }

    if (!err) {
        /* authdata */
        err = copy_cc_array_to_authdata (in_context, cv5->authdata, &authdata);
    }

    if (!err) {
        /* principals */
        out_creds->client = client;
        client = NULL;
        out_creds->server = server;
        server = NULL;

        /* copy keyblock */
        if (cv5->keyblock.data) {
            memcpy (keyblock_contents, cv5->keyblock.data, cv5->keyblock.length);
        }
        out_creds->keyblock.enctype = cv5->keyblock.type;
        out_creds->keyblock.length = cv5->keyblock.length;
        out_creds->keyblock.contents = keyblock_contents;
        keyblock_contents = NULL;

        /* copy times */
        out_creds->times.authtime   = ts_incr(cv5->authtime, offset_seconds);
        out_creds->times.starttime  = ts_incr(cv5->starttime, offset_seconds);
        out_creds->times.endtime    = ts_incr(cv5->endtime, offset_seconds);
        out_creds->times.renew_till = ts_incr(cv5->renew_till, offset_seconds);
        out_creds->is_skey          = cv5->is_skey;
        out_creds->ticket_flags     = cv5->ticket_flags;

        /* first ticket */
        if (cv5->ticket.data) {
            memcpy(ticket_data, cv5->ticket.data, cv5->ticket.length);
        }
        out_creds->ticket.length = cv5->ticket.length;
        out_creds->ticket.data = ticket_data;
        ticket_data = NULL;

        /* second ticket */
        if (cv5->second_ticket.data) {
            memcpy(second_ticket_data, cv5->second_ticket.data, cv5->second_ticket.length);
        }
        out_creds->second_ticket.length = cv5->second_ticket.length;
        out_creds->second_ticket.data = second_ticket_data;
        second_ticket_data = NULL;

        out_creds->addresses = addresses;
        addresses = NULL;

        out_creds->authdata = authdata;
        authdata = NULL;

        /* zero out magic number */
        out_creds->magic = 0;
    }

    if (addresses)          { krb5_free_addresses (in_context, addresses); }
    if (authdata)           { krb5_free_authdata (in_context, authdata); }
    if (keyblock_contents)  { free (keyblock_contents); }
    if (ticket_data)        { free (ticket_data); }
    if (second_ticket_data) { free (second_ticket_data); }
    if (client)             { krb5_free_principal (in_context, client); }
    if (server)             { krb5_free_principal (in_context, server); }

    return err;
}

/*
 * copy_krb5_creds_to_cc_credentials
 * - analogous to above but in the reverse direction
 */
krb5_error_code
copy_krb5_creds_to_cc_cred_union (krb5_context in_context,
                                  krb5_creds *in_creds,
                                  cc_credentials_union **out_cred_union)
{
    krb5_error_code err = 0;
    cc_credentials_union *cred_union = NULL;
    cc_credentials_v5_t *cv5 = NULL;
    char *client = NULL;
    char *server = NULL;
    unsigned char *ticket_data = NULL;
    unsigned char *second_ticket_data = NULL;
    unsigned char *keyblock_data = NULL;
    krb5_int32 offset_seconds = 0, offset_microseconds = 0;
    cc_data **cc_address_array = NULL;
    cc_data **cc_authdata_array = NULL;

    if (out_cred_union == NULL) { err = KRB5_CC_NOMEM; }

#if TARGET_OS_MAC
    if (!err) {
        err = krb5_get_time_offsets (in_context, &offset_seconds, &offset_microseconds);
    }
#endif

    if (!err) {
        cred_union = (cc_credentials_union *) malloc (sizeof (*cred_union));
        if (!cred_union) { err = KRB5_CC_NOMEM; }
    }

    if (!err) {
        cv5 = (cc_credentials_v5_t *) malloc (sizeof (*cv5));
        if (!cv5) { err = KRB5_CC_NOMEM; }
    }

    if (!err) {
        err = krb5_unparse_name (in_context, in_creds->client, &client);
    }

    if (!err) {
        err = krb5_unparse_name (in_context, in_creds->server, &server);
    }

    if (!err && in_creds->keyblock.contents) {
        keyblock_data = (unsigned char *) malloc (in_creds->keyblock.length);
        if (!keyblock_data) { err = KRB5_CC_NOMEM; }
    }

    if (!err && in_creds->ticket.data) {
        ticket_data = (unsigned char *) malloc (in_creds->ticket.length);
        if (!ticket_data) { err = KRB5_CC_NOMEM; }
    }

    if (!err && in_creds->second_ticket.data) {
        second_ticket_data = (unsigned char *) malloc (in_creds->second_ticket.length);
        if (!second_ticket_data) { err = KRB5_CC_NOMEM; }
    }

    if (!err) {
        err = copy_addresses_to_cc_array (in_context, in_creds->addresses, &cc_address_array);
    }

    if (!err) {
        err = copy_authdata_to_cc_array (in_context, in_creds->authdata, &cc_authdata_array);
    }

    if (!err) {
        /* principals */
        cv5->client = client;
        client = NULL;
        cv5->server = server;
        server = NULL;

        /* copy more fields */
        if (in_creds->keyblock.contents) {
            memcpy(keyblock_data, in_creds->keyblock.contents, in_creds->keyblock.length);
        }
        cv5->keyblock.type = in_creds->keyblock.enctype;
        cv5->keyblock.length = in_creds->keyblock.length;
        cv5->keyblock.data = keyblock_data;
        keyblock_data = NULL;

        cv5->authtime = ts_incr(in_creds->times.authtime, -offset_seconds);
        cv5->starttime = ts_incr(in_creds->times.starttime, -offset_seconds);
        cv5->endtime = ts_incr(in_creds->times.endtime, -offset_seconds);
        cv5->renew_till = ts_incr(in_creds->times.renew_till, -offset_seconds);
        cv5->is_skey = in_creds->is_skey;
        cv5->ticket_flags = in_creds->ticket_flags;

        if (in_creds->ticket.data) {
            memcpy (ticket_data, in_creds->ticket.data, in_creds->ticket.length);
        }
        cv5->ticket.length = in_creds->ticket.length;
        cv5->ticket.data = ticket_data;
        ticket_data = NULL;

        if (in_creds->second_ticket.data) {
            memcpy (second_ticket_data, in_creds->second_ticket.data, in_creds->second_ticket.length);
        }
        cv5->second_ticket.length = in_creds->second_ticket.length;
        cv5->second_ticket.data = second_ticket_data;
        second_ticket_data = NULL;

        cv5->addresses = cc_address_array;
        cc_address_array = NULL;

        cv5->authdata = cc_authdata_array;
        cc_authdata_array = NULL;

        /* Set up the structures to return to the caller */
        cred_union->version = cc_credentials_v5;
        cred_union->credentials.credentials_v5 = cv5;
        cv5 = NULL;

        *out_cred_union = cred_union;
        cred_union = NULL;
    }

    if (cc_address_array)   { free_cc_array (cc_address_array); }
    if (cc_authdata_array)  { free_cc_array (cc_authdata_array); }
    if (keyblock_data)      { free (keyblock_data); }
    if (ticket_data)        { free (ticket_data); }
    if (second_ticket_data) { free (second_ticket_data); }
    if (client)             { krb5_free_unparsed_name (in_context, client); }
    if (server)             { krb5_free_unparsed_name (in_context, server); }
    if (cv5)                { free (cv5); }
    if (cred_union)         { free (cred_union); }

    return err;
}

krb5_error_code
cred_union_release (cc_credentials_union *in_cred_union)
{
    if (in_cred_union) {
        if (in_cred_union->version == cc_credentials_v5 &&
            in_cred_union->credentials.credentials_v5) {
            cc_credentials_v5_t *cv5 = in_cred_union->credentials.credentials_v5;

            /* should use krb5_free_unparsed_name but we have no context */
            if (cv5->client) { free (cv5->client); }
            if (cv5->server) { free (cv5->server); }

            if (cv5->keyblock.data)      { free (cv5->keyblock.data); }
            if (cv5->ticket.data)        { free (cv5->ticket.data); }
            if (cv5->second_ticket.data) { free (cv5->second_ticket.data); }

            free_cc_array (cv5->addresses);
            free_cc_array (cv5->authdata);

            free (cv5);

        }
        free ((cc_credentials_union *) in_cred_union);
    }

    return 0;
}

#endif /* defined(_WIN32) || defined(USE_CCAPI) */

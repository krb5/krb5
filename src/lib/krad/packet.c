/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krad/packet.c - Packet functions for libkrad */
/*
 * Copyright 2013 Red Hat, Inc.  All rights reserved.
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

#include "internal.h"

#include <string.h>

#include <arpa/inet.h>

typedef unsigned char uchar;

/* RFC 2865 */
#define MSGAUTH_SIZE (2 + MD5_DIGEST_SIZE)
#define OFFSET_CODE 0
#define OFFSET_ID 1
#define OFFSET_LENGTH 2
#define OFFSET_AUTH 4
#define OFFSET_ATTR 20
#define OFFSET_RESP_MSGAUTH (OFFSET_ATTR + MSGAUTH_SIZE)
#define AUTH_FIELD_SIZE (OFFSET_ATTR - OFFSET_AUTH)

#define offset(d, o) ((d)->data + o)

#define buf_code_get(b)     (*(krad_code *)offset(b, OFFSET_CODE))
#define buf_code_set(b, v)  (*(krad_code *)offset(b, OFFSET_CODE)) = v
#define buf_id_get(b)       (*(uint8_t *)offset(b, OFFSET_ID))
#define buf_id_set(b, v)    (*(uint8_t *)offset(b, OFFSET_ID)) = v
#define buf_len_get(b)      load_16_be(offset(b, OFFSET_LENGTH))
#define buf_len_set(b, v)   store_16_be(v, offset(b, OFFSET_LENGTH))
#define buf_auth(b)         ((uint8_t *)offset(b, OFFSET_AUTH))
#define buf_attr(b)         ((uint8_t *)offset(b, OFFSET_ATTR))

#define pkt_code_get(p)     buf_code_get(&(p)->pkt)
#define pkt_code_set(p, v)  buf_code_set(&(p)->pkt, v)
#define pkt_id_get(p)       buf_id_get(&(p)->pkt)
#define pkt_id_set(p, v)    buf_id_set(&(p)->pkt, v)
#define pkt_len_get(p)      buf_len_get(&(p)->pkt)
#define pkt_len_set(p, v)   buf_len_set(&(p)->pkt, v)
#define pkt_auth(p)         buf_auth(&(p)->pkt)
#define pkt_attr(p)         buf_attr(&(p)->pkt)

struct krad_packet_st {
    char buffer[KRAD_PACKET_SIZE_MAX];
    krad_attrset *attrset;
    krb5_data pkt;
};

typedef struct {
    uchar x[(UCHAR_MAX + 1) / 8];
} idmap;

/* Ensure the map is empty. */
static inline void
idmap_init(idmap *map)
{
    memset(map, 0, sizeof(*map));
}

/* Set an id as already allocated. */
static inline void
idmap_set(idmap *map, uchar id)
{
    map->x[id / 8] |= 1 << (id % 8);
}

/* Determine whether or not an id is used. */
static inline krb5_boolean
idmap_isset(const idmap *map, uchar id)
{
    return (map->x[id / 8] & (1 << (id % 8))) != 0;
}

/* Find an unused id starting the search at the value specified in id.
 * NOTE: For optimal security, the initial value of id should be random. */
static inline krb5_error_code
idmap_find(const idmap *map, uchar *id)
{
    krb5_int16 i;

    for (i = *id; i >= 0 && i <= UCHAR_MAX; (*id % 2 == 0) ? i++ : i--) {
        if (!idmap_isset(map, i))
            goto success;
    }

    for (i = *id; i >= 0 && i <= UCHAR_MAX; (*id % 2 == 1) ? i++ : i--) {
        if (!idmap_isset(map, i))
            goto success;
    }

    return ERANGE;

success:
    *id = i;
    return 0;
}

/* Generate size bytes of random data into the buffer. */
static inline krb5_error_code
randomize(krb5_context ctx, void *buffer, unsigned int size)
{
    krb5_data rdata = make_data(buffer, size);
    return krb5_c_random_make_octets(ctx, &rdata);
}

/* Generate a radius packet id. */
static krb5_error_code
id_generate(krb5_context ctx, krad_packet_iter_cb cb, void *data, uchar *id)
{
    krb5_error_code retval;
    const krad_packet *tmp;
    idmap used;
    uchar i;

    retval = randomize(ctx, &i, sizeof(i));
    if (retval != 0) {
        if (cb != NULL)
            (*cb)(data, TRUE);
        return retval;
    }

    if (cb != NULL) {
        idmap_init(&used);
        for (tmp = (*cb)(data, FALSE); tmp != NULL; tmp = (*cb)(data, FALSE))
            idmap_set(&used, tmp->pkt.data[1]);

        retval = idmap_find(&used, &i);
        if (retval != 0)
            return retval;
    }

    *id = i;
    return 0;
}

/* Generate a random authenticator field. */
static krb5_error_code
auth_generate_random(krb5_context ctx, uchar *rauth)
{
    krb5_ui_4 trunctime;
    time_t currtime;

    /* Get the least-significant four bytes of the current time. */
    currtime = time(NULL);
    if (currtime == (time_t)-1)
        return errno;
    trunctime = (krb5_ui_4)currtime;
    memcpy(rauth, &trunctime, sizeof(trunctime));

    /* Randomize the rest of the buffer. */
    return randomize(ctx, rauth + sizeof(trunctime),
                     AUTH_FIELD_SIZE - sizeof(trunctime));
}

/* Generate a response authenticator field. */
static krb5_error_code
auth_generate_response(krb5_context ctx, const char *secret,
                       const krb5_data *respbuf, const uint8_t *auth,
                       uint8_t *rauth)
{
    krb5_crypto_iov input[4];

    /* Encoded RADIUS packet with the request's
     * authenticator and the secret at the end. */
    input[0].flags = KRB5_CRYPTO_TYPE_DATA;
    input[0].data = make_data(respbuf->data, respbuf->length);
    input[1].flags = KRB5_CRYPTO_TYPE_DATA;
    input[1].data = make_data((uint8_t *)auth, AUTH_FIELD_SIZE);
    input[2].flags = KRB5_CRYPTO_TYPE_DATA;
    input[2].data = make_data((char *)secret, strlen(secret));
    input[3].flags = KRB5_CRYPTO_TYPE_CHECKSUM;
    input[3].data = make_data(rauth, AUTH_FIELD_SIZE);

    /* Hash it. */
    return krb5_k_make_checksum_iov(ctx, CKSUMTYPE_RSA_MD5, NULL, 0, input, 4);
}

/* Create a new packet. */
static krad_packet *
packet_new(void)
{
    krad_packet *pkt;

    pkt = calloc(1, sizeof(krad_packet));
    if (pkt == NULL)
        return NULL;
    pkt->pkt = make_data(pkt->buffer, sizeof(pkt->buffer));

    return pkt;
}

/* Set the attrset object by decoding the packet. */
static krb5_error_code
packet_set_attrset(krb5_context ctx, const char *secret, krad_packet *pkt)
{
    krb5_data tmp;

    tmp = make_data(pkt_attr(pkt), pkt->pkt.length - OFFSET_ATTR);
    return kr_attrset_decode(ctx, &tmp, secret, pkt_auth(pkt), &pkt->attrset);
}

/* Determines if a request or response requires a Message-Authenticator
 * attribute. */
static inline krb5_boolean
requires_msgauth(const char *secret, krad_code code)
{
    /* If no secret is provided, assume that the transport is a UNIX socket.
     * Message-Authenticator is required only on UDP and TCP connections. */
    if (*secret == '\0')
        return FALSE;

    /*
     * Per draft-ietf-radext-deprecating-radius-03 sections 5.2.4 and 7.2,
     * Message-Authenticator is required in Access-Request packets and its
     * potential responses when UDP or TCP transport is used.
     */
    return code == krad_code_name2num("Access-Request") ||
        code == krad_code_name2num("Access-Reject") ||
        code == krad_code_name2num("Access-Accept") ||
        code == krad_code_name2num("Access-Challenge");
}

/* Return the beginning of the Message-Authenticator attribute in pkt, or NULL
 * if no such attribute is present. */
static const uint8_t *
lookup_msgauth_addr(const krb5_data *buf)
{
    krad_attr msgauth_type = krad_attr_name2num("Message-Authenticator");
    size_t i;
    uint8_t *p;

    i = OFFSET_ATTR;
    while (i + 2 < buf->length) {
        p = (uint8_t *)buf->data + i;
        if (msgauth_type == (krad_attr)*p)
            return p;
        i += p[1];
    }

    return NULL;
}

/* Check if the packet has a Message-Authenticator attribute. */
static inline krb5_boolean
has_msgauth(const krb5_data *buf)
{
    return lookup_msgauth_addr(buf) ? TRUE : FALSE;
}

/*
 * Calculate the message authenticator MAC for buf as specified in RFC 2869
 * section 5.14, placing the result in mac_out.  Use the provided authenticator
 * auth, which may be from buf or from a corresponding request.
 */
static krb5_error_code
calculate_mac(const char *secret, const krb5_data *buf,
              const uint8_t auth[AUTH_FIELD_SIZE],
              uint8_t mac_out[MD5_DIGEST_SIZE])
{
    uint8_t zeroed_msgauth[MSGAUTH_SIZE];
    krad_attr msgauth_type = krad_attr_name2num("Message-Authenticator");
    const uint8_t *msgauth_attr, *msgauth_end, *buf_end;
    krb5_crypto_iov input[5];
    krb5_data ksecr, mac;

    msgauth_attr = lookup_msgauth_addr(buf);
    if (msgauth_attr == NULL)
        return EINVAL;
    msgauth_end = msgauth_attr + MSGAUTH_SIZE;
    buf_end = (const uint8_t *)buf->data + buf->length;

    /* Keep code, id, and length as they are. */
    input[0].flags = KRB5_CRYPTO_TYPE_DATA;
    input[0].data = make_data(buf->data, OFFSET_AUTH);

    /* Use authenticator from the argument, or from the packet. */
    input[1].flags = KRB5_CRYPTO_TYPE_DATA;
    input[1].data = make_data((uint8_t *)auth, AUTH_FIELD_SIZE);

    /* Read any attributes before Message-Authenticator. */
    input[2].flags = KRB5_CRYPTO_TYPE_DATA;
    input[2].data = make_data(buf_attr(buf), msgauth_attr - buf_attr(buf));

    /* Read Message-Authenticator with the data bytes all set to zero, per RFC
     * 2869 section 5.14. */
    zeroed_msgauth[0] = msgauth_type;
    zeroed_msgauth[1] = MSGAUTH_SIZE;
    memset(zeroed_msgauth + 2, 0, MD5_DIGEST_SIZE);
    input[3].flags = KRB5_CRYPTO_TYPE_DATA;
    input[3].data = make_data(zeroed_msgauth, MSGAUTH_SIZE);

    /* Read any attributes after Message-Authenticator. */
    input[4].flags = KRB5_CRYPTO_TYPE_DATA;
    input[4].data = make_data((uint8_t *)msgauth_end, buf_end - msgauth_end);

    mac = make_data(mac_out, MD5_DIGEST_SIZE);
    ksecr = string2data((char *)secret);
    return k5_hmac_md5(&ksecr, input, 5, &mac);
}

ssize_t
krad_packet_bytes_needed(const krb5_data *buffer)
{
    size_t len;

    if (buffer->length < OFFSET_AUTH)
        return OFFSET_AUTH - buffer->length;

    len = load_16_be(offset(buffer, OFFSET_LENGTH));
    if (len > KRAD_PACKET_SIZE_MAX)
        return -1;

    return (buffer->length > len) ? 0 : len - buffer->length;
}

void
krad_packet_free(krad_packet *pkt)
{
    if (pkt)
        krad_attrset_free(pkt->attrset);
    free(pkt);
}

/* Create a new request packet. */
krb5_error_code
krad_packet_new_request(krb5_context ctx, const char *secret, krad_code code,
                        const krad_attrset *set, krad_packet_iter_cb cb,
                        void *data, krad_packet **request)
{
    krb5_error_code retval;
    krad_packet *pkt = NULL;
    uchar id;
    size_t attrset_len;
    krb5_boolean msgauth_required;

    pkt = packet_new();
    if (pkt == NULL) {
        if (cb != NULL)
            (*cb)(data, TRUE);
        retval = ENOMEM;
        goto cleanup;
    }

    /* Generate the ID. */
    retval = id_generate(ctx, cb, data, &id);
    if (retval != 0)
        goto cleanup;
    pkt_id_set(pkt, id);

    /* Generate the authenticator. */
    retval = auth_generate_random(ctx, pkt_auth(pkt));
    if (retval != 0)
        goto cleanup;

    /* Determine if Message-Authenticator is required. */
    msgauth_required = (*secret != '\0' &&
                        code == krad_code_name2num("Access-Request"));

    /* Encode the attributes. */
    retval = kr_attrset_encode(set, secret, pkt_auth(pkt), msgauth_required,
                               pkt_attr(pkt), &attrset_len);
    if (retval != 0)
        goto cleanup;

    /* Set the code, ID and length. */
    pkt->pkt.length = attrset_len + OFFSET_ATTR;
    pkt_code_set(pkt, code);
    pkt_len_set(pkt, pkt->pkt.length);

    if (msgauth_required) {
        /* Calculate and set actual Message-Authenticator. */
        retval = calculate_mac(secret, &pkt->pkt, pkt_auth(pkt),
                               pkt_attr(pkt) + 2);
        if (retval != 0)
            goto cleanup;
    }

    /* Copy the attrset for future use. */
    retval = packet_set_attrset(ctx, secret, pkt);
    if (retval != 0)
        goto cleanup;

    *request = pkt;
    pkt = NULL;

cleanup:
    krad_packet_free(pkt);
    return retval;
}

/* Create a new request packet. */
krb5_error_code
krad_packet_new_response(krb5_context ctx, const char *secret, krad_code code,
                         const krad_attrset *set, const krad_packet *request,
                         krad_packet **response)
{
    krb5_error_code retval;
    krad_packet *pkt = NULL;
    size_t attrset_len;
    krb5_boolean msgauth_required;

    pkt = packet_new();
    if (pkt == NULL)
        return ENOMEM;

    /* Determine if Message-Authenticator is required. */
    msgauth_required = requires_msgauth(secret, code);

    /* Encode the attributes. */
    retval = kr_attrset_encode(set, secret, pkt_auth(request),
                               msgauth_required, pkt_attr(pkt), &attrset_len);
    if (retval != 0)
        goto cleanup;

    /* Set the code, ID and length. */
    pkt->pkt.length = attrset_len + OFFSET_ATTR;
    pkt_code_set(pkt, code);
    pkt_id_set(pkt, pkt_id_get(request));
    pkt_len_set(pkt, pkt->pkt.length);

    /* Generate the authenticator. */
    retval = auth_generate_response(ctx, secret, &pkt->pkt, pkt_auth(request),
                                    pkt_auth(pkt));
    if (retval != 0)
        goto cleanup;

    /* Copy the attrset for future use. */
    retval = packet_set_attrset(ctx, secret, pkt);
    if (retval != 0)
        goto cleanup;

    if (msgauth_required) {
        /*
         * Calculate and replace the Message-Authenticator MAC.  Per RFC 2869
         * section 5.14, use the authenticator from the request, not from the
         * response.
         */
        retval = calculate_mac(secret, &pkt->pkt, pkt_auth(request),
                               pkt_attr(pkt) + 2);
        if (retval != 0)
            goto cleanup;
    }

    *response = pkt;
    pkt = NULL;

cleanup:
    krad_packet_free(pkt);
    return retval;
}

/* Verify the Message-Authenticator value in pkt, using the provided
 * authenticator (which may be from pkt or from a corresponding request). */
static krb5_error_code
verify_msgauth(const char *secret, const krb5_data *buf,
               const uint8_t auth[AUTH_FIELD_SIZE])
{
    uint8_t mac[MD5_DIGEST_SIZE];
    const uint8_t *msgauth;
    krb5_error_code retval;

    msgauth = lookup_msgauth_addr(buf);
    if (msgauth == NULL)
        return ENODATA;

    retval = calculate_mac(secret, buf, auth, mac);
    if (retval)
        return retval;

    if (k5_bcmp(mac, msgauth + 2, MD5_DIGEST_SIZE) != 0)
        return EBADMSG;

    return 0;
}


static krb5_error_code
validate_packet(const krb5_data *buf, uint16_t *validated_len)
{
    krad_attr msgauth_type = krad_attr_name2num("Message-Authenticator");
    uint16_t pktlen, i;
    uint8_t attrlen;

    if (buf->length > KRAD_PACKET_SIZE_MAX)
        return EMSGSIZE;

    if (buf->length < OFFSET_ATTR)
        return EBADMSG;

    /* Use packet length from header. Ignore remaining bytes if they exist. */
    pktlen = buf_len_get(buf);

    if (pktlen < OFFSET_ATTR)
        return EBADMSG;

    if (pktlen > buf->length)
        return EBADMSG;

    i = OFFSET_ATTR;
    while (i + 2 <= pktlen) {
        attrlen = buf->data[i+1];

        if (i + attrlen > pktlen)
            return EBADMSG;

        if (buf->data[i] == msgauth_type && attrlen != MSGAUTH_SIZE)
            return EBADMSG;

        i += attrlen;
    }

    if (i != pktlen)
        return EBADMSG;

    if (validated_len)
        *validated_len = pktlen;

    return 0;
}

/* Decode a packet. It must be validated first. */
static krb5_error_code
decode_packet(krb5_context ctx, const char *secret, const krb5_data *buffer,
              krad_packet **pkt)
{
    krb5_error_code retval;
    krad_packet *tmp;

    /* Allocate memory. */
    tmp = packet_new();
    if (tmp == NULL) {
        retval = ENOMEM;
        goto error;
    }

    /* Copy over the buffer. */
    tmp->pkt.length = buffer->length;
    memcpy(tmp->pkt.data, buffer->data, buffer->length);

    /* Parse attributes sequence and allocate attribute list. */
    retval = packet_set_attrset(ctx, secret, tmp);
    if (retval != 0)
        goto error;

    *pkt = tmp;
    return 0;

error:
    krad_packet_free(tmp);
    return retval;
}

krb5_error_code
krad_packet_decode_request(krb5_context ctx, const char *secret,
                           const krb5_data *buffer, krad_packet_iter_cb cb,
                           void *data, const krad_packet **duppkt,
                           krad_packet **reqpkt)
{
    const krad_packet *tmp = NULL;
    uint16_t len;
    krb5_data validbuf;
    krb5_error_code retval;

    /* Ensuure a well-formed packet. */
    retval = validate_packet(buffer, &len);
    if (retval)
        return retval;

    validbuf = make_data(buffer->data, len);

    /* Verify Message-Authenticator if present. */
    if (has_msgauth(&validbuf)) {
        retval = verify_msgauth(secret, &validbuf, buf_auth(&validbuf));
        if (retval)
            return retval;
    } else if (requires_msgauth(secret, buf_code_get(&validbuf))) {
        return ENODATA;
    }

    retval = decode_packet(ctx, secret, &validbuf, reqpkt);
    if (retval)
        return retval;

    if (cb != NULL) {
        while ((tmp = (*cb)(data, FALSE)) != NULL) {
            if (pkt_id_get(*reqpkt) == pkt_id_get(tmp))
                break;
        }

        if (tmp != NULL)
            (*cb)(data, TRUE);
    }

    *duppkt = tmp;
    return 0;
}

krb5_error_code
krad_packet_decode_response(krb5_context ctx, const char *secret,
                            const krb5_data *buffer, krad_packet_iter_cb cb,
                            void *data, const krad_packet **reqpkt,
                            krad_packet **rsppkt)
{
    uchar auth[AUTH_FIELD_SIZE];
    uint16_t len;
    krb5_data validbuf;
    const krad_packet *req = NULL;
    krb5_boolean msgauth_required;
    krb5_boolean req_matched = FALSE;
    krb5_error_code retval;

    retval = validate_packet(buffer, &len);
    if (retval)
        goto cleanup;

    validbuf = make_data(buffer->data, len);

    msgauth_required = requires_msgauth(secret, buf_code_get(&validbuf));

    /* When Message-Authenticator is required, a pending requests iterator must
     * be provided in order to find the matching request. The request
     * authenticator is needed to verify the Message-Authenticator. */
    if (msgauth_required && !cb)
        return EINVAL;

    if (cb) {
        while ((req = (*cb)(data, FALSE)) != NULL) {
            if (buf_id_get(&validbuf) != pkt_id_get(req))
                continue;

            req_matched = TRUE;

            /* Response */
            retval = auth_generate_response(ctx, secret, &validbuf,
                                            pkt_auth(req), auth);
            if (retval)
                goto cleanup;

            /* If the authenticator matches, then the response is valid. */
            if (memcmp(buf_auth(&validbuf), auth, sizeof(auth)) != 0)
                continue;

            /* Verify Message-Authenticator if present. */
            if (has_msgauth(&validbuf)) {
                retval = verify_msgauth(secret, &validbuf, pkt_auth(req));
                if (retval)
                    continue;
            } else if (msgauth_required) {
                continue;
            }

            break;
        }

        if (!req) {
            retval = req_matched ? EBADMSG : EBADE;
            goto cleanup;
        }
    }

    retval = decode_packet(ctx, secret, &validbuf, rsppkt);
    if (retval)
        goto cleanup;

    *reqpkt = req;

cleanup:
    if (retval != 0 || req != NULL)
        (*cb)(data, TRUE);

    return retval;
}

const krb5_data *
krad_packet_encode(const krad_packet *pkt)
{
    return &pkt->pkt;
}

krad_code
krad_packet_get_code(const krad_packet *pkt)
{
    if (pkt == NULL)
        return 0;

    return pkt_code_get(pkt);
}

const krb5_data *
krad_packet_get_attr(const krad_packet *pkt, krad_attr type, size_t indx)
{
    return krad_attrset_get(pkt->attrset, type, indx);
}

/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * $Id$
 */

#include "gssapiP_krb5.h"

#ifndef NO_PASSWORD
#include <pwd.h>
#include <stdio.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

/*
 * errors:
 * GSS_S_BAD_NAMETYPE   if the type is bogus
 * GSS_S_BAD_NAME       if the type is good but the name is bogus
 * GSS_S_FAILURE        if memory allocation fails
 */

/*
 * Import serialized authdata context
 */
static krb5_error_code
import_name_composite(krb5_context context,
                      unsigned char *enc_data, size_t enc_length,
                      krb5_authdata_context *pad_context)
{
    krb5_authdata_context ad_context;
    krb5_error_code code;
    krb5_data data;

    if (enc_length == 0)
        return 0;

    code = krb5_authdata_context_init(context, &ad_context);
    if (code != 0)
        return code;

    data.data = (char *)enc_data;
    data.length = enc_length;

    code = krb5_authdata_import_attributes(context,
                                           ad_context,
                                           AD_USAGE_MASK,
                                           &data);
    if (code != 0) {
        krb5_authdata_context_free(context, ad_context);
        return code;
    }

    *pad_context = ad_context;

    return 0;
}

/* Split a host-based name "service[@host]" into allocated strings
 * placed in *service_out and *host_out (possibly NULL). */
static krb5_error_code
parse_hostbased(const char *str, size_t len,
                char **service_out, char **host_out)
{
    const char *at;
    size_t servicelen, hostlen;
    char *service, *host = NULL;

    *service_out = *host_out = NULL;

    /* Find the bound of the service name and copy it. */
    at = memchr(str, '@', len);
    servicelen = (at == NULL) ? len : (size_t)(at - str);
    service = xmalloc(servicelen + 1);
    if (service == NULL)
        return ENOMEM;
    memcpy(service, str, servicelen);
    service[servicelen] = '\0';

    /* If present, copy the hostname. */
    if (at != NULL) {
        hostlen = len - servicelen - 1;
        host = malloc(hostlen + 1);
        if (host == NULL) {
            free(service);
            return ENOMEM;
        }
        memcpy(host, at + 1, hostlen);
        host[hostlen] = '\0';
    }

    *service_out = service;
    *host_out = host;
    return 0;
}

/*
 * NUL-terminate data element.
 * Caller must release with xfree().
 */
static char *data_to_str(const char *data, size_t length)
{
    char *buf;

    if ((buf = xmalloc(length + 1)) != NULL) {
        memcpy(buf, data, length);
        buf[length] = '\0';
    }
    return buf;
}

/*
 * Is input of the form l.d-host:port.  Dots and hypens must be internal to
 * the host name and isolated.
 */
static int hasport(const krb5_data *hostport)
{
    char portbuf[6];
    char *cp = hostport->data;
    char *end = hostport->data + hostport->length;
    size_t portlen;
    long portnum;
    int inword = 0;

    for (cp = hostport->data; cp < end; ++cp) {
        if (((*cp) >= 'a' && (*cp) <= 'z') ||
            ((*cp) >= '0' && (*cp) <= '9') ||
            ((*cp) >= 'A' && (*cp) <= 'Z')) {
            inword = 1;
            continue;
        }
        if (inword && (*cp == '.' || *cp == '-')) {
            inword = 0;
            continue;
        }
        if (!inword || *cp++ != ':' ||          /* Malformed host */
            (portlen = (end - cp)) == 0 ||      /* Empty port part */
            portlen >= sizeof(portbuf) ||       /* Port part too long */
            *cp < '1' || *cp > '9')
            break;
        memcpy(portbuf, cp, portlen);
        portbuf[portlen] = '\0';
        portnum = strtol(portbuf, &cp, 10);
        return (portnum > 0 && portnum < 65536 && *cp == '\0');
    }
    return 0;
}

/*
 * Sadly Microsoft's principal naming scheme for SQL server instances is not
 * GSSAPI friendly.  Instead of encoding the port number into the service name,
 * they append it to the hostname:  MSSQLSvc/db.example.com:1433.  At least
 * some JDBC libraries specify server name of "MSSQLSvc/db.example.com:1433"
 * with a null name type.
 *
 * This only works when the database server is in the default realm and is not
 * an alias.  If either condition is false, the client is unable to obtain the
 * required tickets.
 *
 * The code below is invoked for all names with a null name type.  If parsing
 * the name as a principal yields a two-part principal in the default realm,
 * and the second part ends in ":port" where port is a base 10 integer between
 * 1 and 65535, we assume that the name is in fact a host(port) based service.
 *
 * The krb5_sname_to_principal() function was separately extended to handle a
 * port suffix when the name type indicates a host-based service.
 *
 * Returns: 0 when the input_name is not a hostport based service.
 *          1 when the input_name is a hostport based service, or an error
 *            occurred in which case code is set to a suitable error code.
 */
static int parse_hpbs(
        krb5_context context,
        const char *input_buf,
        size_t buf_len,
        char **hostpart,
        char **servicepart,
        krb5_error_code *code)
{
    static const char MSSQLSvc[] = "MSSQLSvc";
    int result = 0;
    int mssql_workaround = 0;
    krb5_data *realm;
    krb5_principal tmp;
    const krb5_data *s;                         /* Service component */
    const krb5_data *h;                         /* Host component */
    char *input_name;
    char *default_realm;

    *code = profile_get_boolean(context->profile, KRB5_CONF_LIBDEFAULTS,
                                "mssql_workaround", NULL, 1, &mssql_workaround);
    if (*code != 0)
        return 1;       /* Fail */
    if (!mssql_workaround)
        return 0;

    if ((*code = krb5_get_default_realm(context, &default_realm)) != 0)
        return 1;       /* Fail */

    if ((input_name = data_to_str(input_buf, buf_len)) == 0) {
        *code = ENOMEM;
        free(default_realm);
        return 1;       /* Fail */
    }

    if ((*code = krb5_parse_name(context, input_name, &tmp)) != 0) {
        free(default_realm);
        free(input_name);
        return 1;       /* Fail */
    }

    /*
     * When the input name specifies no realm or equivalently (after
     * krb5_parse_name) the default realm, has two components and the first
     * component is MSSQLSvc (case-insensitive) we treat the input name as a
     * host-based service provided the second component is the form
     * host:port, with port a positive decimal number less than 65536.
     */
    realm = krb5_princ_realm(context, tmp);
    if (realm->length == strlen(default_realm) &&
        strncmp(default_realm, realm->data, realm->length) == 0 &&
        krb5_princ_size(context, tmp) == 2 &&
        (s = krb5_princ_component(context, tmp, 0)) != 0 &&
        s->length + 1 == sizeof(MSSQLSvc) &&
        strncasecmp(s->data, MSSQLSvc, s->length) == 0 &&
        (h = krb5_princ_component(context, tmp, 1)) != 0 &&
        hasport(h)) {
        char *host;
        char *srvc;

        if ((host = data_to_str(h->data, h->length)) != NULL &&
            (srvc = data_to_str(s->data, s->length)) != NULL) {
            *hostpart = host;
            *servicepart = srvc;
            result = 1;
        } else {
            if (host)
                xfree(host);
            *code = ENOMEM;
        }
    }

    krb5_free_principal(context, tmp);
    xfree(input_name);
    free(default_realm);
    return result;
}

OM_uint32 KRB5_CALLCONV
krb5_gss_import_name(minor_status, input_name_buffer,
                     input_name_type, output_name)
    OM_uint32 *minor_status;
    gss_buffer_t input_name_buffer;
    gss_OID input_name_type;
    gss_name_t *output_name;
{
    krb5_context context;
    krb5_principal princ = NULL;
    krb5_error_code code;
    unsigned char *cp, *end;
    char *tmp = NULL, *tmp2 = NULL, *service = NULL, *host = NULL, *stringrep;
    ssize_t    length;
#ifndef NO_PASSWORD
    struct passwd *pw;
#endif
    int is_composite = 0;
    krb5_authdata_context ad_context = NULL;
    OM_uint32 status = GSS_S_FAILURE;
    krb5_gss_name_t name;

    *output_name = NULL;
    *minor_status = 0;

    code = krb5_gss_init_context(&context);
    if (code)
        goto cleanup;

    if ((input_name_type != GSS_C_NULL_OID) &&
        (g_OID_equal(input_name_type, gss_nt_service_name) ||
         g_OID_equal(input_name_type, gss_nt_service_name_v2))) {
        /* Split the name into service and host (or NULL). */
        code = parse_hostbased(input_name_buffer->value,
                               input_name_buffer->length, &service, &host);
        if (code)
            goto cleanup;

        /*
         * Compute the initiator target name.  In some cases this is a waste of
         * getaddrinfo/getnameinfo queries, but computing the name when we need
         * it would require a lot of code changes.
         */
        code = krb5_sname_to_principal(context, host, service, KRB5_NT_SRV_HST,
                                       &princ);
        if (code)
            goto cleanup;
    } else if ((input_name_type != GSS_C_NULL_OID) &&
               (g_OID_equal(input_name_type, gss_nt_krb5_principal))) {
        krb5_principal input;

        if (input_name_buffer->length != sizeof(krb5_principal)) {
            code = G_WRONG_SIZE;
            status = GSS_S_BAD_NAME;
            goto cleanup;
        }

        input = *((krb5_principal *) input_name_buffer->value);

        code = krb5_copy_principal(context, input, &princ);
        if (code)
            goto cleanup;
    } else if ((input_name_type != NULL) &&
               g_OID_equal(input_name_type, GSS_C_NT_ANONYMOUS)) {
        code = krb5_copy_principal(context, krb5_anonymous_principal(),
                                   &princ);
        if (code)
            goto cleanup;
    } else if ((input_name_type == GSS_C_NULL_OID ||
                g_OID_equal(input_name_type, gss_nt_krb5_name)) &&
               parse_hpbs(context, input_name_buffer->value,
                          input_name_buffer->length, &host, &service, &code)) {
        if (!code)
            code = krb5_sname_to_principal(context, host, service,
                                           KRB5_NT_SRV_HST, &princ);
        if (code)
            goto cleanup;
    } else {
#ifndef NO_PASSWORD
        uid_t uid;
        struct passwd pwx;
        char pwbuf[BUFSIZ];
#endif

        stringrep = NULL;

        tmp = k5memdup0(input_name_buffer->value, input_name_buffer->length,
                        &code);
        if (tmp == NULL)
            goto cleanup;
        tmp2 = NULL;

        /* Find the appropriate string rep to pass into parse_name. */
        if ((input_name_type == GSS_C_NULL_OID) ||
            g_OID_equal(input_name_type, gss_nt_krb5_name) ||
            g_OID_equal(input_name_type, gss_nt_user_name)) {
            stringrep = (char *) tmp;
#ifndef NO_PASSWORD
        } else if (g_OID_equal(input_name_type, gss_nt_machine_uid_name)) {
            uid = *(uid_t *) input_name_buffer->value;
        do_getpwuid:
            if (k5_getpwuid_r(uid, &pwx, pwbuf, sizeof(pwbuf), &pw) == 0)
                stringrep = pw->pw_name;
            else
                code = G_NOUSER;
        } else if (g_OID_equal(input_name_type, gss_nt_string_uid_name)) {
            uid = atoi(tmp);
            goto do_getpwuid;
#endif
        } else if (g_OID_equal(input_name_type, gss_nt_exported_name) ||
                   g_OID_equal(input_name_type, GSS_C_NT_COMPOSITE_EXPORT)) {
#define BOUNDS_CHECK(cp, end, n)                                        \
            do { if ((end) - (cp) < (n)) goto fail_name; } while (0)
            cp = (unsigned char *)tmp;
            end = cp + input_name_buffer->length;

            BOUNDS_CHECK(cp, end, 2);
            if (*cp++ != 0x04)
                goto fail_name;
            switch (*cp++) {
            case 0x01:
                break;
            case 0x02:
                is_composite++;
                break;
            default:
                goto fail_name;
            }

            BOUNDS_CHECK(cp, end, 2);
            if (*cp++ != 0x00)
                goto fail_name;
            length = *cp++;
            if (length != (ssize_t)gss_mech_krb5->length+2)
                goto fail_name;

            BOUNDS_CHECK(cp, end, 2);
            if (*cp++ != 0x06)
                goto fail_name;
            length = *cp++;
            if (length != (ssize_t)gss_mech_krb5->length)
                goto fail_name;

            BOUNDS_CHECK(cp, end, length);
            if (memcmp(cp, gss_mech_krb5->elements, length) != 0)
                goto fail_name;
            cp += length;

            BOUNDS_CHECK(cp, end, 4);
            length = *cp++;
            length = (length << 8) | *cp++;
            length = (length << 8) | *cp++;
            length = (length << 8) | *cp++;

            BOUNDS_CHECK(cp, end, length);
            tmp2 = k5alloc(length + 1, &code);
            if (tmp2 == NULL)
                goto cleanup;
            strncpy(tmp2, (char *)cp, length);
            tmp2[length] = 0;
            stringrep = tmp2;
            cp += length;

            if (is_composite) {
                BOUNDS_CHECK(cp, end, 4);
                length = *cp++;
                length = (length << 8) | *cp++;
                length = (length << 8) | *cp++;
                length = (length << 8) | *cp++;

                BOUNDS_CHECK(cp, end, length);
                code = import_name_composite(context,
                                             cp, length,
                                             &ad_context);
                if (code != 0)
                    goto fail_name;
                cp += length;
            }
            assert(cp == end);
        } else {
            status = GSS_S_BAD_NAMETYPE;
            goto cleanup;
        }

        /* At this point, stringrep is set, or if not, code is. */
        if (stringrep) {
            code = krb5_parse_name(context, (char *)stringrep, &princ);
            if (code)
                goto cleanup;
        } else {
        fail_name:
            status = GSS_S_BAD_NAME;
            goto cleanup;
        }
    }

    /* Create a name and save it in the validation database. */
    code = kg_init_name(context, princ, service, host, ad_context,
                        KG_INIT_NAME_NO_COPY, &name);
    if (code)
        goto cleanup;
    princ = NULL;
    ad_context = NULL;
    service = host = NULL;
    *output_name = (gss_name_t)name;
    status = GSS_S_COMPLETE;

cleanup:
    *minor_status = (OM_uint32)code;
    if (*minor_status)
        save_error_info(*minor_status, context);
    krb5_free_principal(context, princ);
    krb5_authdata_context_free(context, ad_context);
    krb5_free_context(context);
    free(tmp);
    free(tmp2);
    free(service);
    free(host);
    return status;
}

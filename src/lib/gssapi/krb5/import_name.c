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

OM_uint32
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
    char *tmp, *stringrep, *tmp2;
    ssize_t    length;
#ifndef NO_PASSWORD
    struct passwd *pw;
#endif
    int has_ad = 0;
    krb5_authdata_context ad_context = NULL;

    code = krb5_gss_init_context(&context);
    if (code) {
        *minor_status = code;
        return GSS_S_FAILURE;
    }

    /* set up default returns */

    *output_name = NULL;
    *minor_status = 0;

    /* Go find the appropriate string rep to pass into parse_name */

    if ((input_name_type != GSS_C_NULL_OID) &&
        (g_OID_equal(input_name_type, gss_nt_service_name) ||
         g_OID_equal(input_name_type, gss_nt_service_name_v2))) {
        char *service, *host;

        if ((tmp =
             xmalloc(input_name_buffer->length + 1)) == NULL) {
            *minor_status = ENOMEM;
            krb5_free_context(context);
            return(GSS_S_FAILURE);
        }

        memcpy(tmp, input_name_buffer->value, input_name_buffer->length);
        tmp[input_name_buffer->length] = 0;

        service = tmp;
        if ((host = strchr(tmp, '@'))) {
            *host = '\0';
            host++;
        }

        code = krb5_sname_to_principal(context, host, service, KRB5_NT_SRV_HST,
                                       &princ);

        xfree(tmp);
    } else if ((input_name_type != GSS_C_NULL_OID) &&
               (g_OID_equal(input_name_type, gss_nt_krb5_principal))) {
        krb5_principal input;

        if (input_name_buffer->length != sizeof(krb5_principal)) {
            *minor_status = (OM_uint32) G_WRONG_SIZE;
            krb5_free_context(context);
            return(GSS_S_BAD_NAME);
        }

        input = *((krb5_principal *) input_name_buffer->value);

        if ((code = krb5_copy_principal(context, input, &princ))) {
            *minor_status = code;
            save_error_info(*minor_status, context);
            krb5_free_context(context);
            return(GSS_S_FAILURE);
        }
    } else if ((input_name_type != NULL) &&
               g_OID_equal(input_name_type, GSS_C_NT_ANONYMOUS)) {
        code = krb5_copy_principal(context, krb5_anonymous_principal(), &princ);
        if (code != 0) {
            krb5_free_context(context);
            *minor_status = code;
            return GSS_S_FAILURE;
        }
    }
    else {
#ifndef NO_PASSWORD
        uid_t uid;
        struct passwd pwx;
        char pwbuf[BUFSIZ];
#endif

        stringrep = NULL;

        if ((tmp =
             (char *) xmalloc(input_name_buffer->length + 1)) == NULL) {
            *minor_status = ENOMEM;
            krb5_free_context(context);
            return(GSS_S_FAILURE);
        }
        tmp2 = 0;

        memcpy(tmp, input_name_buffer->value, input_name_buffer->length);
        tmp[input_name_buffer->length] = 0;

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
                *minor_status = (OM_uint32) G_NOUSER;
        } else if (g_OID_equal(input_name_type, gss_nt_string_uid_name)) {
            uid = atoi(tmp);
            goto do_getpwuid;
#endif
        } else if (g_OID_equal(input_name_type, gss_nt_exported_name)) {
#define BOUNDS_CHECK(cp, end, n) do { if ((end) - (cp) < (n)) goto fail_name; } while (0)
            cp = (unsigned char *)tmp;
            end = cp + input_name_buffer->length;

            BOUNDS_CHECK(cp, end, 2);
            if (*cp++ != 0x04)
                goto fail_name;
            switch (*cp++) {
            case 0x01:
                break;
            case 0x02:
                has_ad++;
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
            tmp2 = malloc(length+1);
            if (tmp2 == NULL) {
                xfree(tmp);
                *minor_status = ENOMEM;
                krb5_free_context(context);
                return GSS_S_FAILURE;
            }
            strncpy(tmp2, (char *)cp, length);
            tmp2[length] = 0;
            stringrep = tmp2;
            cp += length;

            if (has_ad) {
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
            xfree(tmp);
            krb5_free_context(context);
            return(GSS_S_BAD_NAMETYPE);
        }

        /* at this point, stringrep is set, or if not, *minor_status is. */

        if (stringrep)
            code = krb5_parse_name(context, (char *) stringrep, &princ);
        else {
        fail_name:
            xfree(tmp);
            if (tmp2)
                xfree(tmp2);
            krb5_free_context(context);
            return(GSS_S_BAD_NAME);
        }

        if (tmp2)
            xfree(tmp2);
        xfree(tmp);
    }

    /* at this point, a krb5 function has been called to set princ.  code
       contains the return status */

    if (code) {
        *minor_status = (OM_uint32) code;
        save_error_info(*minor_status, context);
        krb5_authdata_context_free(context, ad_context);
        krb5_free_context(context);
        return(GSS_S_BAD_NAME);
    }

    /* save the name in the validation database */
    code = kg_init_name(context, princ, ad_context,
                        KG_INIT_NAME_INTERN | KG_INIT_NAME_NO_COPY,
                        (krb5_gss_name_t *)output_name);
    if (code != 0) {
        *minor_status = (OM_uint32) code;
        save_error_info(*minor_status, context);
        krb5_free_principal(context, princ);
        krb5_authdata_context_free(context, ad_context);
        krb5_free_context(context);
        return(GSS_S_FAILURE);
    }

    krb5_free_context(context);

    /* return it */

    return(GSS_S_COMPLETE);
}

/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/kdb/ldap/libkdb_ldap/ldap_service_stash.c */
/*
 * Copyright (c) 2004-2005, Novell, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *   * The copyright holder's name is not used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <ctype.h>
#include "ldap_main.h"
#include "kdb_ldap.h"
#include "ldap_service_stash.h"

/* Decode a password of the form {HEX}<hexstring>. */
static krb5_error_code
dec_password(krb5_context context, const char *str,
             unsigned char **password_out)
{
    size_t len;
    const unsigned char *p;
    unsigned char *password, *q;
    unsigned int k;

    *password_out = NULL;

    if (strncmp(str, "{HEX}", 5) != 0) {
        krb5_set_error_message(context, EINVAL,
                               _("Not a hexadecimal password"));
        return EINVAL;
    }
    str += 5;

    len = strlen(str);
    if (len % 2 != 0) {
        krb5_set_error_message(context, EINVAL, _("Password corrupt"));
        return EINVAL;
    }

    q = password = malloc(len / 2 + 1);
    if (password == NULL)
        return ENOMEM;

    for (p = (unsigned char *)str; *p != '\0'; p += 2) {
        if (!isxdigit(*p) || !isxdigit(p[1])) {
            free(password);
            krb5_set_error_message(context, EINVAL, _("Password corrupt"));
            return EINVAL;
        }
        sscanf((char *)p, "%2x", &k);
        *q++ = k;
    }
    *q = '\0';

    *password_out = password;
    return 0;
}

krb5_error_code
krb5_ldap_readpassword(krb5_context context, krb5_ldap_context *ldap_context,
                       unsigned char **password)
{
    int                         entryfound=0;
    krb5_error_code             st=0;
    char                        line[RECORDLEN]="0", *start=NULL, *file=NULL;
    FILE                        *fptr=NULL;

    *password = NULL;

    if (ldap_context->service_password_file)
        file = ldap_context->service_password_file;

#ifndef HAVE_STRERROR_R
# undef strerror_r
# define strerror_r(ERRNUM, BUF, SIZE) (strncpy(BUF, strerror(ERRNUM), SIZE), BUF[(SIZE)-1] = 0)
#endif

    fptr = fopen(file, "r");
    if (fptr == NULL) {
        st = errno;
        krb5_set_error_message(context, st,
                               _("Cannot open LDAP password file '%s': %s"),
                               file, error_message(st));
        goto rp_exit;
    }
    set_cloexec_file(fptr);

    /* get the record from the file */
    while (fgets(line, RECORDLEN, fptr)!= NULL) {
        char tmp[RECORDLEN];

        tmp[0] = '\0';
        /* Handle leading white-spaces */
        for (start = line; isspace(*start); ++start);

        /* Handle comment lines */
        if (*start == '!' || *start == '#')
            continue;
        sscanf(line, "%*[ \t]%[^#]", tmp);
        if (tmp[0] == '\0')
            sscanf(line, "%[^#]", tmp);
        if (strcasecmp(tmp, ldap_context->bind_dn) == 0) {
            entryfound = 1; /* service_dn record found !!! */
            break;
        }
    }
    fclose (fptr);

    if (entryfound == 0)  {
        st = KRB5_KDB_SERVER_INTERNAL_ERR;
        krb5_set_error_message(context, st, _("Bind DN entry '%s' missing in "
                                              "LDAP password file '%s'"),
                               ldap_context->bind_dn, file);
        goto rp_exit;
    }
    /* replace the \n with \0 */
    start = strchr(line, '\n');
    if (start)
        *start = '\0';

    start = strchr(line, '#');
    if (start == NULL) {
        /* password field missing */
        st = KRB5_KDB_SERVER_INTERNAL_ERR;
        krb5_set_error_message(context, st, _("Stash file entry corrupt"));
        goto rp_exit;
    }
    ++ start;

    /* Extract the plain password information. */
    st = dec_password(context, start, password);

rp_exit:
    if (st) {
        if (*password)
            free (*password);
        *password = NULL;
    }
    return st;
}

/* Encodes a sequence of bytes in hexadecimal */

int
tohex(krb5_data in, krb5_data *ret)
{
    unsigned int       i=0;
    int                err = 0;

    ret->length = 0;
    ret->data = NULL;

    ret->data = malloc((unsigned int)in.length * 2 + 1 /*Null termination */);
    if (ret->data == NULL) {
        err = ENOMEM;
        goto cleanup;
    }
    ret->length = in.length * 2;
    ret->data[ret->length] = 0;

    for (i = 0; i < in.length; i++)
        snprintf(ret->data + 2 * i, 3, "%02x", in.data[i] & 0xff);

cleanup:

    if (ret->length == 0) {
        free(ret->data);
        ret->data = NULL;
    }

    return err;
}

/*
 * Copyright (c) 2011, PADL Software Pty Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of PADL Software nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL PADL SOFTWARE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <string.h>
#include <errno.h>

#include "saml_kdc.h"

/*
 * Usage: saml_sign [assertion.xml|-] [idp-princ|-] [keytab|-]
 */
int main(int argc, char *argv[])
{
    FILE *fp = NULL;
    krb5_context context = NULL;
    krb5_principal principal = NULL;
    krb5_keytab keytab = NULL;
    krb5_error_code code;
    char buf[BUFSIZ];
    krb5_keytab_entry ent;
    krb5_kt_cursor cursor = NULL;
    krb5_keyblock key;
    krb5_data data;
    krb5_authdata authdata;
    saml2::Assertion *assertion = NULL;
    string signedAssertionBuf;

    memset(&ent, 0, sizeof(ent));
    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));

    if (argc > 4 || (argc > 1 && strcmp(argv[1], "-help") == 0)) {
        fprintf(stderr, "Usage: %s [assertion.xml|-] [idp-princ|-] [keytab|-]\n", argv[0]);
        return EINVAL;
    }

    SAMLConfig &config = SAMLConfig::getConfig();
    config.init();

    if (argc > 1 && strcmp(argv[1], "-") != 0) {
        fp = fopen(argv[1], "r");
        if (fp == NULL) {
            fprintf(stderr, "Failed to open %s for reading: %s\n",
                argv[1], strerror(errno));
            return errno;
        }
    } else {
        fp = stdin;
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        size_t len = strlen(buf);

        data.data = (char *)realloc(data.data, data.length + len + 1);
        if (data.data == NULL) {
            code = ENOMEM;
            goto cleanup;
        }
        memcpy(&data.data[data.length], buf, len);
        data.length += len;
        data.data[data.length] = '\0';
    }

    code = krb5_init_context(&context);
    if (code != 0)
        goto cleanup;

    if (argc > 2 && strcmp(argv[2], "-") != 0) {
        code = krb5_parse_name(context, argv[2], &principal);
        if (code != 0)
            goto cleanup;
    } else {
        principal = NULL;
    }

    if (argc > 3 && strcmp(argv[3], "-") != 0) {
        code = krb5_kt_resolve(context, argv[3], &keytab);
    } else {
        code = krb5_kt_default(context, &keytab);
    }
    if (code != 0)
        goto cleanup;

    code = krb5_kt_start_seq_get(context, keytab, &cursor);
    if (code != 0)
        goto cleanup;

    key.enctype = ENCTYPE_NULL;

    while ((code = krb5_kt_next_entry(context, keytab, &ent, &cursor)) == 0) {
        if (principal != NULL &&
            !krb5_principal_compare(context, principal, ent.principal))
            continue;
        else if (!saml_is_idp_princ(context, ent.principal))
            continue;

        if (principal == NULL) {
            code = krb5_copy_principal(context, ent.principal, &principal);
            if (code != 0)
                goto cleanup;
        }

        code = krb5_copy_keyblock_contents(context, &ent.key, &key);

        krb5_free_keytab_entry_contents(context, &ent);

        if (code == 0)
            break;
    }

    if (code != 0)
        goto cleanup;

    if (key.enctype == ENCTYPE_NULL) {
        code = KRB5_KT_NOTFOUND;
        goto cleanup;
    }

    authdata.ad_type = KRB5_AUTHDATA_SAML;
    authdata.length = data.length;
    authdata.contents = (krb5_octet *)data.data;

    code = saml_krb_decode_assertion(context, &authdata, &assertion);
    if (code != 0)
        goto cleanup;

    try {
        Signature *signature;

        code = saml_krb_build_signature(context, principal, &key,
                                        SAML_KRB_USAGE_SERVER_KEY, &signature);
        if (code != 0)
            goto cleanup;

        assertion->setSignature(signature);
        vector <Signature *> signatures(1, signature);
        XMLHelper::serialize(assertion->marshall((DOMDocument *)NULL, &signatures, NULL), signedAssertionBuf);
    } catch (exception &e) {
        code = KRB5_CRYPTO_INTERNAL;
        goto cleanup;
    }

    fprintf(stdout, "%s\n", signedAssertionBuf.c_str());

cleanup:
    if (fp != stdin)
        fclose(fp);

    if (code != 0)
        fprintf(stderr, "Failed to sign assertion: %s\n",
                krb5_get_error_message(context, code));

    if (principal != NULL)
        krb5_free_principal(context, principal);
    if (cursor != NULL)
        krb5_kt_end_seq_get(context, keytab, &cursor);
    if (keytab != NULL)
        krb5_kt_close(context, keytab);
    krb5_free_keyblock_contents(context, &key);
    krb5_free_data_contents(context, &data);
    if (context != NULL)
        krb5_free_context(context);
    delete assertion;

    return code;
}

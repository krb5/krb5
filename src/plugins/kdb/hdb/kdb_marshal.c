/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * plugins/kdb/hdb/kdb_marshal.c
 *
 * Copyright 2009 by the Massachusetts Institute of Technology.
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
 *
 */

#include "k5-int.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <db.h>
#include <stdio.h>
#include <errno.h>
#include <utime.h>
#include "kdb5.h"
#include "kdb_hdb.h"

void
kh_free_Principal(krb5_context context,
                  Principal *principal)
{
    kh_db_context *kh = KH_DB_CONTEXT(context);

    if (principal != NULL)
        (*kh->heim_free_principal)(kh->hcontext, principal);
}

void
kh_free_Event(krb5_context context,
              Event *event)
{
    kh_free_Principal(context, event->principal);
}

void
kh_free_HostAddresses(krb5_context context,
                      HostAddresses *addrs)
{
    kh_db_context *kh = KH_DB_CONTEXT(context);

    if (addrs != NULL)
        (*kh->heim_free_addresses)(kh->hcontext, addrs);
}

#if 0
static krb5_error_code
kh_marshal_octet_string(krb5_context context,
                        const krb5_data *in_data,
                        heim_octet_string *out_data)
{
    out_data->data = malloc(in_data->length);
    if (out_data->data == NULL)
        return ENOMEM;

    memcpy(out_data->data, in_data->data, in_data->length);

    out_data->length = in_data->length;

    return 0;
}

static krb5_error_code
kh_unmarshal_octet_string_contents(krb5_context context,
                                   const heim_octet_string *in_data,
                                   krb5_data *out_data)
{
    out_data->magic = KV5M_DATA;
    out_data->data = malloc(in_data->length);
    if (out_data->data == NULL)
        return ENOMEM;

    memcpy(out_data->data, in_data->data, in_data->length);

    out_data->length = in_data->length;

    return 0;
}

static krb5_error_code
kh_unmarshal_octet_string(krb5_context context,
                          heim_octet_string *in_data,
                          krb5_data **out_data)
{
    krb5_error_code code;

    *out_data = k5alloc(sizeof(krb5_data), &code);
    if (code != 0)
        return code;

    code = kh_unmarshal_octet_string_contents(context, in_data, *out_data);
    if (code != 0) {
        free(*out_data);
        *out_data = NULL;
        return code;
    }

    return 0;
}
#endif

static krb5_error_code
kh_marshal_general_string(krb5_context context,
                          const krb5_data *in_data,
                          heim_general_string *out_str)
{
    *out_str = malloc(in_data->length + 1);
    if (*out_str == NULL)
        return ENOMEM;

    memcpy(*out_str, in_data->data, in_data->length);
    (*out_str)[in_data->length] = '\0';

    return 0;
}

static krb5_error_code
kh_unmarshal_general_string_contents(krb5_context context,
                                     const heim_general_string in_str,
                                     krb5_data *out_data)
{
    out_data->magic = KV5M_DATA;
    out_data->length = strlen(in_str);
    out_data->data = malloc(out_data->length);
    if (out_data->data == NULL)
        return ENOMEM;

    memcpy(out_data->data, in_str, out_data->length);
    return 0;
}

#if 0
static krb5_error_code
kh_unmarshal_general_string(krb5_context context,
                            const heim_general_string in_str,
                            krb5_data **out_data)
{
    krb5_error_code code;

    *out_data = k5alloc(sizeof(krb5_data), &code);
    if (code != 0)
        return code;

    code = kh_unmarshal_general_string_contents(context, in_str, *out_data);
    if (code != 0) {
        free(*out_data);
        *out_data = NULL;
        return code;
    }

    return 0;
}
#endif

krb5_error_code
kh_marshal_Principal(krb5_context context,
                     krb5_const_principal kprinc,
                     Principal **out_hprinc)
{
    krb5_error_code code;
    Principal *hprinc;
    int i;

    hprinc = k5alloc(sizeof(*hprinc), &code);
    if (code != 0)
        return code;

    hprinc->name.name_type = kprinc->type;
    hprinc->name.name_string.val = k5alloc(kprinc->length *
                                           sizeof(heim_general_string),
                                           &code);
    if (code != 0) {
        kh_free_Principal(context, hprinc);
        return code;
    }
    for (i = 0; i < kprinc->length; i++) {
        code = kh_marshal_general_string(context, &kprinc->data[i],
                                         &hprinc->name.name_string.val[i]);
        if (code != 0) {
            kh_free_Principal(context, hprinc);
            return code;
        }
        hprinc->name.name_string.len++;
    }
    code = kh_marshal_general_string(context, &kprinc->realm, &hprinc->realm);
    if (code != 0) {
        kh_free_Principal(context, hprinc);
        return code;
    }

    *out_hprinc = hprinc;

    return 0;
}

krb5_error_code
kh_unmarshal_Principal(krb5_context context,
                       const Principal *hprinc,
                       krb5_principal *out_kprinc)
{
    krb5_error_code code;
    krb5_principal kprinc;
    unsigned int i;

    kprinc = k5alloc(sizeof(*kprinc), &code);
    if (code != 0)
        return code;

    kprinc->magic = KV5M_PRINCIPAL;
    kprinc->type = hprinc->name.name_type;
    kprinc->data = k5alloc(hprinc->name.name_string.len * sizeof(krb5_data),
                           &code);
    if (code != 0) {
        krb5_free_principal(context, kprinc);
        return code;
    }
    for (i = 0; i < hprinc->name.name_string.len; i++) {
        code = kh_unmarshal_general_string_contents(context,
                                                    hprinc->name.name_string.val[i],
                                                    &kprinc->data[i]);
        if (code != 0) {
            krb5_free_principal(context, kprinc);
            return code;
        }
        kprinc->length++;
    }
    code = kh_unmarshal_general_string_contents(context,
                                                hprinc->realm,
                                                &kprinc->realm);
    if (code != 0) {
        krb5_free_principal(context, kprinc);
        return code;
    }

    *out_kprinc = kprinc;

    return 0;
}

static krb5_error_code
kh_marshal_Event(krb5_context context,
                 const krb5_db_entry *kentry,
                 Event *event)
{
    krb5_error_code code;
    krb5_timestamp mod_time = 0;
    krb5_principal mod_princ = NULL;

    memset(event, 0, sizeof(*event));

    code = krb5_dbe_lookup_mod_princ_data(context, (krb5_db_entry *)kentry,
                                          &mod_time, &mod_princ);
    if (code != 0)
        return code;

    event->time = mod_time;

    if (mod_princ != NULL) {
        code = kh_marshal_Principal(context, mod_princ, &event->principal);
        if (code != 0) {
            krb5_free_principal(context, mod_princ);
            return code;
        }
    }

    krb5_free_principal(context, mod_princ);

    return 0;
}

static krb5_error_code
kh_unmarshal_Event(krb5_context context,
                   const Event *event,
                   krb5_db_entry *kentry)
{
    krb5_error_code code;
    krb5_principal princ = NULL;

    if (event->principal != NULL) {
        code = kh_unmarshal_Principal(context, event->principal, &princ);
        if (code != 0)
            return code;
    }

    code = krb5_dbe_update_mod_princ_data(context, kentry,
                                          event->time, princ);

    krb5_free_principal(context, princ);

    return code;
}

static krb5_error_code
kh_marshal_HDBFlags(krb5_context context,
                    krb5_flags kflags,
                    HDBFlags *hflags)
{
    memset(hflags, 0, sizeof(*hflags));

    if (kflags & KRB5_KDB_DISALLOW_TGT_BASED)
        hflags->initial = 1;
    if ((kflags & KRB5_KDB_DISALLOW_FORWARDABLE) == 0)
        hflags->forwardable = 1;
    if ((kflags & KRB5_KDB_DISALLOW_PROXIABLE) == 0)
        hflags->proxiable = 1;
    if ((kflags & KRB5_KDB_DISALLOW_RENEWABLE) == 0)
        hflags->renewable = 1;
    if ((kflags & KRB5_KDB_DISALLOW_POSTDATED) == 0)
        hflags->postdate = 1;
    if ((kflags & KRB5_KDB_DISALLOW_SVR) == 0)
        hflags->server = 1;
    hflags->client = 1;
    if (kflags & KRB5_KDB_DISALLOW_ALL_TIX)
        hflags->invalid = 1;
    if (kflags & KRB5_KDB_REQUIRES_PRE_AUTH)
        hflags->require_preauth = 1;
    if (kflags & KRB5_KDB_PWCHANGE_SERVICE)
        hflags->change_pw = 1;
    if (kflags & KRB5_KDB_REQUIRES_HW_AUTH)
        hflags->require_hwauth = 1;
    if (kflags & KRB5_KDB_OK_AS_DELEGATE)
        hflags->ok_as_delegate = 1;
    /* hflags->user_to_user */
    /* hflags->immutable */
    if (kflags & KRB5_KDB_OK_TO_AUTH_AS_DELEGATE)
        hflags->trusted_for_delegation = 1;
    /* hflags->allow_kerberos4 */
    /* hflags->allow_digest */

    return 0;
}

static krb5_error_code
kh_unmarshal_HDBFlags(krb5_context context,
                      HDBFlags hflags,
                      krb5_flags *kflags)
{
    *kflags = 0;

    if (hflags.initial)
        *kflags |= KRB5_KDB_DISALLOW_TGT_BASED;
    if (!hflags.forwardable)
        *kflags |= KRB5_KDB_DISALLOW_FORWARDABLE;
    if (!hflags.proxiable)
        *kflags |= KRB5_KDB_DISALLOW_PROXIABLE;
    if (!hflags.renewable)
        *kflags |= KRB5_KDB_DISALLOW_RENEWABLE;
    if (!hflags.postdate)
        *kflags |= KRB5_KDB_DISALLOW_POSTDATED;
    if (!hflags.server)
        *kflags |= KRB5_KDB_DISALLOW_SVR;
    if (hflags.client)
        ;
    if (hflags.invalid)
        *kflags |= KRB5_KDB_DISALLOW_ALL_TIX;
    if (hflags.require_preauth)
        *kflags |= KRB5_KDB_REQUIRES_PRE_AUTH;
    if (hflags.change_pw)
        *kflags |= KRB5_KDB_PWCHANGE_SERVICE;
    if (hflags.require_hwauth)
        *kflags |= KRB5_KDB_REQUIRES_HW_AUTH;
    if (hflags.ok_as_delegate)
        *kflags |= KRB5_KDB_OK_AS_DELEGATE;
    if (hflags.user_to_user)
        ;
    if (hflags.immutable)
        ;
    if (hflags.trusted_for_delegation)
        *kflags |= KRB5_KDB_OK_TO_AUTH_AS_DELEGATE;
    if (hflags.allow_kerberos4)
        ;
    if (hflags.allow_digest)
        ;
    return 0;
}

static krb5_error_code
kh_marshal_Key(krb5_context context,
               const krb5_key_data *kkey,
               Key *hkey)
{
    krb5_error_code code;

    memset(hkey, 0, sizeof(*hkey));

    hkey->key.keytype = kkey->key_data_type[0];
    hkey->key.keyvalue.data = k5alloc(kkey->key_data_length[0], &code);
    if (code != 0)
        return code;
    memcpy(hkey->key.keyvalue.data, kkey->key_data_contents[0],
           kkey->key_data_length[0]);
    hkey->key.keyvalue.length = kkey->key_data_length[0];

    if (kkey->key_data_contents[1] != NULL) {
        Salt *salt;

        salt = k5alloc(sizeof(*salt), &code);
        if (code != 0)
            goto cleanup;

        switch (kkey->key_data_type[1]) {
        case KRB5_KDB_SALTTYPE_NORMAL:
            salt->type = hdb_pw_salt;
            break;
        case KRB5_KDB_SALTTYPE_AFS3:
            salt->type = hdb_afs3_salt;
            break;
        default:
            salt->type = 0;
            break;
        }

        salt->salt.data = k5alloc(kkey->key_data_length[1], &code);
        if (code != 0) {
            free(salt);
            goto cleanup;
        }
        memcpy(salt->salt.data, kkey->key_data_contents[1],
               kkey->key_data_length[1]);
        salt->salt.length = kkey->key_data_length[1];

        hkey->salt = salt;
    }

cleanup:
    if (code != 0 && hkey->key.keyvalue.data != NULL)
        free(hkey->key.keyvalue.data);

    return code;
}

static krb5_error_code
kh_unmarshal_Key(krb5_context context,
                 const hdb_entry *hentry,
                 const Key *hkey,
                 krb5_key_data *kkey)
{
    memset(kkey, 0, sizeof(*kkey));

    kkey->key_data_ver = KRB5_KDB_V1_KEY_DATA_ARRAY;
    kkey->key_data_kvno = hentry->kvno;

    kkey->key_data_type[0] = hkey->key.keytype;
    kkey->key_data_contents[0] = malloc(hkey->key.keyvalue.length);
    if (kkey->key_data_contents[0] == NULL)
        return ENOMEM;

    memcpy(kkey->key_data_contents[0], hkey->key.keyvalue.data,
           hkey->key.keyvalue.length);
    kkey->key_data_length[0] = hkey->key.keyvalue.length;

    if (hkey->salt != NULL) {
        switch (hkey->salt->type) {
        case hdb_pw_salt:
            kkey->key_data_type[1] = KRB5_KDB_SALTTYPE_NORMAL;
            break;
        case hdb_afs3_salt:
            kkey->key_data_type[1] = KRB5_KDB_SALTTYPE_AFS3;
            break;
        default:
            kkey->key_data_type[1] = KRB5_KDB_SALTTYPE_SPECIAL;
            break;
        }

        kkey->key_data_contents[1] = malloc(hkey->salt->salt.length);
        if (kkey->key_data_contents[1] == NULL) {
            memset(kkey->key_data_contents[0], 0, kkey->key_data_length[0]);
            free(kkey->key_data_contents[0]);
            return ENOMEM;
        }
        memcpy(kkey->key_data_contents[1], hkey->salt->salt.data,
               hkey->salt->salt.length);
        kkey->key_data_length[1] = hkey->salt->salt.length;
    }

    return 0;
}

/*
 * Extension marshalers
 */

static krb5_error_code
kh_marshal_HDB_extension_data_last_pw_change(krb5_context context,
                                             const krb5_db_entry *kentry,
                                             HDB_extension *hext)
{
    krb5_timestamp stamp;
    krb5_error_code code;

    code = krb5_dbe_lookup_last_pwd_change(context,
                                           (krb5_db_entry *)kentry, &stamp);
    if (code != 0)
        return code;

    hext->data.u.last_pw_change = stamp;

    return 0;
}

static krb5_error_code
kh_unmarshal_HDB_extension_data_last_pw_change(krb5_context context,
                                               HDB_extension *hext,
                                               krb5_db_entry *kentry)
{
    return krb5_dbe_update_last_pwd_change(context, kentry,
                                           hext->data.u.last_pw_change);
}

typedef krb5_error_code (*kh_hdb_marshal_extension_fn)(krb5_context,
                                                       const krb5_db_entry *,
                                                       HDB_extension *);

typedef krb5_error_code (*kh_hdb_unmarshal_extension_fn)(krb5_context,
                                                         HDB_extension *,
                                                         krb5_db_entry *);

struct {
    kh_hdb_marshal_extension_fn marshal;
    kh_hdb_unmarshal_extension_fn unmarshal;
} kh_hdb_extension_vtable[] = {
    { NULL, NULL }, /* choice_HDB_extension_data_asn1_ellipsis */
    { NULL, NULL }, /* choice_HDB_extension_data_pkinit_acl */
    { NULL, NULL }, /* choice_HDB_extension_data_pkinit_cert_hash */
    { NULL, NULL }, /* choice_HDB_extension_data_allowed_to_delegate_to */
    { NULL, NULL }, /* choice_HDB_extension_data_lm_owf */
    { NULL, NULL }, /* choice_HDB_extension_data_password */
    { NULL, NULL }, /* choice_HDB_extension_data_aliases */
    { kh_marshal_HDB_extension_data_last_pw_change,
      kh_unmarshal_HDB_extension_data_last_pw_change }
};

static const size_t kh_hdb_extension_count =
    sizeof(kh_hdb_extension_vtable) / sizeof(kh_hdb_extension_vtable[0]);

static krb5_error_code
kh_marshal_HDB_extension(krb5_context context,
                         const krb5_db_entry *kentry,
                         HDB_extension *hext)
{
    kh_hdb_marshal_extension_fn marshal = NULL;

    if (hext->data.element < kh_hdb_extension_count)
        marshal = kh_hdb_extension_vtable[hext->data.element].marshal;

    if (marshal == NULL)
        return KRB5_KDB_DBTYPE_NOSUP;

    return (*marshal)(context, kentry, hext);
}

static krb5_error_code
kh_unmarshal_HDB_extension(krb5_context context,
                           HDB_extension *hext,
                           krb5_db_entry *kentry)
{
    kh_hdb_unmarshal_extension_fn unmarshal = NULL;

    if (hext->data.element < kh_hdb_extension_count)
        unmarshal = kh_hdb_extension_vtable[hext->data.element].unmarshal;

    if (unmarshal == NULL)
        return hext->mandatory ? KRB5_KDB_DBTYPE_NOSUP : 0;

    return (*unmarshal)(context, hext, kentry);
}

static krb5_error_code
kh_marshal_HDB_extensions(krb5_context context,
                          const krb5_db_entry *kentry,
                          HDB_extensions *hexts)
{
    unsigned int i;
    krb5_error_code code;

    hexts->val = k5alloc(kh_hdb_extension_count * sizeof(HDB_extension), &code);
    if (code != 0)
        return code;

    hexts->len = 0;

    for (i = 0; i < kh_hdb_extension_count; i++) {
        HDB_extension *hext = &hexts->val[hexts->len];

        hext->data.element = i;

        code = kh_marshal_HDB_extension(context, kentry, hext);
        if (code == KRB5_KDB_DBTYPE_NOSUP)
            continue;
        else if (code != 0)
            break;

        hexts->len++;
    }

    return code;
}

static krb5_error_code
kh_unmarshal_HDB_extensions(krb5_context context,
                            HDB_extensions *hexts,
                            krb5_db_entry *kentry)
{
    unsigned int i;
    krb5_error_code code = 0;

    for (i = 0; i < hexts->len; i++) {
        code = kh_unmarshal_HDB_extension(context, &hexts->val[i], kentry);
        if (code != 0)
            break;
    }

    return code;
}

krb5_error_code
kh_marshal_hdb_entry(krb5_context context,
                     const krb5_db_entry *kentry,
                     hdb_entry *hentry)
{
    kh_db_context *kh = KH_DB_CONTEXT(context);
    krb5_error_code code;
    krb5_int16 kvno = 0;
    int i;

    memset(hentry, 0, sizeof(*hentry));

    code = kh_marshal_Principal(context, kentry->princ, &hentry->principal);
    if (code != 0)
        goto cleanup;

    code = kh_marshal_HDBFlags(context, kentry->attributes, &hentry->flags);
    if (code != 0)
        goto cleanup;

    if (kentry->expiration) {
        hentry->valid_end = k5alloc(sizeof(KerberosTime), &code);
        if (code != 0)
            goto cleanup;
        *(hentry->valid_end) = kentry->expiration;
    }
    if (kentry->pw_expiration) {
        hentry->pw_end = k5alloc(sizeof(KerberosTime), &code);
        if (code != 0)
            goto cleanup;
        *(hentry->pw_end) = kentry->pw_expiration;
    }
    if (kentry->max_life) {
        hentry->max_life = k5alloc(sizeof(unsigned int), &code);
        if (code != 0)
            goto cleanup;
        *(hentry->max_life) = kentry->max_life;
    }
    if (kentry->max_renewable_life) {
        hentry->max_renew = k5alloc(sizeof(unsigned int), &code);
        if (code != 0)
            goto cleanup;
        *(hentry->max_renew) = kentry->max_renewable_life;
    }

    /* last_success */
    /* last_failed */
    /* fail_auth_count */
    /* n_tl_data */

    if ((kentry->attributes & KRB5_KDB_NEW_PRINC) == 0) {
        hentry->modified_by = k5alloc(sizeof(Event), &code);
        if (code != 0)
            goto cleanup;
        code = kh_marshal_Event(context, kentry, hentry->modified_by);
    } else {
        code = kh_marshal_Event(context, kentry, &hentry->created_by);
    }
    if (code != 0)
        goto cleanup;

    hentry->extensions = k5alloc(sizeof(HDB_extensions), &code);
    if (code != 0)
        goto cleanup;

    code = kh_marshal_HDB_extensions(context, kentry, hentry->extensions);
    if (code != 0)
        goto cleanup;

    hentry->keys.len = 0;
    hentry->keys.val = k5alloc(kentry->n_key_data * sizeof(Key), &code);
    if (code != 0)
        goto cleanup;

    for (i = 0; i < kentry->n_key_data; i++) {
        code = kh_marshal_Key(context,
                              &kentry->key_data[i],
                              &hentry->keys.val[hentry->keys.len]);
        if (code != 0)
            goto cleanup;

        if (kentry->key_data[i].key_data_kvno > kvno)
            kvno = kentry->key_data[i].key_data_kvno;

        hentry->keys.len++;
    }

    hentry->kvno = kvno;

cleanup:
    if (code != 0) {
        hdb_entry_ex hext;

        hext.ctx = NULL;
        hext.entry = *hentry;
        hext.free_entry = NULL;

        kh_hdb_free_entry(context, kh, &hext);
        memset(hentry, 0, sizeof(*hentry));
    }

    return code;
}

krb5_error_code
kh_unmarshal_hdb_entry(krb5_context context,
                       const hdb_entry *hentry,
                       krb5_db_entry **kentry_ptr)
{
    kh_db_context *kh = KH_DB_CONTEXT(context);
    krb5_db_entry *kentry;
    krb5_error_code code;
    unsigned int i;

    kentry = k5alloc(sizeof(*kentry), &code);
    if (kentry == NULL)
        return code;

    kentry->magic = KRB5_KDB_MAGIC_NUMBER;
    kentry->len = KRB5_KDB_V1_BASE_LENGTH;

    code = kh_unmarshal_Principal(context, hentry->principal, &kentry->princ);
    if (code != 0)
        goto cleanup;

    code = kh_unmarshal_HDBFlags(context, hentry->flags, &kentry->attributes);
    if (code != 0)
        goto cleanup;

    if (hentry->max_life != NULL)
        kentry->max_life = *(hentry->max_life);
    if (hentry->max_renew != NULL)
        kentry->max_renewable_life = *(hentry->max_renew);
    if (hentry->valid_end != NULL)
        kentry->expiration = *(hentry->valid_end);
    if (hentry->pw_end != NULL)
        kentry->pw_expiration = *(hentry->pw_end);

    /* last_success */
    /* last_failed */
    /* fail_auth_count */
    /* n_tl_data */

    code = kh_unmarshal_Event(context,
                              hentry->modified_by ? hentry->modified_by :
                              &hentry->created_by,
                              kentry);
    if (code != 0)
        goto cleanup;

    code = kh_unmarshal_HDB_extensions(context, hentry->extensions, kentry);
    if (code != 0)
        goto cleanup;

    kentry->key_data = k5alloc(hentry->keys.len * sizeof(krb5_key_data), &code);
    if (code != 0)
        goto cleanup;

    for (i = 0; i < hentry->keys.len; i++) {
        code = kh_unmarshal_Key(context, hentry,
                                &hentry->keys.val[i],
                                &kentry->key_data[i]);
        if (code != 0)
            goto cleanup;

        kentry->n_key_data++;
    }

    *kentry_ptr = kentry;
    kentry = NULL;

cleanup:
    kh_kdb_free_entry(context, kh, kentry);
    return code;
}

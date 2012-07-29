/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/kdb/ldap/libkdb_ldap/ldap_principal.c */
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
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "ldap_main.h"
#include "kdb_ldap.h"
#include "ldap_principal.h"
#include "princ_xdr.h"
#include "ldap_err.h"

struct timeval timelimit = {300, 0};  /* 5 minutes */
char     *principal_attributes[] = { "krbprincipalname",
                                     "krbcanonicalname",
                                     "objectclass",
                                     "krbprincipalkey",
                                     "krbmaxrenewableage",
                                     "krbmaxticketlife",
                                     "krbticketflags",
                                     "krbprincipalexpiration",
                                     "krbticketpolicyreference",
                                     "krbUpEnabled",
                                     "krbpwdpolicyreference",
                                     "krbpasswordexpiration",
                                     "krbLastFailedAuth",
                                     "krbLoginFailedCount",
                                     "krbLastSuccessfulAuth",
                                     "krbLastPwdChange",
                                     "krbLastAdminUnlock",
                                     "krbExtraData",
                                     "krbObjectReferences",
                                     "krbAllowedToDelegateTo",
                                     NULL };

/* Must match KDB_*_ATTR macros in ldap_principal.h.  */
static char *attributes_set[] = { "krbmaxticketlife",
                                  "krbmaxrenewableage",
                                  "krbticketflags",
                                  "krbprincipalexpiration",
                                  "krbticketpolicyreference",
                                  "krbUpEnabled",
                                  "krbpwdpolicyreference",
                                  "krbpasswordexpiration",
                                  "krbprincipalkey",
                                  "krblastpwdchange",
                                  "krbextradata",
                                  "krbLastSuccessfulAuth",
                                  "krbLastFailedAuth",
                                  "krbLoginFailedCount",
                                  "krbLastAdminUnlock",
                                  NULL };

void
krb5_dbe_free_contents(krb5_context context, krb5_db_entry *entry)
{
    krb5_tl_data        *tl_data_next=NULL;
    krb5_tl_data        *tl_data=NULL;
    int i, j;

    if (entry->e_data)
        free(entry->e_data);
    if (entry->princ)
        krb5_free_principal(context, entry->princ);
    for (tl_data = entry->tl_data; tl_data; tl_data = tl_data_next) {
        tl_data_next = tl_data->tl_data_next;
        if (tl_data->tl_data_contents)
            free(tl_data->tl_data_contents);
        free(tl_data);
    }
    if (entry->key_data) {
        for (i = 0; i < entry->n_key_data; i++) {
            for (j = 0; j < entry->key_data[i].key_data_ver; j++) {
                if (entry->key_data[i].key_data_length[j]) {
                    if (entry->key_data[i].key_data_contents[j]) {
                        memset(entry->key_data[i].key_data_contents[j],
                               0,
                               (unsigned) entry->key_data[i].key_data_length[j]);
                        free (entry->key_data[i].key_data_contents[j]);
                    }
                }
                entry->key_data[i].key_data_contents[j] = NULL;
                entry->key_data[i].key_data_length[j] = 0;
                entry->key_data[i].key_data_type[j] = 0;
            }
        }
        free(entry->key_data);
    }
    memset(entry, 0, sizeof(*entry));
    return;
}


void
krb5_ldap_free_principal(krb5_context kcontext, krb5_db_entry *entry)
{
    if (entry == NULL)
        return;
    krb5_dbe_free_contents(kcontext, entry);
    free(entry);
}

krb5_error_code
krb5_ldap_iterate(krb5_context context, char *match_expr,
                  krb5_error_code (*func)(krb5_pointer, krb5_db_entry *),
                  krb5_pointer func_arg)
{
    krb5_db_entry            entry;
    krb5_principal           principal;
    char                     **subtree=NULL, *princ_name=NULL, *realm=NULL, **values=NULL, *filter=NULL;
    unsigned int             tree=0, ntree=1, i=0;
    krb5_error_code          st=0, tempst=0;
    LDAP                     *ld=NULL;
    LDAPMessage              *result=NULL, *ent=NULL;
    kdb5_dal_handle          *dal_handle=NULL;
    krb5_ldap_context        *ldap_context=NULL;
    krb5_ldap_server_handle  *ldap_server_handle=NULL;
    char                     *default_match_expr = "*";

    /* Clear the global error string */
    krb5_clear_error_message(context);

    memset(&entry, 0, sizeof(krb5_db_entry));
    SETUP_CONTEXT();

    realm = ldap_context->lrparams->realm_name;
    if (realm == NULL) {
        realm = context->default_realm;
        if (realm == NULL) {
            st = EINVAL;
            krb5_set_error_message(context, st, _("Default realm not set"));
            goto cleanup;
        }
    }

    /*
     * If no match_expr then iterate through all krb princs like the db2 plugin
     */
    if (match_expr == NULL)
        match_expr = default_match_expr;

    if (asprintf(&filter, FILTER"%s))", match_expr) < 0)
        filter = NULL;
    CHECK_NULL(filter);

    if ((st = krb5_get_subtree_info(ldap_context, &subtree, &ntree)) != 0)
        goto cleanup;

    GET_HANDLE();

    for (tree=0; tree < ntree; ++tree) {

        LDAP_SEARCH(subtree[tree], ldap_context->lrparams->search_scope, filter, principal_attributes);
        for (ent=ldap_first_entry(ld, result); ent != NULL; ent=ldap_next_entry(ld, ent)) {
            values=ldap_get_values(ld, ent, "krbcanonicalname");
            if (values == NULL)
                values=ldap_get_values(ld, ent, "krbprincipalname");
            if (values != NULL) {
                for (i=0; values[i] != NULL; ++i) {
                    if (krb5_ldap_parse_principal_name(values[i], &princ_name) != 0)
                        continue;
                    if (krb5_parse_name(context, princ_name, &principal) != 0)
                        continue;
                    if (is_principal_in_realm(ldap_context, principal) == 0) {
                        if ((st = populate_krb5_db_entry(context, ldap_context, ld, ent, principal,
                                                         &entry)) != 0)
                            goto cleanup;
                        (*func)(func_arg, &entry);
                        krb5_dbe_free_contents(context, &entry);
                        (void) krb5_free_principal(context, principal);
                        free(princ_name);
                        break;
                    }
                    (void) krb5_free_principal(context, principal);
                    free(princ_name);
                }
                ldap_value_free(values);
            }
        } /* end of for (ent= ... */
        ldap_msgfree(result);
    } /* end of for (tree= ... */

cleanup:
    if (filter)
        free (filter);

    for (;ntree; --ntree)
        if (subtree[ntree-1])
            free (subtree[ntree-1]);

    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    return st;
}


/*
 * delete a principal from the directory.
 */
krb5_error_code
krb5_ldap_delete_principal(krb5_context context,
                           krb5_const_principal searchfor)
{
    char                      *user=NULL, *DN=NULL, *strval[10] = {NULL};
    LDAPMod                   **mods=NULL;
    LDAP                      *ld=NULL;
    int                       j=0, ptype=0, pcount=0, attrsetmask=0;
    krb5_error_code           st=0;
    krb5_boolean              singleentry=FALSE;
    KEY                       *secretkey=NULL;
    kdb5_dal_handle           *dal_handle=NULL;
    krb5_ldap_context         *ldap_context=NULL;
    krb5_ldap_server_handle   *ldap_server_handle=NULL;
    krb5_db_entry             *entry = NULL;

    /* Clear the global error string */
    krb5_clear_error_message(context);

    SETUP_CONTEXT();
    /* get the principal info */
    if ((st=krb5_ldap_get_principal(context, searchfor, 0, &entry)))
        goto cleanup;

    if (((st=krb5_get_princ_type(context, entry, &(ptype))) != 0) ||
        ((st=krb5_get_attributes_mask(context, entry, &(attrsetmask))) != 0) ||
        ((st=krb5_get_princ_count(context, entry, &(pcount))) != 0) ||
        ((st=krb5_get_userdn(context, entry, &(DN))) != 0))
        goto cleanup;

    if (DN == NULL) {
        st = EINVAL;
        krb5_set_error_message(context, st, _("DN information missing"));
        goto cleanup;
    }

    GET_HANDLE();

    if (ptype == KDB_STANDALONE_PRINCIPAL_OBJECT) {
        st = ldap_delete_ext_s(ld, DN, NULL, NULL);
        if (st != LDAP_SUCCESS) {
            st = set_ldap_error (context, st, OP_DEL);
            goto cleanup;
        }
    } else {
        if (((st=krb5_unparse_name(context, searchfor, &user)) != 0)
            || ((st=krb5_ldap_unparse_principal_name(user)) != 0))
            goto cleanup;

        memset(strval, 0, sizeof(strval));
        strval[0] = user;
        if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbprincipalname", LDAP_MOD_DELETE,
                                          strval)) != 0)
            goto cleanup;

        singleentry = (pcount == 1) ? TRUE: FALSE;
        if (singleentry == FALSE) {
            if (secretkey != NULL) {
                if ((st=krb5_add_ber_mem_ldap_mod(&mods, "krbprincipalkey", LDAP_MOD_DELETE | LDAP_MOD_BVALUES,
                                                  secretkey->keys)) != 0)
                    goto cleanup;
            }
        } else {
            /*
             * If the Kerberos user principal to be deleted happens to be the last one associated
             * with the directory user object, then it is time to delete the other kerberos
             * specific attributes like krbmaxticketlife, i.e, unkerberize the directory user.
             * From the attrsetmask value, identify the attributes set on the directory user
             * object and delete them.
             * NOTE: krbsecretkey attribute has per principal entries. There can be chances that the
             * other principals' keys are exisiting/left-over. So delete all the values.
             */
            while (attrsetmask) {
                if (attrsetmask & 1) {
                    if ((st=krb5_add_str_mem_ldap_mod(&mods, attributes_set[j], LDAP_MOD_DELETE,
                                                      NULL)) != 0)
                        goto cleanup;
                }
                attrsetmask >>= 1;
                ++j;
            }

            /* the same should be done with the objectclass attributes */
            {
                char *attrvalues[] = {"krbticketpolicyaux", "krbprincipalaux", NULL};
/*              char *attrvalues[] = {"krbpwdpolicyrefaux", "krbticketpolicyaux", "krbprincipalaux", NULL};  */
                int p, q, r=0, amask=0;

                if ((st=checkattributevalue(ld, DN, "objectclass", attrvalues, &amask)) != 0)
                    goto cleanup;
                memset(strval, 0, sizeof(strval));
                for (p=1, q=0; p<=4; p<<=1, ++q)
                    if (p & amask)
                        strval[r++] = attrvalues[q];
                strval[r] = NULL;
                if (r > 0) {
                    if ((st=krb5_add_str_mem_ldap_mod(&mods, "objectclass", LDAP_MOD_DELETE,
                                                      strval)) != 0)
                        goto cleanup;
                }
            }
        }
        st=ldap_modify_ext_s(ld, DN, mods, NULL, NULL);
        if (st != LDAP_SUCCESS) {
            st = set_ldap_error(context, st, OP_MOD);
            goto cleanup;
        }
    }

cleanup:
    if (user)
        free (user);

    if (DN)
        free (DN);

    if (secretkey != NULL) {
        int i=0;
        while (i < secretkey->nkey) {
            free (secretkey->keys[i]->bv_val);
            free (secretkey->keys[i]);
            ++i;
        }
        free (secretkey->keys);
        free (secretkey);
    }

    krb5_ldap_free_principal(context, entry);

    ldap_mods_free(mods, 1);
    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    return st;
}


/*
 * Function: krb5_ldap_unparse_principal_name
 *
 * Purpose: Removes '\\' that comes before every occurence of '@'
 *          in the principal name component.
 *
 * Arguments:
 *       user_name     (input/output)      Principal name
 *
 */

krb5_error_code
krb5_ldap_unparse_principal_name(char *user_name)
{
    char *in, *out;

    out = user_name;
    for (in = user_name; *in; in++) {
        if (*in == '\\' && *(in + 1) == '@')
            continue;
        *out++ = *in;
    }
    *out = '\0';

    return 0;
}


/*
 * Function: krb5_ldap_parse_principal_name
 *
 * Purpose: Inserts '\\' before every occurence of '@'
 *          in the principal name component.
 *
 * Arguments:
 *       i_princ_name     (input)      Principal name without '\\'
 *       o_princ_name     (output)     Principal name with '\\'
 *
 * Note: The caller has to free the memory allocated for o_princ_name.
 */

krb5_error_code
krb5_ldap_parse_principal_name(char *i_princ_name, char **o_princ_name)
{
    const char *at_rlm_name, *p;
    struct k5buf buf;

    at_rlm_name = strrchr(i_princ_name, '@');
    if (!at_rlm_name) {
        *o_princ_name = strdup(i_princ_name);
        if (!o_princ_name)
            return ENOMEM;
    } else {
        krb5int_buf_init_dynamic(&buf);
        for (p = i_princ_name; p < at_rlm_name; p++) {
            if (*p == '@')
                krb5int_buf_add(&buf, "\\");
            krb5int_buf_add_len(&buf, p, 1);
        }
        krb5int_buf_add(&buf, at_rlm_name);
        *o_princ_name = krb5int_buf_data(&buf);
        if (!*o_princ_name)
            return ENOMEM;
    }
    return 0;
}

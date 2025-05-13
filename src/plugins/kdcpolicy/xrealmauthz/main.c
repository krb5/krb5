/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* include/krb5/kdcpolicy_plugin.h - KDC policy plugin interface */
/*
 * Copyright (C) 2017 by Red Hat, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <krb5/krb5.h>
#include <kdb.h>
#include <krb5/plugin.h>
#include <krb5/kdcpolicy_plugin.h>
#include <profile.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Prefix used for cross-realm authorization attributes */
#define ATTR_PREFIX "xr:"
#define MAX_DENIAL_MSG_LEN 256

struct realm_entry {
    const char *name;
    size_t length; /* store precomputed lengths for speed */
};

struct xrealmauthz_data {
    int enforcing;  /* Whether to actually enforce restrictions */
    struct realm_entry *allowed_realms;
    size_t num_allowed_realms;
};

/* Typedef for pointer to the structure */
typedef struct xrealmauthz_data *xrealmauthz_moddata;

static krb5_error_code
xrealmauthz_init(krb5_context context, krb5_kdcpolicy_moddata *data_out)
{
    krb5_error_code ret;
    int enforcing = 1;
    xrealmauthz_moddata moddata = NULL;
    profile_t profile = NULL;
    char **profile_realm_list = NULL;
    const char *section[] = {"kdcdefaults", "xrealmauthz_allowed_realms", NULL};
    *data_out = NULL;

    ret = krb5_get_profile(context, &profile);
    if (ret)
        goto cleanup;

    /* Check if enforcing mode is disabled in config, default to TRUE */
    profile_get_boolean(profile, "kdcdefaults", "xrealmauthz_enforcing",
                       NULL, TRUE, &enforcing);

    moddata = calloc(1, sizeof(struct xrealmauthz_data));
    if (moddata == NULL) {
        ret = ENOMEM;
        goto cleanup;
    }

    /* Get array of allowed realms from config */
    ret = profile_get_values(profile, section, &profile_realm_list);
    if (ret == PROF_NO_RELATION) {
        /* No allowed realms configured, this is OK */
        ret = 0;
    } else if (ret) {
        goto cleanup;
    }

    /* Count and allocate realm entries */
    if (profile_realm_list != NULL) {
        for (moddata->num_allowed_realms = 0;
             profile_realm_list[moddata->num_allowed_realms] != NULL;
             moddata->num_allowed_realms++);

        moddata->allowed_realms = calloc(moddata->num_allowed_realms,
                                       sizeof(struct realm_entry));
        if (moddata->allowed_realms == NULL) {
            ret = ENOMEM;
            goto cleanup;
        }

        /* Transfer ownership of the strings and precompute lengths */
        for (size_t i = 0; i < moddata->num_allowed_realms; i++) {
            moddata->allowed_realms[i].name = profile_realm_list[i];
            moddata->allowed_realms[i].length = strlen(profile_realm_list[i]);
        }
        free(profile_realm_list);
        profile_realm_list = NULL;
    }

    moddata->enforcing = enforcing;

    com_err("", 0, "xrealmauthz cross-realm authorization plugin loaded "
            "(enforcing mode: %s, pre-approved realms: %d)",
            enforcing ? "enabled" : "disabled",
            (int)moddata->num_allowed_realms);

cleanup:
    if (ret) {
        if (moddata) {
            /* If we allocated the realm_entry array, clean it up */
            if (moddata->allowed_realms) {
                /* Free any realm names we managed to copy */
                for (size_t i = 0; i < moddata->num_allowed_realms; i++)
                    free((char *)moddata->allowed_realms[i].name);
                free(moddata->allowed_realms);
            }
            free(moddata);
        }
        moddata = NULL;
    }
    /* If we've failed before taking ownership of the strings, free them properly */
    if (profile_realm_list)
        profile_free_list(profile_realm_list);
    if (profile)
        profile_release(profile);
    *data_out = (krb5_kdcpolicy_moddata)moddata;
    return ret;
}

static krb5_error_code
xrealmauthz_fini(krb5_context context, krb5_kdcpolicy_moddata data)
{
    xrealmauthz_moddata moddata = (xrealmauthz_moddata)data;

    if (moddata) {
        if (moddata->allowed_realms) {
            /* First free each realm name we took ownership of */
            for (size_t i = 0; i < moddata->num_allowed_realms; i++)
                free((char *)moddata->allowed_realms[i].name);
            /* Then free the array of realm_entry structures */
            free(moddata->allowed_realms);
        }
        free(moddata);
    }
    return 0;
}

/* Direct string comparison is safe here because allowed_realms
 * comes from trusted config file and client_realm is already
 * validated by Kerberos core */
static krb5_boolean
is_realm_preapproved(xrealmauthz_moddata data,
                     const krb5_data *client_realm)
{
    if (data == NULL || data->allowed_realms == NULL)
        return FALSE;

    for (size_t i = 0; i < data->num_allowed_realms; i++) {
        if (data->allowed_realms[i].length == client_realm->length &&
            strncmp(data->allowed_realms[i].name, client_realm->data,
                   client_realm->length) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

/* Helper to check if a specified string attribute exists on the cross-realm TGT */
static krb5_error_code
check_cross_realm_tgt_attribute(krb5_context context,
                              const char *attr_key,
                              krb5_db_entry *tgt_entry,
                              krb5_boolean *result_out)
{
    krb5_error_code ret;
    char *attr_value = NULL;

    *result_out = FALSE;

    ret = krb5_dbe_get_string(context, tgt_entry, attr_key, &attr_value);
    if (ret == 0 && attr_value != NULL) {
        *result_out = TRUE;
        krb5_dbe_free_string(context, attr_value);
    }

    return ret;
}

/* Check if cross-realm auth is allowed based on client realm or principal */
static krb5_error_code
check_cross_realm_auth(krb5_context context,
                      const krb5_ticket *ticket,
                      const krb5_kdc_req *request,
                      xrealmauthz_moddata data,
                      const char **status_out)
{
    krb5_error_code ret;
    char *client_realm_acl = NULL;
    char *client_princ_acl = NULL;
    char *client_princ_str = NULL;
    char *client_princ_no_realm = NULL;
    char *service_princ_str = NULL;
    krb5_boolean is_allowed = FALSE;
    krb5_db_entry *tgt_entry = NULL;
    static char denial_msg[MAX_DENIAL_MSG_LEN]; /* safe since the KDC is not multi-threaded */
    krb5_boolean enforcing = data ? data->enforcing : TRUE;

    *status_out = NULL;

    /* Check pre-approved realms first */
    if (is_realm_preapproved(data, &ticket->enc_part2->client->realm))
        return 0;

    /* Build ACL name for client realm */
    if (asprintf(&client_realm_acl, "%s@%.*s", ATTR_PREFIX,
                (int)ticket->enc_part2->client->realm.length,
                ticket->enc_part2->client->realm.data) < 0) {
        ret = ENOMEM;
        goto cleanup;
    }

    /* Get TGT principal entry once for both checks */
    ret = krb5_db_get_principal(context, ticket->server, 0, &tgt_entry);
    if (ret) {
        *status_out = "xrealmauthz plugin failed to retrieve cross-realm TGT from database";
        goto cleanup;
    }

    /* Check if client realm is allowed */
    ret = check_cross_realm_tgt_attribute(context, client_realm_acl,
                                        tgt_entry, &is_allowed);
    if (ret || is_allowed)
        goto cleanup;

    /* Build principal ACL string handling direct vs transitive trust */
    if (krb5_realm_compare(context, ticket->server, ticket->enc_part2->client)) {
        /* direct trust, get bare principal */
        ret = krb5_unparse_name_flags(context, ticket->enc_part2->client,
                                    KRB5_PRINCIPAL_UNPARSE_NO_REALM,
                                    &client_princ_no_realm);
        if (ret)
            goto cleanup;

        if (asprintf(&client_princ_acl, "%s%s",
                    ATTR_PREFIX, client_princ_no_realm) < 0) {
            ret = ENOMEM;
            goto cleanup;
        }
    } else {
        /* transitive trust, get fully qualified principal */
        ret = krb5_unparse_name(context, ticket->enc_part2->client,
                               &client_princ_str);
        if (ret)
            goto cleanup;

        if (asprintf(&client_princ_acl, "%s%s",
                    ATTR_PREFIX, client_princ_str) < 0) {
            ret = ENOMEM;
            goto cleanup;
        }
    }

    /* Check if client principal is allowed using already retrieved TGT entry */
    ret = check_cross_realm_tgt_attribute(context, client_princ_acl,
                                        tgt_entry, &is_allowed);
    if (ret)
        goto cleanup;

    if (!is_allowed) {
        /* Construct informative denial_msg for both enforcing cases  */
        if (!enforcing) {
            /* Get client principal if we don't already have it */
            if (client_princ_str == NULL) {
                ret = krb5_unparse_name(context, ticket->enc_part2->client,
                                      &client_princ_str);
                if (ret)
                    goto cleanup;
            }

            /* Get requested service principal */
            ret = krb5_unparse_name(context, request->server, &service_princ_str);
            if (ret)
                goto cleanup;

            snprintf(denial_msg, MAX_DENIAL_MSG_LEN,
                    "xrealmauthz plugin would deny "
                    "%s for %s from %.*s",
                    client_princ_str, service_princ_str,
                    (int)ticket->server->realm.length,
                    ticket->server->realm.data);
        } else {
            /* KDC logging will append client and service principal */
            snprintf(denial_msg, MAX_DENIAL_MSG_LEN,
                    "xrealmauthz plugin denied from %.*s",
                    (int)ticket->server->realm.length,
                    ticket->server->realm.data);
        }

        *status_out = denial_msg;

        if (!enforcing)
            com_err("", 0, "%s", denial_msg);

        /* If we're not enforcing, allow it but return success */
        ret = enforcing ? KRB5KDC_ERR_POLICY : 0;
    }

cleanup:
    krb5_db_free_principal(context, tgt_entry);
    free(client_realm_acl);
    free(client_princ_acl);
    krb5_free_unparsed_name(context, client_princ_str);
    krb5_free_unparsed_name(context, client_princ_no_realm);
    krb5_free_unparsed_name(context, service_princ_str);
    return ret;
}

static krb5_error_code
xrealmauthz_check(krb5_context context,
                 krb5_kdcpolicy_moddata moddata,
                 const krb5_kdc_req *request,
                 const struct _krb5_db_entry_new *server,
                 const krb5_ticket *ticket,
                 const char *const *auth_indicators,
                 const char **status_out,
                 krb5_deltat *lifetime_out,
                 krb5_deltat *renew_lifetime_out)
{
    xrealmauthz_moddata data = (xrealmauthz_moddata)moddata;

    /* Initialize output parameters */
    *status_out = NULL;
    if (lifetime_out != NULL)
        *lifetime_out = 0;
    if (renew_lifetime_out != NULL)
        *renew_lifetime_out = 0;

    /* Check if this is a cross-realm request by comparing realms */
    if (krb5_realm_compare(context, request->server, ticket->enc_part2->client)) {
        return 0;
    }

    return check_cross_realm_auth(context, ticket, request, data, status_out);
}

krb5_error_code
kdcpolicy_xrealmauthz_initvt(krb5_context context, int maj_ver, int min_ver,
                           krb5_plugin_vtable vtable);

krb5_error_code
kdcpolicy_xrealmauthz_initvt(krb5_context context, int maj_ver, int min_ver,
                           krb5_plugin_vtable vtable)
{
    krb5_kdcpolicy_vtable vt;

    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;

    vt = (krb5_kdcpolicy_vtable)vtable;
    vt->name = "xrealmauthz";
    vt->init = xrealmauthz_init;
    vt->fini = xrealmauthz_fini;
    vt->check_tgs = xrealmauthz_check;
    return 0;
}

/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/kdb/ldap/libkdb_ldap/ldap_krbcontainer.c */
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

#include "ldap_main.h"
#include "kdb_ldap.h"
#include "ldap_err.h"

char    *policyrefattribute[] = {"krbTicketPolicyReference",NULL};
char    *krbcontainerrefattr[] = {"krbContainerReference", NULL};

/*
 *  Free the krb5_ldap_krbcontainer_params
 */

void
krb5_ldap_free_krbcontainer_params(krb5_ldap_krbcontainer_params *cparams)
{
    if (cparams == NULL)
        return;

    if (cparams->policyreference)
        krb5_xfree(cparams->policyreference);

    if (cparams->parent)
        krb5_xfree(cparams->parent);

    if (cparams->DN)
        krb5_xfree(cparams->DN);

    krb5_xfree(cparams);

    return;
}

/*
 * Read the kerberos container. Kerberos container dn is read from the krb5.conf file.
 * In case of eDirectory, if the dn is not present in the conf file, refer Security Container
 * to fetch the dn information.
 *
 * Reading kerberos container includes reading the policyreference attribute and the policy
 * object to read the attributes associated with it.
 */

krb5_error_code
krb5_ldap_read_krbcontainer_params(krb5_context context,
                                   krb5_ldap_krbcontainer_params **cparamp)

{
    krb5_error_code                 st=0, tempst=0;
    LDAP                            *ld=NULL;
    LDAPMessage                     *result=NULL, *ent=NULL;
    krb5_ldap_krbcontainer_params   *cparams=NULL;
    kdb5_dal_handle                 *dal_handle=NULL;
    krb5_ldap_context               *ldap_context=NULL;
    krb5_ldap_server_handle         *ldap_server_handle=NULL;

    SETUP_CONTEXT();
    GET_HANDLE();

    cparams =(krb5_ldap_krbcontainer_params *) malloc(sizeof(krb5_ldap_krbcontainer_params));
    CHECK_NULL(cparams);
    memset(cparams, 0, sizeof(krb5_ldap_krbcontainer_params));

    /* read kerberos containter location from [dbmodules] section of krb5.conf file */
    if (ldap_context->conf_section) {
        if ((st=profile_get_string(context->profile, KDB_MODULE_SECTION, ldap_context->conf_section,
                                   KRB5_CONF_LDAP_KERBEROS_CONTAINER_DN, NULL,
                                   &cparams->DN)) != 0) {
            krb5_set_error_message(context, st,
                                   _("Error reading kerberos container "
                                     "location from krb5.conf"));
            goto cleanup;
        }
    }

    /* read kerberos containter location from [dbdefaults] section of krb5.conf file */
    if (cparams->DN == NULL) {
        if ((st=profile_get_string(context->profile, KDB_MODULE_DEF_SECTION,
                                   KRB5_CONF_LDAP_KERBEROS_CONTAINER_DN, NULL,
                                   NULL, &cparams->DN)) != 0) {
            krb5_set_error_message(context, st,
                                   _("Error reading kerberos container "
                                     "location from krb5.conf"));
            goto cleanup;
        }
    }

    if (cparams->DN == NULL) {
        st = KRB5_KDB_SERVER_INTERNAL_ERR;
        krb5_set_error_message(context, st,
                               _("Kerberos container location not specified"));
        goto cleanup;
    }

    /* NOTE: krbmaxtktlife, krbmaxrenewableage ... present on Kerberos Container is
     * not read
     */
    LDAP_SEARCH_1(cparams->DN, LDAP_SCOPE_BASE, "(objectclass=krbContainer)", policyrefattribute, IGNORE_STATUS);
    if (st != LDAP_SUCCESS && st != LDAP_NO_SUCH_OBJECT) {
        st = set_ldap_error(context, st, OP_SEARCH);
        goto cleanup;
    }

    if (st == LDAP_NO_SUCH_OBJECT) {
        st = KRB5_KDB_NOENTRY;
        goto cleanup;
    }

    if ((ent = ldap_first_entry(ld, result))) {
        if ((st=krb5_ldap_get_string(ld, ent, "krbticketpolicyreference",
                                     &(cparams->policyreference), NULL)) != 0)
            goto cleanup;
    }
    ldap_msgfree(result);

    if (cparams->policyreference != NULL) {
        LDAP_SEARCH_1(cparams->policyreference, LDAP_SCOPE_BASE, NULL, policy_attributes, IGNORE_STATUS);
        if (st != LDAP_SUCCESS && st!= LDAP_NO_SUCH_OBJECT) {
            st = set_ldap_error(context, st, OP_SEARCH);
            goto cleanup;
        }
        st = LDAP_SUCCESS; /* reset the return status in case it is LDAP_NO_SUCH_OBJECT */

        ent=ldap_first_entry(ld, result);
        if (ent != NULL) {
            krb5_ldap_get_value(ld, ent, "krbmaxtktlife", &(cparams->max_life));
            krb5_ldap_get_value(ld, ent, "krbmaxrenewableage", &(cparams->max_renewable_life));
            krb5_ldap_get_value(ld, ent, "krbticketflags", &(cparams->tktflags));
        }
        ldap_msgfree(result);
    }
    *cparamp=cparams;

cleanup:
    if (st != 0) {
        krb5_ldap_free_krbcontainer_params(cparams);
        *cparamp=NULL;
    }
    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    return st;
}

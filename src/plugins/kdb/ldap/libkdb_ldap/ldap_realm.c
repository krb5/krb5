/*
 * lib/kdb/kdb_ldap/ldap_realm.c
 *
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
#include "ldap_realm.h"
#include "ldap_principal.h"
#include "ldap_err.h"

#define END_OF_LIST -1
char  *realm_attributes[] = {"krbSearchScope","krbSubTree",
			     "krbMaxTicketLife", "krbMaxRenewableAge",
			     "krbTicketFlags", "krbDefaultEncType",
			     "krbDefaultSaltType", "krbUpEnabled",
			     "krbPolicyReference", "krbSupportedEncTypes",
			     "krbSupportedSaltTypes", "krbLdapServers",
			     "krbKdcServers",  "krbAdmServers",
			     "krbPwdServers", NULL};


char  *policy_attributes[] = { "krbMaxTicketLife",
			       "krbMaxRenewableAge",
			       "krbTicketFlags",
			       NULL };



char  *policyclass[] =     { "krbPolicy", NULL };
char  *kdcclass[] =        { "krbKdcService", NULL };
char  *adminclass[] =      { "krbAdmService", NULL };
char  *pwdclass[] =        { "krbPwdService", NULL };
char  *subtreeclass[] =    { "Organization", "OrganizationalUnit", "Domain",
			     "Country", "Locality", NULL };

int supportedenctypes[] = { ENCTYPE_DES_CBC_CRC, ENCTYPE_DES_CBC_MD4, ENCTYPE_DES_CBC_MD5,
			    ENCTYPE_DES3_CBC_SHA1, ENCTYPE_AES128_CTS_HMAC_SHA1_96,
			    ENCTYPE_AES256_CTS_HMAC_SHA1_96, ENCTYPE_ARCFOUR_HMAC, -1};

int supportedsalttypes[] = { KRB5_KDB_SALTTYPE_NORMAL, KRB5_KDB_SALTTYPE_V4,
			     KRB5_KDB_SALTTYPE_NOREALM, KRB5_KDB_SALTTYPE_ONLYREALM,
			     KRB5_KDB_SALTTYPE_SPECIAL, -1};


char  *krbContainerRefclass[] = { "krbContainerRefAux", NULL};


static void
ignore_duplicates(int_list)
    int         *int_list;
{
    int  i=0, j=0, scount=0;

    for (i=0; int_list[i] != END_OF_LIST; scount=i++)
	;

    for (i=0; i <= scount; ++i) {
	if (i > 0 && int_list[i] == int_list[i-1]) {
	    for (j=i; j<=scount; ++j)
		int_list[j-1] = int_list[j];
	    int_list[scount] = END_OF_LIST;
	    --scount;
	    --i;
	    continue;
	}
    }
}

/*
 * list realms from eDirectory
 */

/*
 * Function to remove all special characters from a string (rfc2254).
 * Use whenever exact matching is to be done ...
 */
static char *
ldap_filter_correct (unsigned char *in, unsigned int len)
{
    int i, count;
    char *out, *ptr;

    for (i = 0, count = 0; i < len; i++)
	switch (in[i]) {
	case '*':
	case '(':
	case ')':
	case '\\':
	case '\0':
	    count ++;
	}

    out = (char *)malloc((len + (count * 2) + 1) * sizeof (char));
    assert (out != NULL);
    memset(out, 0, len + (count * 2) + 1);

    for (i = 0, ptr = out; i < len; i++)
	switch (in[i]) {
	case '*':
	    ptr[0] = '\\';
	    ptr[1] = '2';
	    ptr[2] = 'a';
	    ptr += 3;
	    break;
	case '(':
	    ptr[0] = '\\';
	    ptr[1] = '2';
	    ptr[2] = '8';
	    ptr += 3;
	    break;
	case ')':
	    ptr[0] = '\\';
	    ptr[1] = '2';
	    ptr[2] = '9';
	    ptr += 3;
	    break;
	case '\\':
	    ptr[0] = '\\';
	    ptr[1] = '5';
	    ptr[2] = 'c';
	    ptr += 3;
	    break;
	case '\0':
	    ptr[0] = '\\';
	    ptr[1] = '0';
	    ptr[2] = '0';
	    ptr += 3;
	    break;
	default:
	    ptr[0] = in[i];
	    ptr += 1;
	    break;
	}

    /* ptr[count - 1] = '\0'; */

    return out;
}

static int principal_in_realm_2(krb5_principal principal, char *realm) {
    /* Cross realm trust ... */
    if (principal->length == 2 &&
	principal->data[0].length == sizeof ("krbtgt") &&
	strncasecmp (principal->data[0].data, "krbtgt", sizeof ("krbtgt")) &&
	principal->data[1].length == strlen (realm) &&
	strncasecmp (principal->data[1].data, realm, strlen (realm)))
	return 0;

    if (strlen(realm) != principal->realm.length)
	return 1;

    if (strncasecmp(realm, principal->realm.data, principal->realm.length) != 0)
	return 1;

    return 0;
}

/*
 * Lists the realms in the Directory.
 */

krb5_error_code
krb5_ldap_list_realm(context, realms)
    krb5_context	        context;
    char                        ***realms;
{
    char                        **values = NULL;
    unsigned int                i = 0, count = 0;
    krb5_error_code             st = 0, tempst = 0;
    LDAP                        *ld = NULL;
    LDAPMessage                 *result = NULL, *ent = NULL;
    kdb5_dal_handle             *dal_handle = NULL;
    krb5_ldap_context           *ldap_context = NULL;
    krb5_ldap_server_handle     *ldap_server_handle = NULL;

    SETUP_CONTEXT ();

    /* get the kerberos container DN information */
    if (ldap_context->krbcontainer == NULL) {
	if ((st = krb5_ldap_read_krbcontainer_params(context,
						     &(ldap_context->krbcontainer))) != 0)
	    goto cleanup;
    }

    /* get ldap handle */
    GET_HANDLE ();

    {
	char *cn[] = {"cn", NULL};
	LDAP_SEARCH(ldap_context->krbcontainer->DN,
		    LDAP_SCOPE_ONELEVEL,
		    "(objectclass=krbRealmContainer)",
		    cn);
    }

    *realms = NULL;

    count = ldap_count_entries (ld, result);
    if (count == -1) {
	ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &st);
	st = set_ldap_error (context, st, OP_SEARCH);
	goto cleanup;
    }

    *realms = calloc(count+1, sizeof (char *));
    CHECK_NULL(*realms);

    for (ent = ldap_first_entry(ld, result), count = 0; ent != NULL;
	 ent = ldap_next_entry(ld, ent)) {

	if ((values = ldap_get_values (ld, ent, "cn")) != NULL) {

	    (*realms)[count] = strdup(values[0]);
	    CHECK_NULL((*realms)[count]);
	    count += 1;

	    ldap_value_free(values);
	}
    } /* for (ent= ... */
    ldap_msgfree(result);

cleanup:

    /* some error, free up all the memory */
    if (st != 0) {
	if (*realms) {
	    for (i=0; (*realms)[i] != NULL; ++i) {
		free ((*realms)[i]);
	    }
	    free (*realms);
	    *realms = NULL;
	}
    }

    /* If there are no elements, still return a NULL terminated array */

    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    return st;
}


/*
 * Delete the realm along with the principals belonging to the realm in the Directory.
 */

krb5_error_code
krb5_ldap_delete_realm (context, lrealm)
    krb5_context                context;
    char                        *lrealm;
{
    LDAP                        *ld = NULL;
    krb5_error_code             st = 0, tempst=0;
    char                        **values=NULL, *subtrees[2]={NULL};;
    LDAPMessage                 *result_arr[3]={NULL}, *result = NULL, *ent = NULL;
    krb5_principal              principal;
    int                         l=0, ntree=0, i=0, j=0, mask=0;
    kdb5_dal_handle             *dal_handle = NULL;
    krb5_ldap_context           *ldap_context = NULL;
    krb5_ldap_server_handle     *ldap_server_handle = NULL;
    krb5_ldap_realm_params      *rparam=NULL;

    SETUP_CONTEXT ();

    if (lrealm == NULL) {
	st = EINVAL;
	krb5_set_error_message (context, st, "Realm information not available");
	goto cleanup;
    }

    if ((st=krb5_ldap_read_realm_params(context, lrealm, &rparam, &mask)) != 0)
	goto cleanup;

    /* get ldap handle */
    GET_HANDLE ();

    /* delete all the principals belonging to the realm in the tree */
    {
	char *attr[] = {"krbprincipalname", NULL}, *realm=NULL, filter[256];
	krb5_ldap_context lcontext;

	realm = ldap_filter_correct (lrealm, strlen (lrealm));
	assert (sizeof (filter) >= sizeof ("(krbprincipalname=)") +
		strlen (realm) + 2 /* "*@" */ + 1);

	sprintf (filter, "(krbprincipalname=*@%s)", realm);
	free (realm);

	/* LDAP_SEARCH(NULL, LDAP_SCOPE_SUBTREE, filter, attr); */
	memset(&lcontext, 0, sizeof(krb5_ldap_context));
	lcontext.lrparams = rparam;
	if ((st=krb5_get_subtree_info(&lcontext, subtrees, &ntree)) != 0)
	    goto cleanup;

	for (l=0; l < ntree; ++l) {
	    LDAP_SEARCH(subtrees[l], rparam->search_scope, filter, attr);
	    result_arr[l] = result;
	}
    }

    /* NOTE: Here all the principals should be cached and the ldap handle should be freed,
     * as a DAL-LDAP interface is called right down here. Caching might be constrained by
     * availability of the memory. The caching is not done, however there would be limit
     * on the minimum number of handles for a server and it is 2. As the DAL-LDAP is not
     * thread-safe this should suffice.
     */
    for (j=0; (result=result_arr[j]) != NULL; ++j) {
	for (ent = ldap_first_entry (ld, result); ent != NULL;
	     ent = ldap_next_entry (ld, ent)) {
	    if ((values = ldap_get_values(ld, ent, "krbPrincipalName")) != NULL) {
		for (i = 0; values[i] != NULL; ++i) {
		    krb5_parse_name(context, values[i], &principal);
		    if (principal_in_realm_2(principal, lrealm) == 0) {
			int nent = 0;
			if ((st=krb5_ldap_delete_principal(context, principal,
							   &nent)) != LDAP_SUCCESS)
			    goto cleanup;
		    }
		    krb5_free_principal(context, principal);
		}
		ldap_value_free(values);
	    }
	}
	ldap_msgfree(result);
    }

    /* Delete the realm object */
    if ((st=ldap_delete_ext_s(ld, ldap_context->lrparams->realmdn, NULL, NULL)) != LDAP_SUCCESS) {
	int ost = st;
	st = translate_ldap_error (st, OP_DEL);
	krb5_set_error_message (context, st, "Realm Delete FAILED: %s",
				ldap_err2string(ost));
    }

cleanup:
    for (l=0; l < ntree; ++l) {
	if (subtrees[l])
	    free (subtrees[l]);
    }
    krb5_ldap_free_realm_params(rparam);
    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    return st;
}

static int compare (const void *i, const void *j) {
    if (*(const krb5_int32 *)i > *(const krb5_int32 *)j)
	return 1;

    if (*(const krb5_int32 *)i < *(const krb5_int32 *)j)
	return -1;

    return 0;
}


/*
 * Modify the realm attributes in the Directory.
 */

krb5_error_code
krb5_ldap_modify_realm(context, rparams, mask)
    krb5_context             context;
    krb5_ldap_realm_params   *rparams;
    int                      mask;
{
    LDAP                  *ld=NULL;
    krb5_error_code       st=0;
    char                  *strval[5]={NULL};
#ifdef HAVE_EDIRECTORY
    char                  **values=NULL;
    char                  **oldkdcservers=NULL, **oldadminservers=NULL, **oldpasswdservers=NULL;
    LDAPMessage           *result=NULL, *ent=NULL;
    int                   count=0;
    char errbuf[1024];
#endif
    LDAPMod               **mods = NULL;
    int                   i=0, oldmask=0, objectmask=0;
    kdb5_dal_handle       *dal_handle=NULL;
    krb5_ldap_context     *ldap_context=NULL;
    krb5_ldap_server_handle *ldap_server_handle=NULL;

    if (mask == 0)
	return 0;

    if (rparams == NULL) {
	st = EINVAL;
	return st;
    }

    SETUP_CONTEXT ();

    /* Check validity of arguments */
    if (ldap_context->krbcontainer == NULL ||
	rparams->tl_data == NULL ||
	rparams->tl_data->tl_data_contents == NULL ||
	((mask & LDAP_REALM_SUBTREE) && rparams->subtree == NULL) ||
	/* This has to be fixed ... */
	((mask & LDAP_REALM_DEFENCTYPE) && rparams->suppenctypes == NULL) ||
	((mask & LDAP_REALM_DEFSALTTYPE) && rparams->suppsalttypes == NULL) ||
#ifdef HAVE_EDIRECTORY
	((mask & LDAP_REALM_KDCSERVERS) && rparams->kdcservers == NULL) ||
	((mask & LDAP_REALM_ADMINSERVERS) && rparams->adminservers == NULL) ||
	((mask & LDAP_REALM_PASSWDSERVERS) && rparams->passwdservers == NULL) ||
#endif
	0) {
	st = EINVAL;
	goto cleanup;
    }

    /* get ldap handle */
    GET_HANDLE ();

    /* get the oldmask obtained from the krb5_ldap_read_realm_params */
    {
	void *voidptr=NULL;

	if ((st=decode_tl_data(rparams->tl_data, KDB_TL_MASK, &voidptr)) == 0) {
	    oldmask = *((int *) voidptr);
	    free (voidptr);
	} else {
	    st = EINVAL;
	    krb5_set_error_message (context, st, "tl_data not available");
	    return st;
	}
    }

    /*
     * Sort the list of salt-types / enc-types ... just to eliminate duplicates
     * later.
     */
    {
	if ((mask & LDAP_REALM_SUPPENCTYPE) && rparams->suppenctypes) {
	    for (i = 0; rparams->suppenctypes [i] != END_OF_LIST; i++) {
	    }
	    qsort ((void *)rparams->suppenctypes, (unsigned) i, sizeof(krb5_int32), compare);
	}
	if ((mask & LDAP_REALM_SUPPSALTTYPE) && rparams->suppsalttypes) {
	    for (i = 0; rparams->suppenctypes [i] != END_OF_LIST; i++) {
	    }
	    qsort ((void *)rparams->suppsalttypes, (unsigned) i, sizeof(krb5_int32), compare);
	}
    }

    /* SUBTREE ATTRIBUTE */
    if (mask & LDAP_REALM_SUBTREE) {
	if (strlen(rparams->subtree) != 0) {
	    st = checkattributevalue(ld, rparams->subtree, "Objectclass", subtreeclass,
				     &objectmask);
	    CHECK_CLASS_VALIDITY(st, objectmask, "subtree value: ");
	}
	memset(strval, 0, sizeof(strval));
	strval[0] = rparams->subtree;
	if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbsubtree", LDAP_MOD_REPLACE,
					  strval)) != 0)
	    goto cleanup;
    }

    /* SEARCHSCOPE ATTRIBUTE */
    if (mask & LDAP_REALM_SEARCHSCOPE) {
	if ((st=krb5_add_int_mem_ldap_mod(&mods, "krbsearchscope", LDAP_MOD_REPLACE,
					  (rparams->search_scope == LDAP_SCOPE_ONELEVEL
					   || rparams->search_scope == LDAP_SCOPE_SUBTREE) ?
					  rparams->search_scope : LDAP_SCOPE_SUBTREE)) != 0)
	    goto cleanup;
    }

    if (mask & LDAP_REALM_MAXRENEWLIFE) {

	if ((st=krb5_add_int_mem_ldap_mod(&mods, "krbMaxRenewableAge", LDAP_MOD_REPLACE,
					  rparams->max_renewable_life)) != 0)
	    goto cleanup;
    }

    /* krbMaxTicketLife ATTRIBUTE */

    if (mask & LDAP_REALM_MAXTICKETLIFE) {

	if ((st=krb5_add_int_mem_ldap_mod(&mods, "krbMaxTicketLife", LDAP_MOD_REPLACE,
					  rparams->max_life)) != 0)
	    goto cleanup;
    }

    /* krbTicketFlags ATTRIBUTE */

    if (mask & LDAP_REALM_KRBTICKETFLAGS) {

	if ((st=krb5_add_int_mem_ldap_mod(&mods, "krbTicketFlags", LDAP_MOD_REPLACE,
					  rparams->tktflags)) != 0)
	    goto cleanup;
    }


    /* DEFENCTYPE ATTRIBUTE */
    if (mask & LDAP_REALM_DEFENCTYPE) {
	/* check if the entered enctype is valid */
	if (krb5_c_valid_enctype(rparams->defenctype)) {

	    /* check if the defenctype exists in the suppenctypes list */
	    for (i = 0; rparams->suppenctypes[i] != END_OF_LIST; ++i)
		if (rparams->defenctype == rparams->suppenctypes[i])
		    break;

	    /* touching the end of list means defenctype is missing */
	    if (rparams->suppenctypes[i] == END_OF_LIST) {
		st = EINVAL;
		krb5_set_error_message (context, st, "Default enctype not in the supported list");
		goto cleanup;
	    }

	    if ((st=krb5_add_int_mem_ldap_mod(&mods, "krbdefaultenctype", LDAP_MOD_REPLACE,
					      rparams->defenctype)) != 0)
		goto cleanup;
	} else {
	    st = EINVAL;
	    krb5_set_error_message (context, st, "Invalid default enctype");
	    goto cleanup;
	}
    }

    /* DEFSALTTYPE ATTRIBUTE */
    if (mask & LDAP_REALM_DEFSALTTYPE) {
	/* check if the entered salttype is valid */
	if (rparams->defsalttype>=0 && rparams->defsalttype<6) {

	    /* check if the defsalttype exists in the suppsalttypes list */
	    for (i = 0; rparams->suppsalttypes[i] != END_OF_LIST; ++i)
		if (rparams->defsalttype == rparams->suppsalttypes[i])
		    break;

	    /* touching the end of the list means defsalttype is missing */
	    if (rparams->suppsalttypes[i] == END_OF_LIST) {
		st = EINVAL;
		krb5_set_error_message (context, st, "Default salttype not in the supported list");
		goto cleanup;
	    }

	    if ((st=krb5_add_int_mem_ldap_mod(&mods, "krbdefaultsalttype",
					      LDAP_MOD_REPLACE, rparams->defsalttype)) != 0)
		goto cleanup;

	} else {
	    st = EINVAL;
	    krb5_set_error_message (context, st, "Invalid default salttype");
	    goto cleanup;
	}
    }

    /* SUPPSALTTYPE ATTRIBUTE */
    if (mask & LDAP_REALM_SUPPSALTTYPE) {
	krb5_boolean flag=FALSE;

	for (i = 0; rparams->suppsalttypes[i] != END_OF_LIST; ++i) {
	    /* check if the salttypes entered is valid */
	    if (!(rparams->suppsalttypes[i]>=0 && rparams->suppsalttypes[i]<6)) {
		st = EINVAL;
		krb5_set_error_message (context, st, "salttype %d not valid", rparams->suppsalttypes[i]);
		goto cleanup;
	    }

	    /* Ensure that the default salt type is supported */
	    if ((oldmask & LDAP_REALM_DEFSALTTYPE ||
		 mask & LDAP_REALM_DEFSALTTYPE) &&
		rparams->defsalttype == rparams->suppsalttypes[i])
		flag = TRUE;
	}

	if (flag == FALSE) { /* Default salt type is not supported */
	    st = EINVAL;
	    krb5_set_error_message (context, st, "Default salttype not in the supported list");
	    goto cleanup;
	}
	ignore_duplicates(rparams->suppsalttypes);

	if ((st=krb5_add_int_arr_mem_ldap_mod(&mods, "krbsupportedsalttypes",
					      LDAP_MOD_REPLACE, rparams->suppsalttypes)) != 0)
	    goto cleanup;
    }

    /* SUPPENCTYPE ATTRIBUTE */
    if (mask & LDAP_REALM_SUPPENCTYPE) {
	krb5_boolean flag=FALSE;

	for (i=0; rparams->suppenctypes[i] != END_OF_LIST; ++i) {

	    /* check if the enctypes entered is valid */
	    if (krb5_c_valid_enctype(rparams->suppenctypes[i]) == 0) {
		st = EINVAL;
		krb5_set_error_message (context, st, "Enctype %d not valid", rparams->suppenctypes[i]);
		goto cleanup;
	    }

	    /* Ensure that the default encryption type is supported */
	    if ((oldmask & LDAP_REALM_DEFENCTYPE ||
		 mask & LDAP_REALM_DEFENCTYPE) &&
		rparams->defenctype == rparams->suppenctypes[i])
		flag = TRUE;
	}

	if (flag == FALSE) { /* Default encryption type is not supported */
	    st = EINVAL;
	    krb5_set_error_message(context, st, "Default enctype not in the supported list");
	    goto cleanup;
	}
	ignore_duplicates(rparams->suppenctypes);

	if ((st=krb5_add_int_arr_mem_ldap_mod(&mods, "krbsupportedenctypes",
					      LDAP_MOD_REPLACE, rparams->suppenctypes)) != 0)
	    goto cleanup;
    }

#ifdef HAVE_EDIRECTORY

    /* KDCSERVERS ATTRIBUTE */
    if (mask & LDAP_REALM_KDCSERVERS) {
	/* validate the server list */
	for (i=0; rparams->kdcservers[i] != NULL; ++i) {
	    st = checkattributevalue(ld, rparams->kdcservers[i], "objectClass", kdcclass,
				     &objectmask);
	    CHECK_CLASS_VALIDITY(st, objectmask, "kdc service object value: ");
	}

	if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbkdcservers", LDAP_MOD_REPLACE,
					  rparams->kdcservers)) != 0)
	    goto cleanup;
    }

    /* ADMINSERVERS ATTRIBUTE */
    if (mask & LDAP_REALM_ADMINSERVERS) {
	/* validate the server list */
	for (i=0; rparams->adminservers[i] != NULL; ++i) {
	    st = checkattributevalue(ld, rparams->adminservers[i], "objectClass", adminclass,
				     &objectmask);
	    CHECK_CLASS_VALIDITY(st, objectmask, "admin service object value: ");
	}

	if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbadmservers", LDAP_MOD_REPLACE,
					  rparams->adminservers)) != 0)
	    goto cleanup;
    }

    /* PASSWDSERVERS ATTRIBUTE */
    if (mask & LDAP_REALM_PASSWDSERVERS) {
	/* validate the server list */
	for (i=0; rparams->passwdservers[i] != NULL; ++i) {
	    st = checkattributevalue(ld, rparams->passwdservers[i], "objectClass", pwdclass,
				     &objectmask);
	    CHECK_CLASS_VALIDITY(st, objectmask, "password service object value: ");
	}

	if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbpwdservers", LDAP_MOD_REPLACE,
					  rparams->passwdservers)) != 0)
	    goto cleanup;
    }

    /*
     * Read the old values of the krbkdcservers, krbadmservers and
     * krbpwdservers.  This information is later used to decided the
     * deletions/additions to the list.
     */
    if (mask & LDAP_REALM_KDCSERVERS || mask & LDAP_REALM_ADMINSERVERS ||
	mask & LDAP_REALM_PASSWDSERVERS) {
	char *servers[] = {"krbKdcServers", "krbAdmServers", "krbPwdServers", NULL};

	if ((st= ldap_search_ext_s(ld,
			       rparams->realmdn,
			       LDAP_SCOPE_BASE,
			       0,
			       servers,
			       0,
			       NULL,
			       NULL,
			       NULL,
			       0,
			       &result)) != LDAP_SUCCESS) {
	    st = set_ldap_error (context, st, OP_SEARCH);
	    goto cleanup;
	}

	ent = ldap_first_entry(ld, result);
	if (ent) {
	    if ((values=ldap_get_values(ld, ent, "krbKdcServers")) != NULL) {
		count = ldap_count_values(values);
		if ((st=copy_arrays(values, &oldkdcservers, count)) != 0)
		    goto cleanup;
		ldap_value_free(values);
	    }

	    if ((values=ldap_get_values(ld, ent, "krbAdmServers")) != NULL) {
		count = ldap_count_values(values);
		if ((st=copy_arrays(values, &oldadminservers, count)) != 0)
		    goto cleanup;
		ldap_value_free(values);
	    }

	    if ((values=ldap_get_values(ld, ent, "krbPwdServers")) != NULL) {
		count = ldap_count_values(values);
		if ((st=copy_arrays(values, &oldpasswdservers, count)) != 0)
		    goto cleanup;
		ldap_value_free(values);
	    }
	}
	ldap_msgfree(result);
    }
#endif

    /* Realm modify opearation */
    if ((st=ldap_modify_ext_s(ld, rparams->realmdn, mods, NULL, NULL)) != LDAP_SUCCESS) {
	st = set_ldap_error (context, st, OP_MOD);
	goto cleanup;
    }

#ifdef HAVE_EDIRECTORY
    /* krbRealmReferences attribute is updated here, depending on the additions/deletions
     * to the 4 servers' list.
     */
    if (mask & LDAP_REALM_KDCSERVERS) {
	char **newkdcservers=NULL;

	count = ldap_count_values(rparams->kdcservers);
	if ((st=copy_arrays(rparams->kdcservers, &newkdcservers, count)) != 0)
	    goto cleanup;

	/* find the deletions and additions to the server list */
	if (oldkdcservers && newkdcservers)
	    disjoint_members(oldkdcservers, newkdcservers);

	/* delete the krbRealmReferences attribute from the servers that are dis-associated. */
	if (oldkdcservers)
	    for (i=0; oldkdcservers[i]; ++i)
		if ((st=deleteAttribute(ld, oldkdcservers[i], "krbRealmReferences",
					rparams->realmdn)) != 0) {
		    sprintf (errbuf, "Error removing 'krbRealmReferences' from %s: ",
			     oldkdcservers[i]);
		    prepend_err_str (context, errbuf, st, st);
		    goto cleanup;
		}

	/* add the krbRealmReferences attribute from the servers that are associated. */
	if (newkdcservers)
	    for (i=0; newkdcservers[i]; ++i)
		if ((st=updateAttribute(ld, newkdcservers[i], "krbRealmReferences",
					rparams->realmdn)) != 0) {
		    sprintf (errbuf, "Error adding 'krbRealmReferences' to %s: ",
			     newkdcservers[i]);
		    prepend_err_str (context, errbuf, st, st);
		    goto cleanup;
		}

	if (newkdcservers)
	    ldap_value_free(newkdcservers);
    }

    if (mask & LDAP_REALM_ADMINSERVERS) {
	char **newadminservers=NULL;

	count = ldap_count_values(rparams->adminservers);
	if ((st=copy_arrays(rparams->adminservers, &newadminservers, count)) != 0)
	    goto cleanup;

	/* find the deletions and additions to the server list */
	if (oldadminservers && newadminservers)
	    disjoint_members(oldadminservers, newadminservers);

	/* delete the krbRealmReferences attribute from the servers that are dis-associated. */
	if (oldadminservers)
	    for (i=0; oldadminservers[i]; ++i)
		if ((st=deleteAttribute(ld, oldadminservers[i], "krbRealmReferences",
					rparams->realmdn)) != 0) {
		    sprintf(errbuf, "Error removing 'krbRealmReferences' from "
			    "%s: ", oldadminservers[i]);
		    prepend_err_str (context, errbuf, st, st);
		    goto cleanup;
		}

	/* add the krbRealmReferences attribute from the servers that are associated. */
	if (newadminservers)
	    for (i=0; newadminservers[i]; ++i)
		if ((st=updateAttribute(ld, newadminservers[i], "krbRealmReferences",
					rparams->realmdn)) != 0) {
		    sprintf(errbuf, "Error adding 'krbRealmReferences' to %s: ",
			    newadminservers[i]);
		    prepend_err_str (context, errbuf, st, st);
		    goto cleanup;
		}
	if (newadminservers)
	    ldap_value_free(newadminservers);
    }

    if (mask & LDAP_REALM_PASSWDSERVERS) {
	char **newpasswdservers=NULL;

	count = ldap_count_values(rparams->passwdservers);
	if ((st=copy_arrays(rparams->passwdservers, &newpasswdservers, count)) != 0)
	    goto cleanup;

	/* find the deletions and additions to the server list */
	if (oldpasswdservers && newpasswdservers)
	    disjoint_members(oldpasswdservers, newpasswdservers);

	/* delete the krbRealmReferences attribute from the servers that are dis-associated. */
	if (oldpasswdservers)
	    for (i=0; oldpasswdservers[i]; ++i)
		if ((st=deleteAttribute(ld, oldpasswdservers[i], "krbRealmReferences",
					rparams->realmdn)) != 0) {
		    sprintf(errbuf, "Error removing 'krbRealmReferences' from "
			    "%s: ", oldpasswdservers[i]);
		    prepend_err_str (context, errbuf, st, st);
		    goto cleanup;
		}

	/* add the krbRealmReferences attribute from the servers that are associated. */
	if (newpasswdservers)
	    for (i=0; newpasswdservers[i]; ++i)
		if ((st=updateAttribute(ld, newpasswdservers[i], "krbRealmReferences",
					rparams->realmdn)) != 0) {
		    sprintf(errbuf, "Error adding 'krbRealmReferences' to %s: ",
			    newpasswdservers[i]);
		    prepend_err_str (context, errbuf, st, st);
		    goto cleanup;
		}
	if (newpasswdservers)
	    ldap_value_free(newpasswdservers);
    }
#endif

cleanup:

#ifdef HAVE_EDIRECTORY
    if (oldkdcservers) {
	for (i=0; oldkdcservers[i]; ++i)
	    free(oldkdcservers[i]);
	free(oldkdcservers);
    }

    if (oldadminservers) {
	for (i=0; oldadminservers[i]; ++i)
	    free(oldadminservers[i]);
	free(oldadminservers);
    }

    if (oldpasswdservers) {
	for (i=0; oldpasswdservers[i]; ++i)
	    free(oldpasswdservers[i]);
	free(oldpasswdservers);
    }
#endif

    ldap_mods_free(mods, 1);
    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    return st;
}



/*
 * Create the Kerberos container in the Directory
 */

krb5_error_code
krb5_ldap_create_krbcontainer(context, krbcontparams)
    krb5_context                          context;
    const krb5_ldap_krbcontainer_params   *krbcontparams;
{
    LDAP                        *ld=NULL;
    char                        *strval[2]={NULL}, *kerberoscontdn=NULL, **rdns=NULL;
    int                         pmask=0;
    LDAPMod                     **mods = NULL;
    krb5_error_code             st=0;
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_context           *ldap_context=NULL;
    krb5_ldap_server_handle     *ldap_server_handle=NULL;
#ifdef HAVE_EDIRECTORY
    int                         crmask=0;
#endif

    SETUP_CONTEXT ();

    /* get ldap handle */
    GET_HANDLE ();

    if (krbcontparams != NULL && krbcontparams->DN != NULL) {
	kerberoscontdn = krbcontparams->DN;
    } else {
	/* If the user has not given, use the default cn=Kerberos,cn=Security */
#ifdef HAVE_EDIRECTORY
	kerberoscontdn = KERBEROS_CONTAINER;
#else
	st = EINVAL;
	krb5_set_error_message (context, st, "Kerberos Container information is missing");
	goto cleanup;
#endif
    }

    strval[0] = "krbContainer";
    strval[1] = NULL;
    if ((st=krb5_add_str_mem_ldap_mod(&mods, "objectclass", LDAP_MOD_ADD, strval)) != 0)
	goto cleanup;

    rdns = ldap_explode_dn(kerberoscontdn, 1);
    if (rdns == NULL) {
	st = EINVAL;
	krb5_set_error_message(context, st, "Invalid Kerberos container DN");
	goto cleanup;
    }

    strval[0] = rdns[0];
    strval[1] = NULL;
    if ((st=krb5_add_str_mem_ldap_mod(&mods, "cn", LDAP_MOD_ADD, strval)) != 0)
	goto cleanup;

    /* check if the policy reference value exists and is of krbpolicyreference object class */
    if (krbcontparams && krbcontparams->policyreference) {
	st = checkattributevalue(ld, krbcontparams->policyreference, "objectclass", policyclass,
				 &pmask);
	CHECK_CLASS_VALIDITY(st, pmask, "ticket policy object value: ");

	strval[0] = krbcontparams->policyreference;
	strval[1] = NULL;
	if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbpolicyreference", LDAP_MOD_ADD,
					  strval)) != 0)
	    goto cleanup;
    }

    /* create the kerberos container */
    if ((st = ldap_add_ext_s(ld, kerberoscontdn, mods, NULL, NULL)) != LDAP_SUCCESS) {
	int ost = st;
	st = translate_ldap_error (st, OP_ADD);
	krb5_set_error_message (context, st, "Kerberos Container create FAILED: %s", ldap_err2string(ost));
	goto cleanup;
    }

#ifdef HAVE_EDIRECTORY

    /* free the mods array */
    ldap_mods_free(mods, 1);
    mods=NULL;

    /* check whether the security container is bound to krbcontainerrefaux object class */
    if ((st=checkattributevalue(ld, SECURITY_CONTAINER, "objectClass",
				krbContainerRefclass, &crmask)) != 0) {
	prepend_err_str (context, "Security Container read FAILED: ", st, st);
	/* delete Kerberos Container, status ignored intentionally */
	ldap_delete_ext_s(ld, kerberoscontdn, NULL, NULL);
	goto cleanup;
    }

    if (crmask == 0) {
	/* Security Container is extended with krbcontainerrefaux object class */
	strval[0] = "krbContainerRefAux";
	if ((st=krb5_add_str_mem_ldap_mod(&mods, "objectclass", LDAP_MOD_ADD, strval)) != 0)
	    goto cleanup;
    }

    strval[0] = kerberoscontdn;
    strval[1] = NULL;
    if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbcontainerreference", LDAP_MOD_ADD, strval)) != 0)
	goto cleanup;

    /* update the security container with krbContainerReference attribute */
    if ((st=ldap_modify_ext_s(ld, SECURITY_CONTAINER, mods, NULL, NULL)) != LDAP_SUCCESS) {
	int ost = st;
	st = translate_ldap_error (st, OP_MOD);
	krb5_set_error_message (context, st, "Security Container update FAILED: %s", ldap_err2string(ost));
	/* delete Kerberos Container, status ignored intentionally */
	ldap_delete_ext_s(ld, kerberoscontdn, NULL, NULL);
	goto cleanup;
    }
#endif

cleanup:

    if (rdns)
	ldap_value_free (rdns);

    ldap_mods_free(mods, 1);
    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    return(st);
}


/*
 * Create Realm in eDirectory. This is used by kdb5_util
 */

krb5_error_code
krb5_ldap_create_realm(context, rparams, mask)
    krb5_context                context;
    krb5_ldap_realm_params      *rparams;
    int                         mask;
{
    LDAP                        *ld=NULL;
    krb5_error_code             st=0;
    char                        *dn=NULL;
    char                        *strval[4]={NULL};
    LDAPMod                     **mods = NULL;
    int                         i=0, objectmask=0;
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_context           *ldap_context=NULL;
    krb5_ldap_server_handle     *ldap_server_handle=NULL;
#ifdef HAVE_EDIRECTORY
    char errbuf[1024];
#endif
    char                        *realm_name;

    SETUP_CONTEXT ();

    /* Check input validity ... */
    if (ldap_context->krbcontainer == NULL ||
	ldap_context->krbcontainer->DN == NULL ||
	rparams == NULL ||
	rparams->realm_name == NULL ||
	((mask & LDAP_REALM_SUBTREE) && rparams->subtree  == NULL) ||
	((mask & LDAP_REALM_POLICYREFERENCE) && rparams->policyreference == NULL) ||
	((mask & LDAP_REALM_SUPPSALTTYPE) && rparams->suppsalttypes == NULL) ||
	((mask & LDAP_REALM_SUPPENCTYPE) && rparams->suppenctypes == NULL) ||
#ifdef HAVE_EDIRECTORY
	((mask & LDAP_REALM_KDCSERVERS) && rparams->kdcservers == NULL) ||
	((mask & LDAP_REALM_ADMINSERVERS) && rparams->adminservers == NULL) ||
	((mask & LDAP_REALM_PASSWDSERVERS) && rparams->passwdservers == NULL) ||
#endif
	0) {
	st = EINVAL;
	return st;
    }

    if (ldap_context->krbcontainer == NULL) {
	if ((st = krb5_ldap_read_krbcontainer_params(context,
						     &(ldap_context->krbcontainer))) != 0)
	    goto cleanup;
    }

    /* get ldap handle */
    GET_HANDLE ();

    realm_name = rparams->realm_name;

    dn = malloc(strlen("cn=") + strlen(realm_name) + strlen(ldap_context->krbcontainer->DN) + 2);
    CHECK_NULL(dn);
    sprintf(dn, "cn=%s,%s", realm_name, ldap_context->krbcontainer->DN);

    strval[0] = realm_name;
    strval[1] = NULL;
    if ((st=krb5_add_str_mem_ldap_mod(&mods, "cn", LDAP_MOD_ADD, strval)) != 0)
	goto cleanup;

    strval[0] = "top";
    strval[1] = "krbrealmcontainer";
    strval[2] = "krbpolicyaux";
    strval[3] = NULL;

    if ((st=krb5_add_str_mem_ldap_mod(&mods, "objectclass", LDAP_MOD_ADD, strval)) != 0)
	goto cleanup;

    /* SUBTREE ATTRIBUTE */
    if (mask & LDAP_REALM_SUBTREE) {
	if (strlen(rparams->subtree) != 0) {
	    st = checkattributevalue(ld, rparams->subtree, "Objectclass", subtreeclass,
				     &objectmask);
	    CHECK_CLASS_VALIDITY(st, objectmask, "realm object value: ");

	}
	strval[0] = rparams->subtree;
	strval[1] = NULL;
	if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbsubtree", LDAP_MOD_ADD,
					  strval)) != 0)
	    goto cleanup;
    }

    /* SEARCHSCOPE ATTRIBUTE */
    if (mask & LDAP_REALM_SEARCHSCOPE) {
	if ((st=krb5_add_int_mem_ldap_mod(&mods, "krbsearchscope", LDAP_MOD_ADD,
					  (rparams->search_scope == LDAP_SCOPE_ONELEVEL
					   || rparams->search_scope == LDAP_SCOPE_SUBTREE) ?
					  rparams->search_scope : LDAP_SCOPE_SUBTREE)) != 0)
	    goto cleanup;
    }
    if (mask & LDAP_REALM_MAXRENEWLIFE) {

	if ((st=krb5_add_int_mem_ldap_mod(&mods, "krbMaxRenewableAge", LDAP_MOD_ADD,
					  rparams->max_renewable_life)) != 0)
	    goto cleanup;
    }

    /* krbMaxTicketLife ATTRIBUTE */

    if (mask & LDAP_REALM_MAXTICKETLIFE) {

	if ((st=krb5_add_int_mem_ldap_mod(&mods, "krbMaxTicketLife", LDAP_MOD_ADD,
					  rparams->max_life)) != 0)
	    goto cleanup;
    }

    /* krbTicketFlags ATTRIBUTE */

    if (mask & LDAP_REALM_KRBTICKETFLAGS) {

	if ((st=krb5_add_int_mem_ldap_mod(&mods, "krbTicketFlags", LDAP_MOD_ADD,
					  rparams->tktflags)) != 0)
	    goto cleanup;
    }


    /* DEFAULTENCTYPE ATTRIBUTE */
    if (mask & LDAP_REALM_DEFENCTYPE) {
	/* check if the entered enctype is valid */
	if (krb5_c_valid_enctype(rparams->defenctype)) {

	    /* check if the defenctype exists in the suppenctypes list */
	    if (mask & LDAP_REALM_SUPPENCTYPE) {
		for (i=0; rparams->suppenctypes[i] != END_OF_LIST; ++i)
		    if (rparams->defenctype == rparams->suppenctypes[i])
			break;

		if (rparams->suppenctypes[i] == END_OF_LIST) {
		    st = EINVAL;
		    krb5_set_error_message (context, st, "Default enctype not in the "
					    "supported list");
		    goto cleanup;
		}
	    }
	    if ((st=krb5_add_int_mem_ldap_mod(&mods, "krbdefaultenctype", LDAP_MOD_ADD,
					      rparams->defenctype)) != 0)
		goto cleanup;
	} else {
	    st = EINVAL;
	    krb5_set_error_message (context, st, "Default enctype not valid");
	    goto cleanup;
	}
    }

    /* DEFAULTSALTTYPE ATTRIBUTE */
    if (mask & LDAP_REALM_DEFSALTTYPE) {
	/* check if the entered salttype is valid */
	if (rparams->defsalttype >=0 && rparams->defsalttype<6) {

	    /* check if the defsalttype exists in the suppsalttypes list */
	    if (mask & LDAP_REALM_SUPPSALTTYPE) {
		for (i=0; rparams->suppsalttypes[i] != END_OF_LIST; ++i)
		    if (rparams->defsalttype == rparams->suppsalttypes[i])
			break;

		if (rparams->suppsalttypes[i] == END_OF_LIST) {
		    st = EINVAL;
		    krb5_set_error_message (context, st,
					    "Default salttype not in the supported list");
		    goto cleanup;
		}
	    }

	    if ((st=krb5_add_int_mem_ldap_mod(&mods, "krbdefaultsalttype", LDAP_MOD_ADD,
					      rparams->defsalttype)) != 0)
		goto cleanup;
	} else {
	    st = EINVAL;
	    krb5_set_error_message (context, st, "Default salttype not valid");
	    goto cleanup;
	}
    }

    /* SUPPORTEDSALTTYPE ATTRIBUTE */
    if (mask & LDAP_REALM_SUPPSALTTYPE) {
	for (i=0; rparams->suppsalttypes[i] != END_OF_LIST; ++i) {
	    /* check if the salttypes entered is valid */
	    if (!(rparams->suppsalttypes[i]>=0 && rparams->suppsalttypes[i]<6)) {
		st = EINVAL;
		krb5_set_error_message (context, st, "Salttype %d not valid",
					rparams->suppsalttypes[i]);
		goto cleanup;
	    }
	}
	ignore_duplicates(rparams->suppsalttypes);

	if ((st=krb5_add_int_arr_mem_ldap_mod(&mods, "krbsupportedsalttypes", LDAP_MOD_ADD,
					      rparams->suppsalttypes)) != 0)
	    goto cleanup;
    } else {
	/* set all the salt types as the suppsalttypes */
	if ((st=krb5_add_int_arr_mem_ldap_mod(&mods, "krbsupportedsalttypes", LDAP_MOD_ADD,
					      supportedsalttypes)) != 0)
	    goto cleanup;
    }

    /* SUPPORTEDENCTYPE ATTRIBUTE */
    if (mask & LDAP_REALM_SUPPENCTYPE) {
	for (i=0; rparams->suppenctypes[i] != -1; ++i) {

	    /* check if the enctypes entered is valid */
	    if (krb5_c_valid_enctype(rparams->suppenctypes[i]) == 0) {
		st = EINVAL;
		krb5_set_error_message (context, st, "Enctype %d not valid",
					rparams->suppenctypes[i]);
		goto cleanup;
	    }
	}
	ignore_duplicates(rparams->suppenctypes);

	if ((st=krb5_add_int_arr_mem_ldap_mod(&mods, "krbsupportedenctypes", LDAP_MOD_ADD,
					      rparams->suppenctypes)) != 0)
	    goto cleanup;
    } else {
	/* set all the enc types as the suppenctypes */
	if ((st=krb5_add_int_arr_mem_ldap_mod(&mods, "krbsupportedenctypes", LDAP_MOD_ADD,
					      supportedenctypes)) != 0)
	    goto cleanup;
    }

#ifdef HAVE_EDIRECTORY

    /* KDCSERVERS ATTRIBUTE */
    if (mask & LDAP_REALM_KDCSERVERS) {
	/* validate the server list */
	for (i=0; rparams->kdcservers[i] != NULL; ++i) {
	    st = checkattributevalue(ld, rparams->kdcservers[i], "objectClass", kdcclass,
				     &objectmask);
	    CHECK_CLASS_VALIDITY(st, objectmask, "kdc service object value: ");

	}

	if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbkdcservers", LDAP_MOD_ADD,
					  rparams->kdcservers)) != 0)
	    goto cleanup;
    }

    /* ADMINSERVERS ATTRIBUTE */
    if (mask & LDAP_REALM_ADMINSERVERS) {
	/* validate the server list */
	for (i=0; rparams->adminservers[i] != NULL; ++i) {
	    st = checkattributevalue(ld, rparams->adminservers[i], "objectClass", adminclass,
				     &objectmask);
	    CHECK_CLASS_VALIDITY(st, objectmask, "admin service object value: ");

	}

	if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbadmservers", LDAP_MOD_ADD,
					  rparams->adminservers)) != 0)
	    goto cleanup;
    }

    /* PASSWDSERVERS ATTRIBUTE */
    if (mask & LDAP_REALM_PASSWDSERVERS) {
	/* validate the server list */
	for (i=0; rparams->passwdservers[i] != NULL; ++i) {
	    st = checkattributevalue(ld, rparams->passwdservers[i], "objectClass", pwdclass,
				     &objectmask);
	    CHECK_CLASS_VALIDITY(st, objectmask, "password service object value: ");

	}

	if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbpwdservers", LDAP_MOD_ADD,
					  rparams->passwdservers)) != 0)
	    goto cleanup;
    }
#endif

    /* realm creation operation */
    if ((st=ldap_add_ext_s(ld, dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
	st = set_ldap_error (context, st, OP_ADD);
	goto cleanup;
    }

#ifdef HAVE_EDIRECTORY
    if (mask & LDAP_REALM_KDCSERVERS)
	for (i=0; rparams->kdcservers[i]; ++i)
	    if ((st=updateAttribute(ld, rparams->kdcservers[i], "krbRealmReferences", dn)) != 0) {
		sprintf(errbuf, "Error adding 'krbRealmReferences' to %s: ",
			rparams->kdcservers[i]);
		prepend_err_str (context, errbuf, st, st);
		/* delete Realm, status ignored intentionally */
		ldap_delete_ext_s(ld, dn, NULL, NULL);
		goto cleanup;
	    }

    if (mask & LDAP_REALM_ADMINSERVERS)
	for (i=0; rparams->adminservers[i]; ++i)
	    if ((st=updateAttribute(ld, rparams->adminservers[i], "krbRealmReferences", dn)) != 0) {
		sprintf(errbuf, "Error adding 'krbRealmReferences' to %s: ",
			rparams->adminservers[i]);
		prepend_err_str (context, errbuf, st, st);
		/* delete Realm, status ignored intentionally */
		ldap_delete_ext_s(ld, dn, NULL, NULL);
		goto cleanup;
	    }

    if (mask & LDAP_REALM_PASSWDSERVERS)
	for (i=0; rparams->passwdservers[i]; ++i)
	    if ((st=updateAttribute(ld, rparams->passwdservers[i], "krbRealmReferences", dn)) != 0) {
		sprintf(errbuf, "Error adding 'krbRealmReferences' to %s: ",
			rparams->passwdservers[i]);
		prepend_err_str (context, errbuf, st, st);
		/* delete Realm, status ignored intentionally */
		ldap_delete_ext_s(ld, dn, NULL, NULL);
		goto cleanup;
	    }
#endif

cleanup:

    if (dn)
	free(dn);

    ldap_mods_free(mods, 1);
    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    return st;
}

/*
 * Read the realm container configuration from eDirectory for the specified realm.
 */

krb5_error_code
krb5_ldap_read_realm_params(context, lrealm, rlparamp, mask)
    krb5_context	context;
    char            *lrealm;
    krb5_ldap_realm_params **rlparamp;
    int             *mask;
{
    char                   **values=NULL, *krbcontDN=NULL /*, *curr=NULL */;
    unsigned int           i=0, /* masklen=4, */ count=0;
    krb5_error_code        st=0, tempst=0;
    LDAP                   *ld=NULL;
    LDAPMessage            *result=NULL,*ent=NULL;
    krb5_ldap_realm_params *rlparams=NULL;
    kdb5_dal_handle        *dal_handle=NULL;
    krb5_ldap_context      *ldap_context=NULL;
    krb5_ldap_server_handle *ldap_server_handle=NULL;

    SETUP_CONTEXT ();

    /* validate the input parameter */
    if (lrealm == NULL ||
	ldap_context->krbcontainer == NULL ||
	ldap_context->krbcontainer->DN == NULL) {
	st = EINVAL;
	goto cleanup;
    }

    /* read kerberos container, if not read already */
    if (ldap_context->krbcontainer == NULL) {
	if ((st = krb5_ldap_read_krbcontainer_params(context,
						     &(ldap_context->krbcontainer))) != 0)
	    goto cleanup;
    }
    /* get ldap handle */
    GET_HANDLE ();

    /* Initialize realm container structure */
    rlparams =(krb5_ldap_realm_params *) malloc(sizeof(krb5_ldap_realm_params));
    CHECK_NULL(rlparams);
    memset((char *) rlparams, 0, sizeof(krb5_ldap_realm_params));

    /* allocate tl_data structure to store MASK information */
    rlparams->tl_data = malloc (sizeof(krb5_tl_data));
    if (rlparams->tl_data == NULL) {
	st = ENOMEM;
	goto cleanup;
    }
    memset((char *) rlparams->tl_data, 0, sizeof(krb5_tl_data));
    rlparams->tl_data->tl_data_type = KDB_TL_USER_INFO;

    /* set the mask parameter to 0 */
    *mask = 0;

    /* set default values */
    rlparams->search_scope = LDAP_SCOPE_SUBTREE;

    krbcontDN = ldap_context->krbcontainer->DN;

    rlparams->realmdn = (char *) malloc(strlen("cn=") + strlen(lrealm) + strlen(krbcontDN) + 2);
    if (rlparams->realmdn == NULL) {
	st = ENOMEM;
	goto cleanup;
    }
    sprintf(rlparams->realmdn, "cn=%s,%s", lrealm, krbcontDN);

    /* populate the realm name in the structure */
    rlparams->realm_name = strdup(lrealm);
    CHECK_NULL(rlparams->realm_name);

    LDAP_SEARCH(rlparams->realmdn, LDAP_SCOPE_BASE, "(objectclass=krbRealmContainer)", realm_attributes);

    ent = ldap_first_entry (ld, result);
    if (ent == NULL) {
	ldap_get_option (ld, LDAP_OPT_ERROR_NUMBER, (void *) &st);
#if 0
	st = translate_ldap_error(st, OP_SEARCH);
#endif
	goto cleanup;
    }

    /* Read the attributes */
    {

	if ((values=ldap_get_values(ld, ent, "krbSubTree")) != NULL) {
	    rlparams->subtree = strdup(values[0]);
	    if (rlparams->subtree==NULL) {
		st = ENOMEM;
		goto cleanup;
	    }
	    *mask |= LDAP_REALM_SUBTREE;
	    ldap_value_free(values);
	}

	if ((values=ldap_get_values(ld, ent, "krbSearchScope")) != NULL) {
	    rlparams->search_scope=atoi(values[0]);
	    /* searchscope can be ONE-LEVEL or SUBTREE, else default to SUBTREE */
	    if (!(rlparams->search_scope==1 || rlparams->search_scope==2))
		rlparams->search_scope = LDAP_SCOPE_SUBTREE;
	    *mask |= LDAP_REALM_SEARCHSCOPE;
	    ldap_value_free(values);
	}

	if ((values=ldap_get_values(ld, ent, "krbMaxTicketLife")) != NULL) {
	    rlparams->max_life = atoi(values[0]);
	    *mask |= LDAP_REALM_MAXTICKETLIFE;
	    ldap_value_free(values);
	}

	if ((values=ldap_get_values(ld, ent, "krbMaxRenewableAge")) != NULL) {
	    rlparams->max_renewable_life = atoi(values[0]);
	    *mask |= LDAP_REALM_MAXRENEWLIFE;
	    ldap_value_free(values);
	}

	if ((values=ldap_get_values(ld, ent, "krbTicketFlags")) != NULL) {
	    rlparams->tktflags = atoi(values[0]);
	    *mask |= LDAP_REALM_KRBTICKETFLAGS;
	    ldap_value_free(values);
	}

	if ((values=ldap_get_values(ld, ent, "krbDefaultEncType")) != NULL) {
	    rlparams->defenctype = atoi(values[0]);
	    if (krb5_c_valid_enctype(rlparams->defenctype) == 0)
		rlparams->defenctype = ENCTYPE_DES3_CBC_SHA1;
	    *mask |= LDAP_REALM_DEFENCTYPE;
	    ldap_value_free(values);
	}

	if ((values=ldap_get_values(ld, ent, "krbDefaultSaltType")) != NULL) {
	    rlparams->defsalttype = atoi(values[0]);
	    if (!(rlparams->defsalttype>=0 && rlparams->defsalttype<6))
		rlparams->defsalttype = KRB5_KDB_SALTTYPE_NORMAL;
	    *mask |= LDAP_REALM_DEFSALTTYPE;
	    ldap_value_free(values);
	}
	if ((values=ldap_get_values(ld, ent, "krbSupportedEncTypes")) != NULL) {
	    count = ldap_count_values(values);
	    rlparams->suppenctypes = malloc (sizeof(krb5_int32) * (count + 1));
	    if (rlparams->suppenctypes == NULL) {
		st = ENOMEM;
		goto cleanup;
	    }
	    for (i=0; i<count; ++i)
		rlparams->suppenctypes[i] = atoi(values[i]);
	    rlparams->suppenctypes[count] = -1;
	    *mask |= LDAP_REALM_SUPPENCTYPE;
	    ldap_value_free(values);
	}

	if ((values=ldap_get_values(ld, ent, "krbSupportedSaltTypes")) != NULL) {
	    count = ldap_count_values(values);
	    rlparams->suppsalttypes =  malloc (sizeof(krb5_int32) * (count + 1));
	    if (rlparams->suppsalttypes == NULL) {
		st = ENOMEM;
		goto cleanup;
	    }
	    for (i=0; i<count; ++i)
		rlparams->suppsalttypes[i] = atoi(values[i]);
	    rlparams->suppsalttypes[count] = -1;
	    *mask |= LDAP_REALM_SUPPSALTTYPE;
	    ldap_value_free(values);
	}

#ifdef HAVE_EDIRECTORY

	if ((values=ldap_get_values(ld, ent, "krbKdcServers")) != NULL) {
	    count = ldap_count_values(values);
	    if ((st=copy_arrays(values, &(rlparams->kdcservers), (int) count)) != 0)
		goto cleanup;
	    *mask |= LDAP_REALM_KDCSERVERS;
	    ldap_value_free(values);
	}

	if ((values=ldap_get_values(ld, ent, "krbAdmServers")) != NULL) {
	    count = ldap_count_values(values);
	    if ((st=copy_arrays(values, &(rlparams->adminservers), (int) count)) != 0)
		goto cleanup;
	    *mask |= LDAP_REALM_ADMINSERVERS;
	    ldap_value_free(values);
	}

	if ((values=ldap_get_values(ld, ent, "krbPwdServers")) != NULL) {
	    count = ldap_count_values(values);
	    if ((st=copy_arrays(values, &(rlparams->passwdservers), (int) count)) != 0)
		goto cleanup;
	    *mask |= LDAP_REALM_PASSWDSERVERS;
	    ldap_value_free(values);
	}
#endif
    }
    ldap_msgfree(result);

    /*
     * If all of maxtktlife, maxrenewlife and ticketflags are not directly
     * available, use the policy dn from the policy reference attribute, if
     * available, to fetch the missing.
     */

    if ((!(*mask & LDAP_REALM_MAXTICKETLIFE && *mask & LDAP_REALM_MAXRENEWLIFE &&
	   *mask & LDAP_REALM_KRBTICKETFLAGS)) && rlparams->policyreference) {

	LDAP_SEARCH_1(rlparams->policyreference, LDAP_SCOPE_BASE, NULL, policy_attributes, IGNORE_STATUS);
	if (st != LDAP_SUCCESS && st != LDAP_NO_SUCH_OBJECT) {
	    int ost = st;
	    st = translate_ldap_error (st, OP_SEARCH);
	    krb5_set_error_message (context, st, "Policy object read failed: %s", ldap_err2string(ost));
	    goto cleanup;
	}
	ent = ldap_first_entry (ld, result);
	if (ent != NULL) {
	    if ((*mask & LDAP_REALM_MAXTICKETLIFE) == 0) {
		if ((values=ldap_get_values(ld, ent, "krbmaxticketlife")) != NULL) {
		    rlparams->max_life = atoi(values[0]);
		    *mask |= LDAP_REALM_MAXTICKETLIFE;
		    ldap_value_free(values);
		}
	    }

	    if ((*mask & LDAP_REALM_MAXRENEWLIFE) == 0) {
		if ((values=ldap_get_values(ld, ent, "krbmaxrenewableage")) != NULL) {
		    rlparams->max_renewable_life = atoi(values[0]);
		    *mask |= LDAP_REALM_MAXRENEWLIFE;
		    ldap_value_free(values);
		}
	    }

	    if ((*mask & LDAP_REALM_KRBTICKETFLAGS) == 0) {
		if ((values=ldap_get_values(ld, ent, "krbticketflags")) != NULL) {
		    rlparams->tktflags = atoi(values[0]);
		    *mask |= LDAP_REALM_KRBTICKETFLAGS;
		    ldap_value_free(values);
		}
	    }
	}
	ldap_msgfree(result);
    }

    rlparams->mask = *mask;
    *rlparamp = rlparams;
    st = store_tl_data(rlparams->tl_data, KDB_TL_MASK, mask);

cleanup:

    /* if there is an error, free allocated structures */
    if (st != 0) {
	krb5_ldap_free_realm_params(rlparams);
	*rlparamp=NULL;
    }
    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    return st;
}


/*
  Free the krb5_ldap_realm_params.
*/
void
krb5_ldap_free_realm_params(rparams)
    krb5_ldap_realm_params *rparams;
{
    int i=0;

    if (rparams) {
	if (rparams->realmdn)
	    free(rparams->realmdn);

	if (rparams->realm_name)
	    krb5_xfree(rparams->realm_name);

	if (rparams->subtree)
	    krb5_xfree(rparams->subtree);

	if (rparams->suppenctypes)
	    krb5_xfree(rparams->suppenctypes);

	if (rparams->suppsalttypes)
	    krb5_xfree(rparams->suppsalttypes);

	if (rparams->kdcservers) {
	    for (i=0; rparams->kdcservers[i]; ++i)
		krb5_xfree(rparams->kdcservers[i]);
	    krb5_xfree(rparams->kdcservers);
	}

	if (rparams->adminservers) {
	    for (i=0; rparams->adminservers[i]; ++i)
		krb5_xfree(rparams->adminservers[i]);
	    krb5_xfree(rparams->adminservers);
	}

	if (rparams->passwdservers) {
	    for (i=0; rparams->passwdservers[i]; ++i)
		krb5_xfree(rparams->passwdservers[i]);
	    krb5_xfree(rparams->passwdservers);
	}

	if (rparams->tl_data) {
	    if (rparams->tl_data->tl_data_contents)
		krb5_xfree(rparams->tl_data->tl_data_contents);
	    krb5_xfree(rparams->tl_data);
	}

	if (rparams->mkey.contents) {
	    memset(rparams->mkey.contents, 0, rparams->mkey.length);
	    krb5_xfree(rparams->mkey.contents);
	}

	krb5_xfree(rparams);
    }
    return;
}

/* DAL functions */

krb5_error_code
krb5_ldap_create_realm_1(krb5_context kcontext, char *conf_section, char **db_args)
{
    krb5_error_code status = KRB5_PLUGIN_OP_NOTSUPP;
    krb5_set_error_message(kcontext, status, "LDAP %s", error_message(status));
    return status;
}

krb5_error_code
krb5_ldap_delete_realm_1(krb5_context kcontext, char *conf_section, char **db_args)
{
    krb5_error_code status = KRB5_PLUGIN_OP_NOTSUPP;
    krb5_set_error_message(kcontext, status, "LDAP %s", error_message(status));
    return status;
}

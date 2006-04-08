/*
 * lib/kdb/kdb_ldap/ldap_pwd_policy.c
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
#include "kdb_ldap.h"
#include "ldap_pwd_policy.h"
#include "ldap_err.h"

static char *password_policy_attributes[] = { "krbmaxpwdlife", "krbminpwdlife", "krbpwdmindiffchars",
					      "krbpwdminlength", "krbpwdhistorylength", "krbpwdpolicyrefcount", 
					      NULL };

/*
 * Function to create password policy object. 
 */

krb5_error_code
krb5_ldap_create_password_policy (context, policy)
    krb5_context                context;
    osa_policy_ent_t            policy;
{
    krb5_error_code 	        st=0;
    LDAP  		        *ld=NULL;
    LDAPMod 		        **mods={NULL};
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_context           *ldap_context=NULL;
    krb5_ldap_server_handle     *ldap_server_handle=NULL;
    char                        **rdns=NULL, *strval[2]={NULL};

    /* Clear the global error string */
    krb5_clear_error_message(context);

    /* validate the input parameters */
    if (policy == NULL || policy->name == NULL) 
	return EINVAL;

    SETUP_CONTEXT();
    GET_HANDLE();

    /* get the first component of the dn to set the cn attribute */
    rdns = ldap_explode_dn(policy->name, 1);
    if (rdns == NULL) {
        st = EINVAL;
        krb5_set_error_message(context, st, "Invalid password policy DN syntax");
	goto cleanup;
    }
    
    strval[0] = rdns[0];
    if ((st=krb5_add_str_mem_ldap_mod(&mods, "cn", LDAP_MOD_ADD, strval)) != 0)
      goto cleanup;
    
    strval[0] = "krbPwdPolicy";
    if ((st=krb5_add_str_mem_ldap_mod(&mods, "objectclass", LDAP_MOD_ADD, strval)) != 0)
      goto cleanup;
    
    if (((st=krb5_add_int_mem_ldap_mod(&mods, "krbmaxpwdlife", LDAP_MOD_ADD, 
				       (signed) policy->pw_max_life)) != 0) 
	|| ((st=krb5_add_int_mem_ldap_mod(&mods, "krbminpwdlife", LDAP_MOD_ADD,
					  (signed) policy->pw_min_life)) != 0)
	|| ((st=krb5_add_int_mem_ldap_mod(&mods, "krbpwdmindiffchars", LDAP_MOD_ADD,
					  (signed) policy->pw_min_classes)) != 0)
	|| ((st=krb5_add_int_mem_ldap_mod(&mods, "krbpwdminlength", LDAP_MOD_ADD,
					  (signed) policy->pw_min_length)) != 0)
	|| ((st=krb5_add_int_mem_ldap_mod(&mods, "krbpwdhistorylength", LDAP_MOD_ADD,
					  (signed) policy->pw_history_num)) != 0)
	|| ((st=krb5_add_int_mem_ldap_mod(&mods, "krbpwdpolicyrefcount", LDAP_MOD_ADD,
					  (signed) policy->policy_refcnt)) != 0))
	goto cleanup;

    /* password policy object creation */
    if ((st=ldap_add_s(ld, policy->name, mods)) != LDAP_SUCCESS) {
        st = set_ldap_error (context, st, OP_ADD);
	goto cleanup;
    }
    
 cleanup:
    if (rdns)
	ldap_value_free(rdns);

    ldap_mods_free(mods, 1);
    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    return(st);
}

/*
 * Function to modify password policy object.
 */

krb5_error_code
krb5_ldap_put_password_policy (context, policy)
    krb5_context                context;
    osa_policy_ent_t            policy;
{
    krb5_error_code 	        st=0;
    LDAP  		        *ld=NULL;
    LDAPMod 		        **mods=NULL;
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_context           *ldap_context=NULL;
    krb5_ldap_server_handle     *ldap_server_handle=NULL;

    /* Clear the global error string */
    krb5_clear_error_message(context);

    /* validate the input parameters */
    if (policy == NULL || policy->name == NULL) 
	return EINVAL;

    SETUP_CONTEXT();
    GET_HANDLE();

    if (((st=krb5_add_int_mem_ldap_mod(&mods, "krbmaxpwdlife", LDAP_MOD_REPLACE,
				       (signed) policy->pw_max_life)) != 0)
	|| ((st=krb5_add_int_mem_ldap_mod(&mods, "krbminpwdlife", LDAP_MOD_REPLACE,
					  (signed) policy->pw_min_life)) != 0)
	|| ((st=krb5_add_int_mem_ldap_mod(&mods, "krbpwdmindiffchars", LDAP_MOD_REPLACE,
					  (signed) policy->pw_min_classes)) != 0)
	|| ((st=krb5_add_int_mem_ldap_mod(&mods, "krbpwdminlength", LDAP_MOD_REPLACE,
					  (signed) policy->pw_min_length)) != 0)
	|| ((st=krb5_add_int_mem_ldap_mod(&mods, "krbpwdhistorylength", LDAP_MOD_REPLACE,
					  (signed) policy->pw_history_num)) != 0)
	|| ((st=krb5_add_int_mem_ldap_mod(&mods, "krbpwdpolicyrefcount", LDAP_MOD_REPLACE,
					  (signed) policy->policy_refcnt)) != 0))
	goto cleanup;
    
    /* modify the password policy object. */
    if ((st=ldap_modify_s(ld, policy->name, mods)) != LDAP_SUCCESS) {
        st = set_ldap_error (context, st, OP_MOD);
	goto cleanup;
    }
    
 cleanup:
    ldap_mods_free(mods, 1);
    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);    
    return(st);
}

krb5_error_code 
krb5_ldap_get_password_policy (context, name, policy, cnt)
    krb5_context                context;
    char                        *name;
    osa_policy_ent_t            *policy;
    int                         *cnt;
{
    krb5_error_code             st=0, tempst=0;
    LDAP  		        *ld=NULL;
    LDAPMessage                 *result=NULL,*ent=NULL;  
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_context           *ldap_context=NULL;
    krb5_ldap_server_handle     *ldap_server_handle=NULL;

    /* Clear the global error string */
    krb5_clear_error_message(context);

    /* validate the input parameters */
    if(name == NULL)
	return EINVAL;
    
    SETUP_CONTEXT();
    GET_HANDLE();

    *cnt = 0;
    *(policy) = (osa_policy_ent_t) malloc(sizeof(osa_policy_ent_rec));
    if (*policy == NULL) {
	 st = ENOMEM;
	 goto cleanup;
    }
    memset(*policy, 0, sizeof(osa_policy_ent_rec));

    LDAP_SEARCH(name, LDAP_SCOPE_BASE, "(objectclass=krbPwdPolicy)", password_policy_attributes);
    *cnt = 1;
    (*policy)->name = name;
    (*policy)->version = 1;

    ent=ldap_first_entry(ld, result);
    if (ent != NULL) {
	krb5_ldap_get_value(ld, ent, "krbmaxpwdlife", &((*policy)->pw_max_life));
	krb5_ldap_get_value(ld, ent, "krbminpwdlife", &((*policy)->pw_min_life));
	krb5_ldap_get_value(ld, ent, "krbpwdmindiffchars", &((*policy)->pw_min_classes));
	krb5_ldap_get_value(ld, ent, "krbpwdminlength", &((*policy)->pw_min_length));
	krb5_ldap_get_value(ld, ent, "krbpwdhistorylength", &((*policy)->pw_history_num));
	krb5_ldap_get_value(ld, ent, "krbpwdpolicyrefcount", &((*policy)->policy_refcnt));
    }

cleanup:
    ldap_msgfree(result);
    if (st != 0) {
	if (*policy != NULL) {
	    free (*policy);
	    *policy = NULL;
	}
    }
    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    return st;
}

krb5_error_code
krb5_ldap_delete_password_policy (context, policy)
    krb5_context                context;
    char                        *policy;
{
    krb5_error_code             st=0;
    LDAP                        *ld=NULL;
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_context           *ldap_context=NULL;
    krb5_ldap_server_handle     *ldap_server_handle=NULL;

    /* Clear the global error string */
    krb5_clear_error_message(context);

    /* validate the input parameters */
    if(policy == NULL)
        return EINVAL;

    SETUP_CONTEXT();
    GET_HANDLE();

    if((st=ldap_delete_s(ld, policy)) != LDAP_SUCCESS) {
        st = set_ldap_error (context, st, OP_DEL);
        goto cleanup;
    }

cleanup:
    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    return st;
}

krb5_error_code
krb5_ldap_iterate_password_policy(context, match_expr, func, func_arg) 
    krb5_context                context;
    char                        *match_expr;
    void                        (*func) (krb5_pointer, osa_policy_ent_t );
    krb5_pointer                func_arg;
{
    osa_policy_ent_rec          *entry=NULL;
    char		        *attrs[] = { "cn", NULL };
    krb5_error_code             st=0, tempst=0;
    LDAP		        *ld=NULL;
    LDAPMessage	                *result=NULL, *ent=NULL;
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_context           *ldap_context=NULL;
    krb5_ldap_server_handle     *ldap_server_handle=NULL;
    char 		        *policy_dn=NULL;

    /* Clear the global error string */
    krb5_clear_error_message(context);

    SETUP_CONTEXT();
    GET_HANDLE();

    entry = (osa_policy_ent_t) malloc(sizeof(osa_policy_ent_rec));
    CHECK_NULL(entry);
    memset(entry, 0, sizeof(osa_policy_ent_rec));

    LDAP_SEARCH(NULL, LDAP_SCOPE_SUBTREE, "(objectclass=krbpwdpolicy)", attrs);
    for(ent=ldap_first_entry(ld, result); ent != NULL; ent=ldap_next_entry(ld, ent)) {
	if ((policy_dn=ldap_get_dn(ld, ent)) == NULL)
	    continue;
	entry->name = policy_dn;
	(*func)(func_arg, entry);
	ldap_memfree(policy_dn);
    }
    ldap_msgfree(result);
     
 cleanup:
    if (entry)
	free (entry);
    
    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    return st;
}

void 
krb5_ldap_free_password_policy (context, entry)
    krb5_context                context;
    osa_policy_ent_t            entry;
{
    if(entry)
        free(entry);
    return;
}

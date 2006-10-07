/*
 * lib/kdb/kdb_ldap/ldap_principal2.c
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

#include <time.h>
#include "ldap_main.h"
#include "kdb_ldap.h"
#include "ldap_principal.h"
#include "princ_xdr.h"
#include "ldap_tkt_policy.h"
#include "ldap_pwd_policy.h"
#include "ldap_err.h"
#include "princ_key_encode_decode.h"

extern char* principal_attributes[];
extern char* max_pwd_life_attr[];
#if !defined(LDAP_OPT_RESULT_CODE) && defined(LDAP_OPT_ERROR_NUMBER)
#define LDAP_OPT_RESULT_CODE LDAP_OPT_ERROR_NUMBER
#endif

static krb5_error_code
krb5_decode_krbsecretkey(krb5_context, krb5_db_entry *, struct berval **, krb5_tl_data *);

static krb5_error_code
krb5_read_tkt_policy (krb5_context, krb5_ldap_context *, krb5_db_entry *, char *);

static char *
getstringtime(krb5_timestamp);

static krb5_error_code berval2tl_data (struct berval *in, krb5_tl_data **out) {
    *out = (krb5_tl_data *) malloc (sizeof (krb5_tl_data));
    if (*out == NULL)
	return ENOMEM;

    (*out)->tl_data_length = in->bv_len - 2;
    (*out)->tl_data_contents =  (krb5_octet *) malloc
	((*out)->tl_data_length * sizeof (krb5_octet));
    if ((*out)->tl_data_contents == NULL) {
	free (*out);
	return ENOMEM;
    }

    UNSTORE16_INT (in->bv_val, (*out)->tl_data_type);
    memcpy ((*out)->tl_data_contents, in->bv_val + 2, (*out)->tl_data_length);

    return 0;
}

/*
 * look up a principal in the directory.
 */

krb5_error_code
krb5_ldap_get_principal(context, searchfor, entries, nentries, more)
    krb5_context context;
    krb5_const_principal searchfor;
    krb5_db_entry *entries;	/* filled in */
    int *nentries;		/* how much room/how many found */
    krb5_boolean *more;		/* are there more? */
{
    char                        *user=NULL, *DN=NULL, *filter=NULL, **subtree=NULL;
    unsigned int                tree=0, ntrees=1, mask=0, princlen=0;
    krb5_error_code	        tempst=0, st=0;
    char                        **values=NULL, *policydn=NULL, *pwdpolicydn=NULL;
    char                        *polname = NULL, *tktpolname = NULL;
    char                        **link_references=NULL;
    krb5_tl_data                userinfo_tl_data={0};
    struct berval               **bvalues=NULL;
    LDAP	                *ld=NULL;
    LDAPMessage	                *result=NULL, *ent=NULL;
    krb5_ldap_context           *ldap_context=NULL;
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_server_handle     *ldap_server_handle=NULL;
    krb5_principal              parsed_mod_name=NULL;
    krb5_boolean                attr_present=FALSE;

    /* Clear the global error string */
    krb5_clear_error_message(context);

    /* set initial values */
    *nentries = 0;
    *more = 0;
    memset(entries, 0, sizeof(*entries));

    if (searchfor == NULL)
	return EINVAL;

    dal_handle = (kdb5_dal_handle *) context->db_context;
    ldap_context = (krb5_ldap_context *) dal_handle->db_context;

    CHECK_LDAP_HANDLE(ldap_context);

    if (is_principal_in_realm(ldap_context, searchfor) != 0) {
	*more = 0;
	krb5_set_error_message (context, st, "Principal does not belong to realm");
	goto cleanup;
    }

    if ((st=krb5_unparse_name(context, searchfor, &user)) != 0)
	goto cleanup;

    if ((st=krb5_ldap_unparse_principal_name(user)) != 0)
	goto cleanup;

    princlen = strlen(FILTER) + strlen(user) + 2 + 1;      /* 2 for closing brackets */
    if ((filter=malloc(princlen)) == NULL) {
	st = ENOMEM;
	goto cleanup;
    }
    snprintf(filter, princlen, FILTER"%s))", user);

    if ((st = krb5_get_subtree_info(ldap_context, &subtree, &ntrees)) != 0)
	goto cleanup;

    GET_HANDLE();
    for (tree=0; tree<ntrees && *nentries==0; ++tree) {

	LDAP_SEARCH(subtree[tree], ldap_context->lrparams->search_scope, filter, principal_attributes);
	for (ent=ldap_first_entry(ld, result); ent != NULL && *nentries == 0; ent=ldap_next_entry(ld, ent)) {

	    /* get the associated directory user information */
	    if ((values=ldap_get_values(ld, ent, "krbprincipalname")) != NULL) {
		int i=0, pcount=0, kerberos_principal_object_type=0;

		/* a wild-card in a principal name can return a list of kerberos principals.
		 * Make sure that the correct principal is returned.
		 * NOTE: a principalname k* in ldap server will return all the principals starting with a k
		 */
		for (i=0; values[i] != NULL; ++i) {
		    if (strcasecmp(values[i], user) == 0) {
			*nentries = 1;
			pcount = ldap_count_values(values);
			break;
		    }
		}
		ldap_value_free(values);

		if (*nentries == 0) /* no matching principal found */
		    continue;

		if ((DN = ldap_get_dn(ld, ent)) == NULL) {
		    ldap_get_option (ld, LDAP_OPT_RESULT_CODE, &st);
		    st = set_ldap_error (context, st, 0);
		    goto cleanup;
		}

		if ((values=ldap_get_values(ld, ent, "objectclass")) != NULL) {
		    for (i=0; values[i] != NULL; ++i)
			if (strcasecmp(values[i], "krbprincipal") == 0) {
			    kerberos_principal_object_type = KDB_STANDALONE_PRINCIPAL_OBJECT;
			    if ((st=store_tl_data(&userinfo_tl_data, KDB_TL_PRINCTYPE, &kerberos_principal_object_type)) != 0)
				goto cleanup;
			    break;
			}
		    ldap_value_free(values);
		}

		/* add principalcount, DN and principaltype user information to tl_data */
		if (((st=store_tl_data(&userinfo_tl_data, KDB_TL_PRINCCOUNT, &pcount)) != 0) ||
		    ((st=store_tl_data(&userinfo_tl_data, KDB_TL_USERDN, DN)) != 0))
		    goto cleanup;
	    }

	    /* populate entries->princ with searchfor value */
	    if ((st=krb5_copy_principal(context, searchfor, &(entries->princ))) != 0)
		goto cleanup;

	    /* read all the kerberos attributes */

#ifdef  KRBCONF_KDC_MODIFIES_KDB
	    /* KRBLASTSUCCESSFULAUTH */
	    if ((st=krb5_ldap_get_time(ld, ent, "krbLastSuccessfulAuth", &(entries->last_success),&attr_present)) != 0)
		goto cleanup;
	    if (attr_present == TRUE)
		mask |= KDB_LAST_SUCCESS;

	    /* KRBLASTFAILEDAUTH */
	    if ((st=krb5_ldap_get_time(ld, ent, "krbLastFailedAuth", &(entries->last_failed),&attr_present)) != 0)
		goto cleanup;
	    if (attr_present == TRUE)
		mask |= KDB_LAST_FAILED;

	    /* KRBLOGINFAILEDCOUNT */
	    if (krb5_ldap_get_value(ld, ent, "krbLoginFailedCount", &(entries->fail_auth_count)) == 0)
		mask |= KDB_FAIL_AUTH_COUNT;
#endif

	    /* KRBMAXTICKETLIFE */
	    if (krb5_ldap_get_value(ld, ent, "krbmaxticketlife", &(entries->max_life)) == 0)
		mask |= KDB_MAX_LIFE_ATTR;

	    /* KRBMAXRENEWABLEAGE */
	    if (krb5_ldap_get_value(ld, ent, "krbmaxrenewableage", &(entries->max_renewable_life)) == 0)
		mask |= KDB_MAX_RLIFE_ATTR;

	    /* KRBTICKETFLAGS */
	    if (krb5_ldap_get_value(ld, ent, "krbticketflags", &(entries->attributes)) == 0)
		mask |= KDB_TKT_FLAGS_ATTR;

	    /* PRINCIPAL EXPIRATION TIME */
	    if ((st=krb5_ldap_get_time(ld, ent, "krbprincipalexpiration", &(entries->expiration),
				       &attr_present)) != 0)
		goto cleanup;
	    if (attr_present == TRUE)
		mask |= KDB_PRINC_EXPIRE_TIME_ATTR;

	    /* PASSWORD EXPIRATION TIME */
	    if ((st=krb5_ldap_get_time(ld, ent, "krbpasswordexpiration", &(entries->pw_expiration),
				       &attr_present)) != 0)
		goto cleanup;
	    if (attr_present == TRUE)
		mask |= KDB_PWD_EXPIRE_TIME_ATTR;

	    /* KRBPOLICYREFERENCE */

	    if ((st=krb5_ldap_get_string(ld, ent, "krbticketpolicyreference", &policydn, &attr_present)) != 0)
		goto cleanup;

	    if (attr_present == TRUE) {
		/* Ensure that the policy is inside the realm container */
		if ((st = krb5_ldap_policydn_to_name (context, policydn, &tktpolname)) != 0)
		    goto cleanup;
	    }

	    /* KRBPWDPOLICYREFERENCE */
	    if ((st=krb5_ldap_get_string(ld, ent, "krbpwdpolicyreference", &pwdpolicydn, &attr_present)) != 0)
		goto cleanup;
	    if (attr_present == TRUE) {
		krb5_tl_data  kadm_tl_data;

		mask |= KDB_PWD_POL_REF_ATTR;

		/* Ensure that the policy is inside the realm container */
		if ((st = krb5_ldap_policydn_to_name (context, pwdpolicydn, &polname)) != 0)
		    goto cleanup;

		if ((st = krb5_update_tl_kadm_data(polname, &kadm_tl_data)) != 0) {
		    goto cleanup;
		}
		krb5_dbe_update_tl_data(context, entries, &kadm_tl_data);
	    }

	    /* KRBSECRETKEY */
	    if ((bvalues=ldap_get_values_len(ld, ent, "krbprincipalkey")) != NULL) {
		mask |= KDB_SECRET_KEY;
		if ((st=krb5_decode_krbsecretkey(context, entries, bvalues, &userinfo_tl_data)) != 0)
		    goto cleanup;
	    }

	    /* LAST PASSWORD CHANGE */
	    {
		krb5_timestamp lstpwdchng=0;
		if ((st=krb5_ldap_get_time(ld, ent, "krbLastPwdChange",
					   &lstpwdchng, &attr_present)) != 0)
		    goto cleanup;
		if (attr_present == TRUE) {
		    if ((st=krb5_dbe_update_last_pwd_change(context, entries,
							    lstpwdchng)))
			goto cleanup;
		    mask |= KDB_LAST_PWD_CHANGE_ATTR;
		}
	    }

	    /* KRBOBJECTREFERENCES */
	    {
		int i=0;
		if ((st=krb5_ldap_get_strings(ld, ent, "krbobjectreferences", &link_references, &attr_present)) != 0)
		    goto cleanup;
		if (link_references != NULL) {
		    for (i=0; link_references[i] != NULL; ++i) {
			if ((st=store_tl_data(&userinfo_tl_data, KDB_TL_LINKDN, link_references[i])) != 0)
			    goto cleanup;
		    }
		}
	    }

	    /* Set tl_data */
	    {
		int i;
		struct berval **ber_tl_data = NULL;
		krb5_tl_data *ptr = NULL;

		if ((ber_tl_data = ldap_get_values_len (ld, ent, "krbExtraData")) != NULL) {
		    for (i = 0; ber_tl_data[i] != NULL; i++) {
			if ((st = berval2tl_data (ber_tl_data[i] , &ptr)) != 0)
			    break;
			if ((st = krb5_dbe_update_tl_data(context, entries, ptr)) != 0)
			    break;
		    }
		    ldap_value_free_len (ber_tl_data);
		    if (st != 0)
			goto cleanup;
		    mask |= KDB_EXTRA_DATA;
		}
	    }

	    /* update the mask of attributes present on the directory object to the tl_data */
	    if ((st=store_tl_data(&userinfo_tl_data, KDB_TL_MASK, &mask)) != 0)
		goto cleanup;
	    if ((st=krb5_dbe_update_tl_data(context, entries, &userinfo_tl_data)) != 0)
		goto cleanup;

#ifdef HAVE_EDIRECTORY
	    {
		krb5_timestamp              expiretime=0;
		char                        *is_login_disabled=NULL;

		/* LOGIN EXPIRATION TIME */
		if ((st=krb5_ldap_get_time(ld, ent, "loginexpirationtime", &expiretime,
					   &attr_present)) != 0)
		    goto cleanup;

		if (attr_present == TRUE) {
		    if ((mask & KDB_PRINC_EXPIRE_TIME_ATTR) == 1) {
			if (expiretime < entries->expiration)
			    entries->expiration = expiretime;
		    } else {
			entries->expiration = expiretime;
		    }
		}

		/* LOGIN DISABLED */
		if ((st=krb5_ldap_get_string(ld, ent, "logindisabled", &is_login_disabled, &attr_present)) != 0)
		    goto cleanup;
		if (attr_present == TRUE) {
		    if (strcasecmp(is_login_disabled,"TRUE")== 0)
			entries->attributes |= KRB5_KDB_DISALLOW_ALL_TIX;
		    free (is_login_disabled);
		}
	    }
#endif
	}
	ldap_msgfree(result);
	result = NULL;
    } /* for (tree=0 ... */

    /* once done, put back the ldap handle */
    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    ldap_server_handle = NULL;

    /* if principal not found */
    if (*nentries == 0)
	goto cleanup;

    if ((st=krb5_read_tkt_policy (context, ldap_context, entries, tktpolname)) !=0)
	goto cleanup;

    /* We already know that the policy is inside the realm container. */
    if (polname) {
	osa_policy_ent_t   pwdpol;
	int                cnt=0;
	krb5_timestamp     last_pw_changed;
	krb5_ui_4          pw_max_life;

	memset(&pwdpol, 0, sizeof(pwdpol));

	if ((st=krb5_ldap_get_password_policy(context, polname, &pwdpol, &cnt)) != 0)
	    goto cleanup;
	pw_max_life = pwdpol->pw_max_life;
	free (pwdpol);

	if (pw_max_life > 0) {
	    if ((st=krb5_dbe_lookup_last_pwd_change(context, entries, &last_pw_changed)) != 0)
		goto cleanup;

	    if ((mask & KDB_PWD_EXPIRE_TIME_ATTR) == 1) {
		if ((last_pw_changed + pw_max_life) < entries->pw_expiration)
		    entries->pw_expiration = last_pw_changed + pw_max_life;
	    } else
		entries->pw_expiration = last_pw_changed + pw_max_life;
	}
    }

cleanup:
    ldap_msgfree(result);

    if (*nentries == 0 || st != 0)
	krb5_dbe_free_contents(context, entries);

    if (filter)
	free (filter);

    if (DN)
	ldap_memfree (DN);

    if (subtree) {
	for (; ntrees; --ntrees)
	    if (subtree[ntrees-1])
		free (subtree[ntrees-1]);
	free (subtree);
    }

    if (userinfo_tl_data.tl_data_contents)
	free(userinfo_tl_data.tl_data_contents);

    if (ldap_server_handle)
	krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);

    if (user)
	free(user);

    if (parsed_mod_name)
	krb5_free_principal(context, parsed_mod_name);

    if (pwdpolicydn)
	free(pwdpolicydn);

    if (polname != NULL)
	free(polname);

    if (tktpolname != NULL)
	free (tktpolname);

    if (policydn)
	free(policydn);

    return st;
}

typedef enum{ ADD_PRINCIPAL, MODIFY_PRINCIPAL } OPERATION;
/*
 * ptype is creating confusions. Additionally the logic
 * surronding ptype is redundunt and can be achevied
 * with the help of dn and containerdn members.
 * so dropping the ptype member
 */

typedef struct _xargs_t {
    char           *dn;
    char           *linkdn;
    krb5_boolean   dn_from_kbd;
    char           *containerdn;
    char           *tktpolicydn;
}xargs_t;

static void
free_xargs(xargs)
    xargs_t xargs;
{
    if (xargs.dn)
	free (xargs.dn);
    if (xargs.linkdn)
	free(xargs.linkdn);
    if (xargs.containerdn)
	free (xargs.containerdn);
    if (xargs.tktpolicydn)
	free (xargs.tktpolicydn);
}

static krb5_error_code
process_db_args(context, db_args, xargs, optype)
    krb5_context   context;
    char           **db_args;
    xargs_t        *xargs;
    OPERATION      optype;
{
    int                   i=0;
    krb5_error_code       st=0;
    char                  errbuf[1024];
    char                  *arg=NULL, *arg_val=NULL;
    char                  **dptr=NULL;
    unsigned int          arg_val_len=0;

    if (db_args) {
	for (i=0; db_args[i]; ++i) {
	    arg = strtok_r(db_args[i], "=", &arg_val);
	    if (strcmp(arg, TKTPOLICY_ARG) == 0) {
		dptr = &xargs->tktpolicydn;
	    } else {
		if (strcmp(arg, USERDN_ARG) == 0) {
		    if (optype == MODIFY_PRINCIPAL) {
			st = EINVAL;
			snprintf(errbuf, sizeof(errbuf), "%s option not supported", arg);
			krb5_set_error_message(context, st, "%s", errbuf);
			goto cleanup;
		    }
		    dptr = &xargs->dn;
		} else if (strcmp(arg, CONTAINERDN_ARG) == 0) {
		    if (optype == MODIFY_PRINCIPAL) {
			st = EINVAL;
			snprintf(errbuf, sizeof(errbuf), "%s option not supported", arg);
			krb5_set_error_message(context, st, "%s", errbuf);
			goto cleanup;
		    }
		    dptr = &xargs->containerdn;
		} else if (strcmp(arg, LINKDN_ARG) == 0) {
		    dptr = &xargs->linkdn;
		} else {
		    st = EINVAL;
		    snprintf(errbuf, sizeof(errbuf), "unknown option: %s", arg);
		    krb5_set_error_message(context, st, "%s", errbuf);
		    goto cleanup;
		}

		xargs->dn_from_kbd = TRUE;
		if (xargs->dn != NULL || xargs->containerdn != NULL || xargs->linkdn != NULL) {
		    st = EINVAL;
		    snprintf(errbuf, sizeof(errbuf), "%s option not supported", arg);
		    krb5_set_error_message(context, st, "%s", errbuf);
		    goto cleanup;
		}
		if (arg_val == NULL || strlen(arg_val) == 0) {
		    st = EINVAL;
		    snprintf(errbuf, sizeof(errbuf), "%s option value missing", arg);
		    krb5_set_error_message(context, st, "%s", errbuf);
		    goto cleanup;
		}
	    }

	    if (arg_val == NULL) {
		st = EINVAL;
		snprintf(errbuf, sizeof(errbuf), "%s option value missing", arg);
		krb5_set_error_message(context, st, "%s", errbuf);
		goto cleanup;
	    }
	    arg_val_len = strlen(arg_val) + 1;

	    if (strcmp(arg, TKTPOLICY_ARG) == 0) {
		if ((st = krb5_ldap_name_to_policydn (context, arg_val, dptr)) != 0)
		    goto cleanup;
	    } else {
		*dptr = calloc (1, arg_val_len);
		if (*dptr == NULL) {
		    st = ENOMEM;
		    goto cleanup;
		}
		memcpy(*dptr, arg_val, arg_val_len);
	    }
	}
    }

cleanup:
    return st;
}

/* Decoding ASN.1 encoded key */
static struct berval **
krb5_encode_krbsecretkey(krb5_key_data *key_data, int n_key_data) {
    struct berval **ret = NULL;
    int currkvno;
    int num_versions = 1;
    int i, j, last;

    if (n_key_data <= 0)
	return NULL;

    /* Find the number of key versions */
    for (i = 0; i < n_key_data - 1; i++)
	if (key_data[i].key_data_kvno != key_data[i + 1].key_data_kvno)
	    num_versions++;

    ret = (struct berval **) malloc (num_versions * sizeof (struct berval *) + 1);
    for (i = 0, last = 0, j = 0, currkvno = key_data[0].key_data_kvno; i < n_key_data; i++) {
	krb5_data *code;
	if (i == n_key_data - 1 || key_data[i + 1].key_data_kvno != currkvno) {
	    asn1_encode_sequence_of_keys (key_data+last,
					  (krb5_int16) i - last + 1,
					  0, /* For now, mkvno == 0*/
					  &code);
	    ret[j] = malloc (sizeof (struct berval));
	    /*CHECK_NULL(ret[j]); */
	    ret[j]->bv_len = code->length;
	    ret[j]->bv_val = code->data;
	    j++;
	    last = i + 1;

	    currkvno = key_data[i].key_data_kvno;
	}
    }
    ret[num_versions] = NULL;

    return ret;
}

static krb5_error_code tl_data2berval (krb5_tl_data *in, struct berval **out) {
    *out = (struct berval *) malloc (sizeof (struct berval));
    if (*out == NULL)
	return ENOMEM;

    (*out)->bv_len = in->tl_data_length + 2;
    (*out)->bv_val =  (char *) malloc ((*out)->bv_len);
    if ((*out)->bv_val == NULL) {
	free (*out);
	return ENOMEM;
    }

    STORE16_INT((*out)->bv_val, in->tl_data_type);
    memcpy ((*out)->bv_val + 2, in->tl_data_contents, in->tl_data_length);

    return 0;
}

krb5_error_code
krb5_ldap_put_principal(context, entries, nentries, db_args)
    krb5_context               context;
    krb5_db_entry              *entries;
    register int               *nentries;         /* number of entry structs to update */
    char                       **db_args;
{
    int 		        i=0, l=0, plen=0, kerberos_principal_object_type=0;
    krb5_error_code 	        st=0, tempst=0;
    LDAP  		        *ld=NULL;
    LDAPMessage                 *result=NULL, *ent=NULL;
    char                        *user=NULL, *subtree=NULL, *principal_dn=NULL;
    char                        **values=NULL, *strval[10]={NULL}, errbuf[1024];
    struct berval	        **bersecretkey=NULL;
    LDAPMod 		        **mods=NULL;
    krb5_boolean                tktpolicy_set=FALSE, create_standalone_prinicipal=FALSE;
    krb5_boolean                krb_identity_exists=FALSE, establish_links=FALSE;
    char                        *standalone_principal_dn=NULL;
    krb5_tl_data                *tl_data=NULL;
    krb5_key_data               **keys=NULL;
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_context           *ldap_context=NULL;
    krb5_ldap_server_handle     *ldap_server_handle=NULL;
    osa_princ_ent_rec 	        princ_ent;
    xargs_t                     xargs={0};
    char                        *polname = NULL;
    OPERATION optype;

    /* Clear the global error string */
    krb5_clear_error_message(context);

    SETUP_CONTEXT();
    if (ldap_context->lrparams == NULL || ldap_context->krbcontainer == NULL)
	return EINVAL;

    /* get ldap handle */
    GET_HANDLE();

    for (i=0; i < *nentries; ++i, ++entries) {
	if (is_principal_in_realm(ldap_context, entries->princ) != 0) {
	    st = EINVAL;
	    krb5_set_error_message(context, st, "Principal does not belong to the default realm");
	    goto cleanup;
	}

	/* get the principal information to act on */
	if (entries->princ) {
	    if (((st=krb5_unparse_name(context,entries->princ, &user)) !=0) ||
		((st=krb5_ldap_unparse_principal_name(user)) != 0))
		goto cleanup;
	    plen = strlen(user);
	}

	/* Identity the type of operation, it can be
	 * add principal or modify principal.
	 * hack if the entries->mask has KRB_PRINCIPAL flag set
	 * then it is a add operation
	 */
	if (entries->mask & KDB_PRINCIPAL)
	    optype = ADD_PRINCIPAL;
	else
	    optype = MODIFY_PRINCIPAL;

	if (((st=krb5_get_princ_type(context, entries, &kerberos_principal_object_type)) != 0) ||
	    ((st=krb5_get_userdn(context, entries, &principal_dn)) != 0))
	    goto cleanup;

	if ((st=process_db_args(context, db_args, &xargs, optype)) != 0)
	    goto cleanup;

	/* time to generate the DN information with the help of
	 * containerdn, principalcontainerreference or
	 * realmcontainerdn information
	 */
	if (principal_dn ==NULL && xargs.dn == NULL) { /* creation of standalone principal */
	    /* get the subtree information */
	    if (entries->princ->length == 2 && entries->princ->data[0].length == strlen("krbtgt") &&
		strncmp(entries->princ->data[0].data, "krbtgt", entries->princ->data[0].length) == 0) {
		/* if the principal is a inter-realm principal, always created in the realm container */
		subtree = strdup(ldap_context->lrparams->realmdn);
	    } else if (xargs.containerdn) {
		if ((st=checkattributevalue(ld, xargs.containerdn, NULL, NULL, NULL)) != 0) {
		    if (st == KRB5_KDB_NOENTRY || st == KRB5_KDB_CONSTRAINT_VIOLATION) {
			int ost = st;
			st = EINVAL;
			sprintf(errbuf, "'%s' not found: ", xargs.containerdn);
			prepend_err_str(context, errbuf, st, ost);
		    }
		    goto cleanup;
		}
		subtree = strdup(xargs.containerdn);
	    } else if (ldap_context->lrparams->containerref && strlen(ldap_context->lrparams->containerref) != 0) {
		/*
		 * Here the subtree should be changed with
		 * principalcontainerreference attribute value
		 */
		subtree = strdup(ldap_context->lrparams->containerref);
	    } else {
		subtree = strdup(ldap_context->lrparams->realmdn);
	    }
	    CHECK_NULL(subtree);

	    standalone_principal_dn = malloc(strlen("krbprincipalname=") + strlen(user) + strlen(",") +
					     strlen(subtree) + 1);
	    CHECK_NULL(standalone_principal_dn);
	    sprintf(standalone_principal_dn, "krbprincipalname=%s,%s", user, subtree);
	    /*
	     * free subtree when you are done using the subtree
	     * set the boolean create_standalone_prinicipal to TRUE
	     */
	    create_standalone_prinicipal = TRUE;
	    free(subtree);
	    subtree = NULL;

	}

	/*
	 * If the DN information is presented by the user, time to
	 * validate the input to ensure that the DN falls under
	 * any of the subtrees
	 */
	if (xargs.dn_from_kbd == TRUE) {
	    /* make sure the DN falls in the subtree */
	    int              tre=0, dnlen=0, subtreelen=0, ntrees=0;
	    char             **subtreelist=NULL;
	    char             *dn=NULL;
	    krb5_boolean     outofsubtree=TRUE;

	    if (xargs.dn != NULL) {
		dn = xargs.dn;
	    } else if (xargs.linkdn != NULL) {
		dn = xargs.linkdn;
	    } else if (standalone_principal_dn != NULL) {
		/*
		 * Even though the standalone_principal_dn is constructed
		 * within this function, there is the containerdn input
		 * from the user that can become part of the it.
		 */
		dn = standalone_principal_dn;
	    }

	    /* get the current subtree list */
	    if ((st = krb5_get_subtree_info(ldap_context, &subtreelist, &ntrees)) != 0)
		goto cleanup;

	    for (tre=0; tre<ntrees; ++tre) {
		if (subtreelist[tre] == NULL || strlen(subtreelist[tre]) == 0) {
		    outofsubtree = FALSE;
		    break;
		} else {
		    dnlen = strlen (dn);
		    subtreelen = strlen(subtreelist[tre]);
		    if ((dnlen >= subtreelen) && (strcasecmp((dn + dnlen - subtreelen), subtreelist[tre]) == 0)) {
			outofsubtree = FALSE;
			break;
		    }
		}
	    }

	    for (tre=0; tre < ntrees; ++tre) {
		free(subtreelist[tre]);
	    }

	    if (outofsubtree == TRUE) {
		st = EINVAL;
		krb5_set_error_message(context, st, "DN is out of the realm subtree");
		goto cleanup;
	    }

	    /*
	     * dn value will be set either by dn, linkdn or the standalone_principal_dn
	     * In the first 2 cases, the dn should be existing and in the last case we
	     * are supposed to create the ldap object. so the below should not be
	     * executed for the last case.
	     */

	    if (standalone_principal_dn == NULL) {
		/*
		 * If the ldap object is missing, this results in an error.
		 */

		/*
		 * Search for krbprincipalname attribute here.
		 * This is to find if a kerberos identity is already present
		 * on the ldap object, in which case adding a kerberos identity
		 * on the ldap object should result in an error.
		 */
		char  *attributes[]={"krbticketpolicyreference", "krbprincipalname", NULL};

		LDAP_SEARCH_1(dn, LDAP_SCOPE_BASE, 0, attributes,IGNORE_STATUS);
		if (st == LDAP_SUCCESS) {
		    ent = ldap_first_entry(ld, result);
		    if (ent != NULL) {
			if ((values=ldap_get_values(ld, ent, "krbticketpolicyreference")) != NULL) {
			    tktpolicy_set = TRUE;
			    ldap_value_free(values);
			}

			if ((values=ldap_get_values(ld, ent, "krbprincipalname")) != NULL) {
			    krb_identity_exists = TRUE;
			    ldap_value_free(values);
			}
		    }
		    ldap_msgfree(result);
		} else {
		    st = set_ldap_error(context, st, OP_SEARCH);
		    goto cleanup;
		}
	    }
	}

	/*
	 * If xargs.dn is set then the request is to add a
	 * kerberos principal on a ldap object, but if
	 * there is one already on the ldap object this
	 * should result in an error.
	 */

	if (xargs.dn != NULL && krb_identity_exists == TRUE) {
	    st = EINVAL;
	    snprintf(errbuf, sizeof(errbuf), "ldap object is already kerberized");
	    krb5_set_error_message(context, st, "%s", errbuf);
	    goto cleanup;
	}

	if (xargs.linkdn != NULL) {
	    /*
	     * link information can be changed using modprinc.
	     * However, link information can be changed only on the
	     * standalone kerberos principal objects. A standalone
	     * kerberos principal object is of type krbprincipal
	     * structural objectclass.
	     *
	     * NOTE: kerberos principals on an ldap object can't be
	     * linked to other ldap objects.
	     */
	    if (optype == MODIFY_PRINCIPAL &&
		kerberos_principal_object_type != KDB_STANDALONE_PRINCIPAL_OBJECT) {
		st = EINVAL;
		snprintf(errbuf, sizeof(errbuf), "link information can't be set/updated as the kerberos principal belongs to an ldap object");
		krb5_set_error_message(context, st, "%s", errbuf);
		goto cleanup;
	    }
	    establish_links = TRUE;
	}

#ifdef  KRBCONF_KDC_MODIFIES_KDB
	if ((entries->last_success)!=0) {
	    memset(strval, 0, sizeof(strval));
	    if ((strval[0]=getstringtime(entries->last_success)) == NULL)
		goto cleanup;
	    if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbLastSuccessfulAuth", LDAP_MOD_REPLACE, strval)) != 0) {
		free (strval[0]);
		goto cleanup;
	    }
	    free (strval[0]);
	}

	if (entries->last_failed!=0) {
	    memset(strval, 0, sizeof(strval));
	    if ((strval[0]=getstringtime(entries->last_failed)) == NULL)
		goto cleanup;
	    if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbLastFailedAuth", LDAP_MOD_REPLACE, strval)) != 0) {
		free (strval[0]);
		goto cleanup;
	    }
	    free(strval[0]);
	}

	if (entries->fail_auth_count!=0) {
	    if ((st=krb5_add_int_mem_ldap_mod(&mods, "krbLoginFailedCount", LDAP_MOD_REPLACE, entries->fail_auth_count)) !=0)
		goto cleanup;
	}
#endif

	if (entries->mask & KDB_MAX_LIFE) {
	    if ((st=krb5_add_int_mem_ldap_mod(&mods, "krbmaxticketlife", LDAP_MOD_REPLACE, entries->max_life)) != 0)
		goto cleanup;
	}

	if (entries->mask & KDB_MAX_RLIFE) {
	    if ((st=krb5_add_int_mem_ldap_mod(&mods, "krbmaxrenewableage", LDAP_MOD_REPLACE,
					      entries->max_renewable_life)) != 0)
		goto cleanup;
	}

	if (entries->mask & KDB_ATTRIBUTES) {
	    if ((st=krb5_add_int_mem_ldap_mod(&mods, "krbticketflags", LDAP_MOD_REPLACE,
					      entries->attributes)) != 0)
		goto cleanup;
	}

	if (entries->mask & KDB_PRINCIPAL) {
	    memset(strval, 0, sizeof(strval));
	    strval[0] = user;
	    if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbprincipalname", LDAP_MOD_ADD, strval)) != 0)
		goto cleanup;
	}

	if (entries->mask & KDB_PRINC_EXPIRE_TIME) {
	    memset(strval, 0, sizeof(strval));
	    if ((strval[0]=getstringtime(entries->expiration)) == NULL)
		goto cleanup;
	    if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbprincipalexpiration", LDAP_MOD_REPLACE, strval)) != 0) {
		free (strval[0]);
		goto cleanup;
	    }
	    free (strval[0]);
	}

	if (entries->mask & KDB_PW_EXPIRATION) {
	    memset(strval, 0, sizeof(strval));
	    if ((strval[0]=getstringtime(entries->pw_expiration)) == NULL)
		goto cleanup;
	    if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbpasswordexpiration",
					      LDAP_MOD_REPLACE,
					      strval)) != 0) {
		free (strval[0]);
		goto cleanup;
	    }
	    free (strval[0]);
	}

	if (entries->mask & KDB_POLICY) {
	    for (tl_data=entries->tl_data; tl_data; tl_data=tl_data->tl_data_next) {
		if (tl_data->tl_data_type == KRB5_TL_KADM_DATA) {
		    memset(&princ_ent, 0, sizeof(princ_ent));
		    /* FIX ME: I guess the princ_ent should be freed after this call */
		    if ((st = krb5_lookup_tl_kadm_data(tl_data, &princ_ent)) != 0) {
			goto cleanup;
		    }
		}
	    }

	    if (princ_ent.aux_attributes & KDB_POLICY) {
		memset(strval, 0, sizeof(strval));
		if ((st = krb5_ldap_name_to_policydn (context, princ_ent.policy, &polname)) != 0)
		    goto cleanup;
		strval[0] = polname;
		if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbpwdpolicyreference", LDAP_MOD_REPLACE, strval)) != 0)
		    goto cleanup;
	    } else {
		st = EINVAL;
		krb5_set_error_message(context, st, "Password policy value null");
		goto cleanup;
	    }
	}

	if (entries->mask & KDB_POLICY_CLR) {
	    if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbpwdpolicyreference", LDAP_MOD_DELETE, NULL)) != 0)
		goto cleanup;
	}

	if (entries->mask & KDB_KEY_DATA || entries->mask & KDB_KVNO) {
	    bersecretkey = krb5_encode_krbsecretkey (entries->key_data,
						     entries->n_key_data);

	    if ((st=krb5_add_ber_mem_ldap_mod(&mods, "krbprincipalkey",
					      LDAP_MOD_REPLACE | LDAP_MOD_BVALUES, bersecretkey)) != 0)
		goto cleanup;

	    if (!(entries->mask & KDB_PRINCIPAL)) {
		memset(strval, 0, sizeof(strval));
		if ((strval[0]=getstringtime(entries->pw_expiration)) == NULL)
		    goto cleanup;
		if ((st=krb5_add_str_mem_ldap_mod(&mods,
						  "krbpasswordexpiration",
						  LDAP_MOD_REPLACE, strval)) != 0) {
		    free (strval[0]);
		    goto cleanup;
		}
		free (strval[0]);
	    }

	    /* Update last password change whenever a new key is set */
	    {
		krb5_timestamp last_pw_changed;
		if ((st=krb5_dbe_lookup_last_pwd_change(context, entries,
							&last_pw_changed)) != 0)
		    goto cleanup;

		memset(strval, 0, sizeof(strval));
		if ((strval[0] = getstringtime(last_pw_changed)) == NULL)
		    goto cleanup;

		if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbLastPwdChange",
						  LDAP_MOD_REPLACE, strval)) != 0) {
		    free (strval[0]);
		    goto cleanup;
		}
		free (strval[0]);
	    }

	} /* Modify Key data ends here */

	/* Set tl_data */
	if (entries->tl_data != NULL) {
	    int count = 0;
	    struct berval **ber_tl_data = NULL;
	    krb5_tl_data *ptr;
	    for (ptr = entries->tl_data; ptr != NULL; ptr = ptr->tl_data_next) {
		if (ptr->tl_data_type == KRB5_TL_LAST_PWD_CHANGE
#ifdef SECURID
		    || ptr->tl_data_type == KRB5_TL_DB_ARGS
#endif
		    || ptr->tl_data_type == KRB5_TL_KADM_DATA
		    || ptr->tl_data_type == KDB_TL_USER_INFO)
		    continue;
		count++;
	    }
	    if (count != 0) {
		int j;
		ber_tl_data = (struct berval **) calloc (count, sizeof (struct
									berval*));
		for (j = 0, ptr = entries->tl_data; ptr != NULL; ptr = ptr->tl_data_next) {
		    /* Ignore tl_data that are stored in separate directory
		     * attributes */
		    if (ptr->tl_data_type == KRB5_TL_LAST_PWD_CHANGE
#ifdef SECURID
			|| ptr->tl_data_type == KRB5_TL_DB_ARGS
#endif
			|| ptr->tl_data_type == KRB5_TL_KADM_DATA
			|| ptr->tl_data_type == KDB_TL_USER_INFO)
			continue;
		    if ((st = tl_data2berval (ptr, &ber_tl_data[j])) != 0)
			break;
		    j++;
		}
		if (st != 0) {
		    for (j = 0; ber_tl_data[j] != NULL; j++) {
			free (ber_tl_data[j]->bv_val);
			free (ber_tl_data[j]);
		    }
		    free (ber_tl_data);
		    goto cleanup;
		}
		if ((st=krb5_add_ber_mem_ldap_mod(&mods, "krbExtraData",
						  LDAP_MOD_REPLACE | LDAP_MOD_BVALUES,
						  ber_tl_data)) != 0)
		    goto cleanup;
	    }
	}

	/* Directory specific attribute */
	if (xargs.tktpolicydn != NULL) {
	    int tmask=0;

	    if (strlen(xargs.tktpolicydn) != 0) {
		st = checkattributevalue(ld, xargs.tktpolicydn, "objectclass", policyclass, &tmask);
		CHECK_CLASS_VALIDITY(st, tmask, "ticket policy object value: ");

		strval[0] = xargs.tktpolicydn;
		strval[1] = NULL;
		if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbticketpolicyreference", LDAP_MOD_REPLACE, strval)) != 0)
		    goto cleanup;

	    } else {
		/* if xargs.tktpolicydn is a empty string, then delete
		 * already existing krbticketpolicyreference attr */
		if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbticketpolicyreference", LDAP_MOD_DELETE, NULL)) != 0)
		    goto cleanup;
	    }

	}


	if (establish_links == TRUE) {
	    memset(strval, 0, sizeof(strval));
	    strval[0] = xargs.linkdn;
	    if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbObjectReferences", LDAP_MOD_REPLACE, strval)) != 0)
		goto cleanup;
	}

	/*
	 * in case mods is NULL then return
	 * not sure but can happen in a modprinc
	 * so no need to return an error
	 * addprinc will atleast have the principal name
	 * and the keys passed in
	 */
	if (mods == NULL)
	    goto cleanup;

	if (create_standalone_prinicipal == TRUE) {
	    memset(strval, 0, sizeof(strval));
	    strval[0] = "krbprincipal";
	    strval[1] = "krbprincipalaux";
	    strval[2] = "krbTicketPolicyAux";

	    if ((st=krb5_add_str_mem_ldap_mod(&mods, "objectclass", LDAP_MOD_ADD, strval)) != 0)
		goto cleanup;

	    st=ldap_add_ext_s(ld, standalone_principal_dn, mods, NULL, NULL);
	    if (st != LDAP_SUCCESS) {
		sprintf(errbuf, "Principal add failed: %s", ldap_err2string(st));
		st = translate_ldap_error (st, OP_ADD);
		krb5_set_error_message(context, st, "%s", errbuf);
		goto cleanup;
	    }
	} else {
	    /*
	     * Here existing ldap object is modified and can be related
	     * to any attribute, so always ensure that the ldap
	     * object is extended with all the kerberos related
	     * objectclasses so that there are no constraint
	     * violations.
	     */
	    {
		char *attrvalues[] = {"krbprincipalaux", "krbTicketPolicyAux", NULL};
		int p, q, r=0, amask=0;

		if ((st=checkattributevalue(ld, (xargs.dn) ? xargs.dn : principal_dn,
					    "objectclass", attrvalues, &amask)) != 0) {
		    st = KRB5_KDB_UK_RERROR;
		    goto cleanup;
		}
		memset(strval, 0, sizeof(strval));
		for (p=1, q=0; p<=2; p<<=1, ++q) {
		    if ((p & amask) == 0)
			strval[r++] = attrvalues[q];
		}
		if (r != 0) {
		    if ((st=krb5_add_str_mem_ldap_mod(&mods, "objectclass", LDAP_MOD_ADD, strval)) != 0)
			goto cleanup;
		}
	    }
	    if (xargs.dn != NULL)
		st=ldap_modify_ext_s(ld, xargs.dn, mods, NULL, NULL);
	    else
		st=ldap_modify_ext_s(ld, principal_dn, mods, NULL, NULL);
	    if (st != LDAP_SUCCESS) {
		sprintf(errbuf, "User modification failed: %s", ldap_err2string(st));
		st = translate_ldap_error (st, OP_MOD);
		krb5_set_error_message(context, st, "%s", errbuf);
		goto cleanup;
	    }
	}

    }

cleanup:
    if (user)
	free(user);

    free_xargs(xargs);

    if (standalone_principal_dn)
	free(standalone_principal_dn);

    if (principal_dn)
	free (principal_dn);

    if (polname != NULL)
	free(polname);

    if (subtree)
	free (subtree);

    if (bersecretkey) {
	for (l=0; bersecretkey[l]; ++l) {
	    if (bersecretkey[l]->bv_val)
		free (bersecretkey[l]->bv_val);
	    free (bersecretkey[l]);
	}
	free (bersecretkey);
    }

    if (keys)
	free (keys);

    ldap_mods_free(mods, 1);
    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    *nentries = i;
    return(st);
}

static krb5_error_code
krb5_read_tkt_policy (context, ldap_context, entries, policy)
    krb5_context                context;
    krb5_ldap_context           *ldap_context;
    krb5_db_entry               *entries;
    char                        *policy;
{
    krb5_error_code             st=0;
    unsigned int                mask=0, omask=0;
    int                         tkt_mask=(KDB_MAX_LIFE_ATTR | KDB_MAX_RLIFE_ATTR | KDB_TKT_FLAGS_ATTR);
    krb5_ldap_policy_params     *tktpoldnparam=NULL;

    if ((st=krb5_get_attributes_mask(context, entries, &mask)) != 0)
	goto cleanup;

    if ((mask & tkt_mask) == tkt_mask)
	goto cleanup;

    if (policy != NULL) {
	st = krb5_ldap_read_policy(context, policy, &tktpoldnparam, &omask);
	if (st && st != KRB5_KDB_NOENTRY) {
	    prepend_err_str(context, "Error reading ticket policy. ", st, st);
	    goto cleanup;
	}

	st = 0; /* reset the return status */
    }

    if ((mask & KDB_MAX_LIFE_ATTR) == 0) {
	if ((omask & KDB_MAX_LIFE_ATTR) ==  KDB_MAX_LIFE_ATTR)
	    entries->max_life = tktpoldnparam->maxtktlife;
	else if (ldap_context->lrparams->max_life)
	    entries->max_life = ldap_context->lrparams->max_life;
	else
	    entries->max_life = KRB5_KDB_MAX_LIFE;
    }

    if ((mask & KDB_MAX_RLIFE_ATTR) == 0) {
	if ((omask & KDB_MAX_RLIFE_ATTR) == KDB_MAX_RLIFE_ATTR)
	    entries->max_renewable_life = tktpoldnparam->maxrenewlife;
	else if (ldap_context->lrparams->max_renewable_life)
	    entries->max_renewable_life = ldap_context->lrparams->max_renewable_life;
	else
	    entries->max_renewable_life = KRB5_KDB_MAX_RLIFE;
    }

    if ((mask & KDB_TKT_FLAGS_ATTR) == 0) {
	if ((omask & KDB_TKT_FLAGS_ATTR) == KDB_TKT_FLAGS_ATTR)
	    entries->attributes = tktpoldnparam->tktflags;
	else if (ldap_context->lrparams->tktflags)
	    entries->attributes |= ldap_context->lrparams->tktflags;
    }
    krb5_ldap_free_policy(context, tktpoldnparam);

cleanup:
    return st;
}

static krb5_error_code
krb5_decode_krbsecretkey(context, entries, bvalues, userinfo_tl_data)
    krb5_context                context;
    krb5_db_entry               *entries;
    struct berval               **bvalues;
    krb5_tl_data                *userinfo_tl_data;
{
    char                        *user=NULL;
    int                         i=0, j=0, noofkeys=0;
    krb5_key_data               *key_data=NULL;
    krb5_error_code             st=0;

    if ((st=krb5_unparse_name(context, entries->princ, &user)) != 0)
	goto cleanup;

    for (i=0; bvalues[i] != NULL; ++i) {
	int mkvno; /* Not used currently */
	krb5_int16 n_kd;
	krb5_key_data *kd;
	krb5_data in;

	if (bvalues[i]->bv_len == 0)
	    continue;
	in.length = bvalues[i]->bv_len;
	in.data = bvalues[i]->bv_val;

	st = asn1_decode_sequence_of_keys (&in,
					   &kd,
					   &n_kd,
					   &mkvno);

	if (st != 0) {
	    const char *msg = error_message(st);
	    st = -1; /* Something more appropriate ? */
	    krb5_set_error_message (context, st,
				    "unable to decode stored principal key data (%s)", msg);
	    goto cleanup;
	}
	noofkeys += n_kd;
	key_data = realloc (key_data, noofkeys * sizeof (krb5_key_data));
	for (j = 0; j < n_kd; j++)
	    key_data[noofkeys - n_kd + j] = kd[j];
	free (kd);
    }

    entries->n_key_data = noofkeys;
    entries->key_data = key_data;

cleanup:
    ldap_value_free_len(bvalues);
    free (user);
    return st;
}

static char *
getstringtime(epochtime)
    krb5_timestamp    epochtime;
{
    struct tm           tme;
    char                *strtime=NULL;
    time_t		posixtime = epochtime;

    strtime = calloc (50, 1);
    if (strtime == NULL)
	return NULL;

    if (gmtime_r(&posixtime, &tme) == NULL)
	return NULL;

    strftime(strtime, 50, "%Y%m%d%H%M%SZ", &tme);
    return strtime;
}


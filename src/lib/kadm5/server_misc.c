/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header$
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include    "k5-int.h"
#include    <krb5/kdb.h>
#include    <ctype.h>
#include    "adb.h"

/* for strcasecmp */
#include    <string.h>

#include    "server_internal.h"

kadm5_ret_t
adb_policy_init(kadm5_server_handle_t handle)
{
    osa_adb_ret_t   ret;
    if(handle->policy_db == (osa_adb_policy_t) NULL)
	if((ret = osa_adb_open_policy(&handle->policy_db,
				      &handle->params)) != OSA_ADB_OK)
	     return ret;
    return KADM5_OK;
}

kadm5_ret_t
adb_policy_close(kadm5_server_handle_t handle)
{
    osa_adb_ret_t   ret;
    if(handle->policy_db != (osa_adb_policy_t) NULL)
	if((ret = osa_adb_close_policy(handle->policy_db)) != OSA_ADB_OK)
	    return ret;
    handle->policy_db = NULL;
    return KADM5_OK;
}

/* some of this is stolen from gatekeeper ... */
kadm5_ret_t
passwd_check(kadm5_server_handle_t handle,
	     char *password, int use_policy, kadm5_policy_ent_t pol,
	     krb5_principal principal)
{
    int	    nupper = 0,
	    nlower = 0,
	    ndigit = 0, 
	    npunct = 0,
	    nspec = 0;
    char    c, *s;
    
    if(use_policy) {
	if(strlen(password) < pol->pw_min_length)
	    return KADM5_PASS_Q_TOOSHORT;
	s = password;
	while ((c = *s++)) {
	    if (islower(c)) {
		nlower = 1;
		continue;
	    }
	    else if (isupper(c)) {
		nupper = 1;
		continue;
	    } else if (isdigit(c)) {
		ndigit = 1;
		continue;
	    } else if (ispunct(c)) {
		npunct = 1;
		continue;
	    } else {
		nspec = 1;
		continue;
	    }
	}
	if ((nupper + nlower + ndigit + npunct + nspec) < pol->pw_min_classes) 
	    return KADM5_PASS_Q_CLASS;
	if((find_word(password) == KADM5_OK))
	    return KADM5_PASS_Q_DICT;
	else { 
	    char	*cp;
	    int	c, n = krb5_princ_size(handle->context, principal);
	    cp = krb5_princ_realm(handle->context, principal)->data;
	    if (strcasecmp(cp, password) == 0)
		return KADM5_PASS_Q_DICT;
	    for (c = 0; c < n ; c++) {
		cp = krb5_princ_component(handle->context, principal, c)->data;
		if (strcasecmp(cp, password) == 0)
		    return KADM5_PASS_Q_DICT;
	    }
	    return KADM5_OK;
	}
    } else {
	if (strlen(password) < 1)
	    return KADM5_PASS_Q_TOOSHORT;
    }
    return KADM5_OK;    
}

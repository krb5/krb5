/*
 * lib/kdb/kdb_ldap/ldap_exp.c
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

#include "k5-int.h"
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <errno.h>
#include <utime.h>
#include <kdb5.h>
#include "kdb_ldap.h"
#include "ldap_principal.h"
#include "ldap_pwd_policy.h"

/* Quick and dirty wrapper functions to provide for thread safety
   within the plugin, instead of making the kdb5 library do it.  Eventually
   these should be integrated into the real functions.

   Some of the functions wrapped here are also called directly from
   within this library (e.g., create calls open), so simply dropping
   locking code into the top and bottom of each referenced function
   won't do.  (We aren't doing recursive locks, currently.)  */

static k5_mutex_t *krb5_ldap_mutex;

#define WRAP(NAME,TYPE,ARGLIST,ARGNAMES,ERROR_RESULT)	\
	static TYPE wrap_##NAME ARGLIST			\
	{						\
	    TYPE result;				\
	    int code = k5_mutex_lock (krb5_ldap_mutex);	\
	    if (code) { return ERROR_RESULT; }		\
	    result = NAME ARGNAMES;			\
	    k5_mutex_unlock (krb5_ldap_mutex);		\
	    return result;				\
	}						\
	/* hack: decl to allow a following ";" */	\
	static TYPE wrap_##NAME ()

/* Two special cases: void (can't assign result), and krb5_error_code
   (return error from locking code).  */

#define WRAP_VOID(NAME,ARGLIST,ARGNAMES)		\
	static void wrap_##NAME ARGLIST			\
	{						\
	    int code = k5_mutex_lock (krb5_ldap_mutex);	\
	    if (code) { return; }			\
	    NAME ARGNAMES;				\
	    k5_mutex_unlock (krb5_ldap_mutex);		\
	}						\
	/* hack: decl to allow a following ";" */	\
	static void wrap_##NAME ()

#define WRAP_K(NAME,ARGLIST,ARGNAMES)			\
	WRAP(NAME,krb5_error_code,ARGLIST,ARGNAMES,code)


WRAP_K (krb5_ldap_open,
	(krb5_context kcontext, char *conf_section, char **db_args, int mode),
	(kcontext, conf_section, db_args, mode));
WRAP_K (krb5_ldap_close, (krb5_context ctx), (ctx));
WRAP_K (krb5_ldap_db_get_age, (krb5_context ctx, char *s, time_t *t),
	(ctx, s, t));
WRAP_K (krb5_ldap_get_principal,
	(krb5_context ctx, krb5_const_principal p, krb5_db_entry *d,
	 int * i, krb5_boolean *b),
	(ctx, p, d, i, b));
WRAP_K (krb5_ldap_free_principal,
	(krb5_context ctx, krb5_db_entry *d, int i),
	(ctx, d, i));
WRAP_K (krb5_ldap_put_principal,
	(krb5_context ctx, krb5_db_entry *d, int *i, char **db_args),
	(ctx, d, i, db_args));
WRAP_K (krb5_ldap_delete_principal,
	(krb5_context context, krb5_const_principal searchfor, int *nentries),
	(context, searchfor, nentries));
WRAP_K (krb5_ldap_iterate,
	(krb5_context ctx, char *s,
	 krb5_error_code (*f) (krb5_pointer, krb5_db_entry *),
	 krb5_pointer p),
	(ctx, s, f, p));

WRAP_K (krb5_ldap_create_password_policy,
	(krb5_context context, osa_policy_ent_t entry),
	(context, entry));
WRAP_K (krb5_ldap_get_password_policy,
	(krb5_context kcontext, char *name, osa_policy_ent_t *policy,
	 int *cnt),
	(kcontext, name, policy, cnt));
WRAP_K (krb5_ldap_put_password_policy,
	(krb5_context kcontext, osa_policy_ent_t policy),
	(kcontext, policy));
WRAP_K (krb5_ldap_iterate_password_policy,
	(krb5_context kcontext, char *match_entry,
	 osa_adb_iter_policy_func func, void *data),
	(kcontext, match_entry, func, data));
WRAP_K (krb5_ldap_delete_password_policy,
	(krb5_context kcontext, char *policy),
	(kcontext, policy));
WRAP_VOID (krb5_ldap_free_password_policy,
	   (krb5_context kcontext, osa_policy_ent_t entry),
	   (kcontext, entry));

WRAP (krb5_ldap_alloc, void *,
      (krb5_context kcontext, void *ptr, size_t size),
      (kcontext, ptr, size), NULL);
WRAP_VOID (krb5_ldap_free,
	   (krb5_context kcontext, void *ptr),
	   (kcontext, ptr));

WRAP_K (krb5_ldap_set_mkey,
	(krb5_context kcontext, char *pwd, krb5_keyblock *key),
	(kcontext, pwd, key));
WRAP_K (krb5_ldap_get_mkey,
	(krb5_context context, krb5_keyblock **key),
	(context, key));


static krb5_error_code
wrap_krb5_ldap_lib_init ()
{
    krb5_error_code c;
    c = krb5int_mutex_alloc (&krb5_ldap_mutex);
    if (c)
	return c;
    return krb5_ldap_lib_init ();
}

static krb5_error_code
wrap_krb5_ldap_lib_cleanup (void)
{
    krb5int_mutex_free (krb5_ldap_mutex);
    krb5_ldap_mutex = NULL;
    return krb5_ldap_lib_cleanup();
}

/*
 *      Exposed API
 */

kdb_vftabl krb5_db_vftabl_kldap = {
  1,                                      /* major version number 1 */
  0,                                      /* minor version number 0 */
  /* init_library */			       wrap_krb5_ldap_lib_init,
  /* fini_library */			       wrap_krb5_ldap_lib_cleanup,
  /* init_module */			       wrap_krb5_ldap_open,
  /* fini_module */			       wrap_krb5_ldap_close,
  /* db_create */			       NULL,
  /* db_destroy */			       NULL,
  /* db_get_age */                             wrap_krb5_ldap_db_get_age,
  /* db_set_option */			       NULL,
  /* db_lock */				       NULL,
  /* db_unlock */			       NULL,
  /* db_get_principal */		       wrap_krb5_ldap_get_principal,
  /* db_free_principal */		       wrap_krb5_ldap_free_principal,
  /* db_put_principal */		       wrap_krb5_ldap_put_principal,
  /* db_delete_principal */		       wrap_krb5_ldap_delete_principal,
  /* db_iterate */			       wrap_krb5_ldap_iterate,
  /* db_create_policy */                       wrap_krb5_ldap_create_password_policy,
  /* db_get_policy */                          wrap_krb5_ldap_get_password_policy,
  /* db_put_policy */                          wrap_krb5_ldap_put_password_policy,
  /* db_iter_policy */                         wrap_krb5_ldap_iterate_password_policy,
  /* db_delete_policy */                       wrap_krb5_ldap_delete_password_policy,
  /* db_free_policy */                         wrap_krb5_ldap_free_password_policy,
  /* db_supported_realms */		       NULL,
  /* db_free_supported_realms */	       NULL,
  /* errcode_2_string */                       NULL,
  /* db_alloc */                               wrap_krb5_ldap_alloc,
  /* db_free */                                wrap_krb5_ldap_free,
  /* set_master_key */			       wrap_krb5_ldap_set_mkey,
  /* get_master_key */			       wrap_krb5_ldap_get_mkey,
  /* setup_master_key_name */		       NULL,
  /* store_master_key */		       NULL,
  /* fetch_master_key */		       NULL /* wrap_krb5_ldap_fetch_mkey */,
  /* verify_master_key */		       NULL /* wrap_krb5_ldap_verify_master_key */,
  /* Search enc type */                        NULL,
  /* Change pwd   */                           NULL

};

/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 * $Id$
 * $Source$
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include "string_table.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <kadm5/adb.h>
#include <kadm5/admin.h>

#include <krb5.h>
#include <krb5/kdb.h>

int add_admin_princ(void *handle, krb5_context context,
		    char *name, char *realm, int attrs, int lifetime);

#define ERR 1
#define OK 0

#define ADMIN_LIFETIME 60*60*3 /* 3 hours */
#define CHANGEPW_LIFETIME 60*5 /* 5 minutes */

extern char *progname;

extern krb5_encrypt_block master_encblock;
extern krb5_keyblock master_keyblock;
extern krb5_db_entry master_db;

/*
 * Function: kadm5_create
 *
 * Purpose: create admin principals in KDC database
 *
 * Arguments:	params	(r) configuration parameters to use
 *      
 * Effects:  Creates KADM5_ADMIN_SERVICE and KADM5_CHANGEPW_SERVICE
 * principals in the KDC database and sets their attributes
 * appropriately.
 */
int kadm5_create(kadm5_config_params *params)
{
     int retval;
     void *handle;
     krb5_context context;
     FILE *f;


     if (retval = krb5_init_context(&context))
	  exit(ERR);

     /*
      * The lock file has to exist before calling kadm5_init, but
      * params->admin_lockfile may not be set yet...
      */
     if (retval = kadm5_get_config_params(context, NULL, NULL,
					  params, params)) {
	  com_err(progname, retval, str_INITING_KCONTEXT);
	  return 1;
     }

     if (retval = osa_adb_create_policy_db(params)) {
	  com_err(progname, retval, str_CREATING_POLICY_DB);
	  return 1;
     }

     retval = kadm5_create_magic_princs(params, context);

     krb5_free_context(context);

     return retval;
}

int kadm5_create_magic_princs(kadm5_config_params *params,
			      krb5_context *context)
{
     int retval;
     void *handle;
     
     if ((retval = kadm5_init(progname, NULL, NULL, params,
			      KADM5_STRUCT_VERSION,
			      KADM5_API_VERSION_2,
			      &handle))) {
	  com_err(progname, retval, str_INITING_KCONTEXT);
	  return retval;
     }

     retval = add_admin_princs(handle, context, params->realm);

     kadm5_destroy(handle);

     return retval;
}

/*
 * Function: build_name_with_realm
 *
 * Purpose: concatenate a name and a realm to form a krb5 name
 *
 * Arguments:
 *
 * 	name	(input) the name
 * 	realm	(input) the realm
 *
 * Returns:
 *
 * 	pointer to name@realm, in allocated memory, or NULL if it
 * 	cannot be allocated
 *
 * Requires: both strings are null-terminated
 */
char *build_name_with_realm(char *name, char *realm)
{
     char *n;

     n = (char *) malloc(strlen(name) + strlen(realm) + 2);
     sprintf(n, "%s@%s", name, realm);
     return n;
}

/*
 * Function: add_admin_princs
 *
 * Purpose: create admin principals
 *
 * Arguments:
 *
 * 	rseed		(input) random seed
 * 	realm		(input) realm, or NULL for default realm
 *      <return value>  (output) status, 0 for success, 1 for serious error
 *      
 * Requires:
 *      
 * Effects:
 *      
 * add_admin_princs creates KADM5_ADMIN_SERVICE,
 * KADM5_CHANGEPW_SERVICE.  If any of these exist a message is
 * printed.  If any of these existing principal do not have the proper
 * attributes, a warning message is printed.
 */
int add_admin_princs(void *handle, krb5_context context, char *realm)
{
  krb5_error_code ret = 0;
  
  if ((ret = add_admin_princ(handle, context,
			     KADM5_ADMIN_SERVICE, realm,
			     KRB5_KDB_DISALLOW_TGT_BASED,
			     ADMIN_LIFETIME)))
       goto clean_and_exit;

  if ((ret = add_admin_princ(handle, context, 
			     KADM5_CHANGEPW_SERVICE, realm, 
			     KRB5_KDB_DISALLOW_TGT_BASED |
			     KRB5_KDB_PWCHANGE_SERVICE,
			     CHANGEPW_LIFETIME)))
       goto clean_and_exit;
  
clean_and_exit:

  return ret;
}

/*
 * Function: add_admin_princ
 *
 * Arguments:
 *
 * 	creator		(r) principal to use as "mod_by"
 * 	rseed		(r) seed for random key generator
 * 	name		(r) principal name
 * 	realm		(r) realm name for principal
 * 	attrs		(r) principal's attributes
 * 	lifetime	(r) principal's max life, or 0
 * 	not_unique	(r) error message for multiple entries, never used
 * 	exists		(r) warning message for principal exists
 * 	wrong_attrs	(r) warning message for wrong attributes
 *
 * Returns:
 *
 * 	OK on success
 * 	ERR on serious errors
 *
 * Effects:
 * 
 * If the principal is not unique, not_unique is printed (but this
 * never happens).  If the principal exists, then exists is printed
 * and if the principals attributes != attrs, wrong_attrs is printed.
 * Otherwise, the principal is created with mod_by creator and
 * attributes attrs and max life of lifetime (if not zero).
 */

int add_admin_princ(void *handle, krb5_context context,
		    char *name, char *realm, int attrs, int lifetime)
{
     char *fullname;
     int nprincs;
     krb5_error_code ret;
     kadm5_principal_ent_rec ent;

     memset(&ent, 0, sizeof(ent));

     fullname = build_name_with_realm(name, realm);
     if (ret = krb5_parse_name(context, fullname, &ent.principal)) {
	  com_err(progname, ret, str_PARSE_NAME);
	  return(ERR);
     }
     ent.max_life = lifetime;
     ent.attributes = attrs | KRB5_KDB_DISALLOW_ALL_TIX;
     
     if (ret = kadm5_create_principal(handle, &ent,
					   (KADM5_PRINCIPAL |
					    KADM5_MAX_LIFE |
					    KADM5_ATTRIBUTES),
					   "to-be-random")) {
	  if (ret != KADM5_DUP) {
	       com_err(progname, ret, str_PUT_PRINC, fullname);
	       krb5_free_principal(context, ent.principal);
	       free(fullname);
	       return ERR;
	  }
     } else {
	  /* only randomize key if we created the principal */
	  ret = kadm5_randkey_principal(handle, ent.principal, NULL, NULL);
	  if (ret) {
	       com_err(progname, ret, str_RANDOM_KEY, fullname);
	       krb5_free_principal(context, ent.principal);
	       free(fullname);
	       return ERR;
	  }
	  
	  ent.attributes = attrs;
	  ret = kadm5_modify_principal(handle, &ent, KADM5_ATTRIBUTES);
	  if (ret) {
	       com_err(progname, ret, str_PUT_PRINC, fullname);
	       krb5_free_principal(context, ent.principal);
	       free(fullname);
	       return ERR;
	  }
     }
     
     krb5_free_principal(context, ent.principal);
     free(fullname);

     return OK;
}

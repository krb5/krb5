/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 * $Id$
 * $Source$
 * 
 * $Log$
 * Revision 1.23  1996/07/22 20:24:35  marc
 * this commit includes all the changes on the OV_9510_INTEGRATION and
 * OV_MERGE branches.  This includes, but is not limited to, the new openvision
 * admin system, and major changes to gssapi to add functionality, and bring
 * the implementation in line with rfc1964.  before committing, the
 * code was built and tested for netbsd and solaris.
 *
 * Revision 1.22.4.1  1996/07/18 03:01:22  marc
 * merged in changes from OV_9510_BP to OV_9510_FINAL1
 *
 * Revision 1.22.2.1  1996/06/20  21:44:55  marc
 * File added to the repository on a branch
 *
 * Revision 1.22  1996/06/19  15:09:32  bjaspan
 * changes to work in mit tree
 *
 * Revision 1.21  1995/11/07  23:27:28  grier
 * Add stdlib.h
 * Add string.h
 *
 * Revision 1.20  1995/08/13  16:41:11  jik
 * Fix a nonsensical comment about the iterator() function.  See PR
 * secure-admin/470.
 *
 * Revision 1.19  1995/07/02  19:55:13  jik
 * Key version numbers should start out at 1, not 0.
 * Should get the master key version number from the master_db entry in
 * server_kdb.c, rather than assuming that the master key version number
 * is 0.
 *
 * Revision 1.18  1995/03/14  16:58:50  jik
 * Use krb5_xfree instead of xfree if KRB5B4 is defined.
 *
 * Revision 1.17  1994/03/11 19:37:34  bjaspan
 * [secure-admin/1593: ovsec_adm_create non-error messages go to stderr]
 * [secure-releng/1608: audit secure-admin/1593: ovsec_adm_create non-error messages go to stderr]
 *
 * Sandbox:
 *
 *  Normal messages should be printed to stdout rather than displayed
 *  using com_err, which will cause then to go to stderr.
 *
 * Revision 1.17  1994/03/09  22:21:33  jik
 * Normal messages should be printed to stdout rather than displayed
 * using com_err, which will cause then to go to stderr.
 *
 * Revision 1.16  1993/12/21  20:26:34  marc
 * create new principals with policy NULL, not ""
 *
 * Revision 1.15  1993/12/14  22:51:35  marc
 * missing * in call to krb5_random_key
 *
 * Revision 1.14  1993/11/27  20:42:32  bjaspan
 * fix secure/621: coredumps with default realm
 *
 * Revision 1.13  1993/11/19  20:03:51  shanzer
 * osa_adb_open_T takes a file name argument.
 *
 * Revision 1.12  1993/11/10  21:30:24  bjaspan
 * move init code to main, accept -m
 *
 * Revision 1.11  1993/11/10  04:33:35  bjaspan
 * rewrote adding principals to kdb, and set lifetimes
 *
 * Revision 1.10  1993/11/06  00:08:44  bjaspan
 * use new OVSEC_KADM_* names, use correct realm
 *
 * Revision 1.9  1993/11/05  05:05:35  bjaspan
 * added -r realm argument
 *
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include "string_table.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ovsec_admin/adb.h>
#include <ovsec_admin/admin.h>

#include <krb5.h>
#include <krb5/kdb.h>

int add_admin_princ(void *handle, krb5_context context,
		    char *name, char *realm, int attrs, int lifetime);

#define ERR 1
#define OK 0

#define ADMIN_LIFETIME 60*60*3 /* 3 hours */
#define CHANGEPW_LIFETIME 60*5 /* 5 minutes */

char *whoami;

extern krb5_encrypt_block master_encblock;
extern krb5_keyblock master_keyblock;
extern krb5_db_entry master_db;

/*
 * Function: main
 *
 * Purpose: create admin principals, create and populate admin dbs
 *
 * Arguments:
 *
 *      input           none
 *      <return value>  exit status 1 for error 0 for success
 *      
 * Requires:
 *      
 *      
 * Effects:
 *      
 *      
 * Modifies:
 *
 */

void usage()     
{
     fprintf(stderr, "%s\n", str_PROG_CREATE_USAGE);
     exit(1);
}
     
void main(int argc, char **argv)
{
     char *realm = NULL;
     int freerealm = 0;
     int retval, from_keyboard = 0;
     krb5_principal creator = NULL;
     void *handle;
     krb5_context context;

     whoami = str_PROG_NAME_CREATE;

     argc--; argv++;
     while (argc) {
	  if (strcmp(*argv, "-r") == 0) {
	       argc--; argv++;
	       if (!argc)
		    usage();
	       realm = *argv;
	  } else if (strcmp(*argv, "-m") == 0) {
	       from_keyboard = 1;
	  } else
	       break;
	  argc--; argv++;
     }
     
     if (argc != 0)
	  usage();

     if (retval = krb5_init_context(&context))
	  exit(ERR);

     if (realm == NULL) {
	  if ((retval = krb5_get_default_realm(context, &realm)) != 0)
	       exit(retval);
	  freerealm = 1;
     }
  
     if ((retval = ovsec_kadm_init(whoami, from_keyboard?"non-null":NULL,
				   NULL, realm,
				   OVSEC_KADM_STRUCT_VERSION,
				   OVSEC_KADM_API_VERSION_1,
				   &handle))) {
	  com_err(whoami, retval, str_INITING_KCONTEXT);

	  krb5_free_context(context);
	  exit(ERR);
     }

     retval = add_admin_princs(handle, context, realm);

     ovsec_kadm_destroy(handle);
     krb5_free_context(context);

     if (retval)
	  exit(retval);
     
     exit(0);
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
 * add_admin_princs creates OVSEC_KADM_ADMIN_SERVICE,
 * OVSEC_KADM_CHANGEPW_SERVICE, and OVSEC_KADM_HIST_PRINCIPAL.  If any
 * of these exist a message is printed.  If any of these existing
 * principal do not have the proper attributes, a warning message is
 * printed.
 */
int add_admin_princs(void *handle, krb5_context context, char *realm)
{
  krb5_error_code ret = 0;
  
  if ((ret = add_admin_princ(handle, context,
			     OVSEC_KADM_ADMIN_SERVICE, realm,
			     KRB5_KDB_DISALLOW_TGT_BASED,
			     ADMIN_LIFETIME)))
       goto clean_and_exit;

  if ((ret = add_admin_princ(handle, context, 
			     OVSEC_KADM_CHANGEPW_SERVICE, realm, 
			     KRB5_KDB_DISALLOW_TGT_BASED |
			     KRB5_KDB_PWCHANGE_SERVICE,
			     CHANGEPW_LIFETIME)))
       goto clean_and_exit;
  
#if 0
  /* this is now done inside kdb_init_hist in the admin server */

  if ((ret = add_admin_princ(handle, context, 
			     OVSEC_KADM_HIST_PRINCIPAL, realm,
			     KRB5_KDB_DISALLOW_ALL_TIX,
			     0)))
       goto clean_and_exit;
#endif

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
     ovsec_kadm_principal_ent_rec ent;

     memset(&ent, 0, sizeof(ent));

     fullname = build_name_with_realm(name, realm);
     if (ret = krb5_parse_name(context, fullname, &ent.principal)) {
	  com_err(whoami, ret, str_PARSE_NAME);
	  return(ERR);
     }
     ent.max_life = lifetime;
     ent.attributes = attrs;
     
     if (ret = ovsec_kadm_create_principal(handle, &ent,
					   (OVSEC_KADM_PRINCIPAL |
					    OVSEC_KADM_MAX_LIFE |
					    OVSEC_KADM_ATTRIBUTES),
					   "to-be-random")) {
	  if (ret == OVSEC_KADM_DUP)
	       ret = ovsec_kadm_modify_principal(handle, &ent,
						 (OVSEC_KADM_PRINCIPAL |
						  OVSEC_KADM_MAX_LIFE |
						  OVSEC_KADM_ATTRIBUTES));

	  if (ret) {
	       com_err(whoami, ret, str_PUT_PRINC, fullname);
	       krb5_free_principal(context, ent.principal);
	       free(fullname);
	       return ERR;
	  }
     }

     ret = ovsec_kadm_randkey_principal(handle, ent.principal, NULL);

     krb5_free_principal(context, ent.principal);
     free(fullname);

     if (ret) {
	  com_err(whoami, ret, str_RANDOM_KEY, fullname);
	  return ERR;
     }

     return OK;
}

#if 0
/*
 * Function: main
 *
 * Purpose: Return "garbage" if the caller asks for it.
 *
 * Arguments:
 *
 *      input           (input) A null-terminated string,
 *                      or NULL.
 *      delay           (input/output) The number of seconds the
 *                      function should delay before returning.
 *      <return value>  (output) A string.
 *      
 * Requires:
 *      
 *      "input" must either be NULL or point to an address in the
 *      program's address space.  "delay" must point to an address in
 *      the program's address space.
 *
 * Effects:
 *      
 *      The function first sleeps for approximately the number of
 *      seconds specified in "delay".
 *      
 *      Then, if "input" is non-NULL and points to a null-terminated
 *      string which is equal to "garbage", the function sets "delay"
 *      to 42 and returns a string allocated with malloc(3) containing
 *      "more-garbage".
 *      
 *      If "input" is NULL or does not contain "garbage", the function
 *      returns NULL without modifying "delay".
 *      
 *      If "<return value>" is non-NULL, the caller should deallocate
 *      the string in it (with free(3)) when it is no longer needed.
 *      
 * Modifies:
 *      
 *      May allocate a new block of memory in the malloc(3) arena.
 *      May change the value in the memory location pointed to by
 *      "delay".
 */

krb5_error_code add_random_princ(princ_str, princ, attrs, lifetime,
				 creator, rseed) 
   char *princ_str;
   krb5_principal princ, creator;
   krb5_flags attrs;
   int lifetime;
   krb5_pointer *rseed;
{
    krb5_db_entry entry;
    krb5_error_code ret;
    krb5_encrypted_keyblock ekey;
    krb5_keyblock *rkey;
    int nentries = 1;

    memset((char *) &entry, 0, sizeof(entry));
    entry.principal = princ;
    entry.kvno = 1;
    entry.max_life = KRB5_KDB_MAX_LIFE;
    entry.max_renewable_life = 0;
    entry.mkvno = master_db.mkvno;
    entry.expiration = KRB5_KDB_EXPIRATION;
    entry.mod_name = creator;
    if (lifetime != 0)
	 entry.max_life = lifetime;
    
    if (ret = krb5_timeofday(&entry.mod_date))
      return(ret);

    entry.attributes = attrs;

    ret = krb5_random_key(&master_encblock, *rseed, &rkey);
    if (ret != 0) {
      com_err(whoami, ret, str_RANDOM_KEY, princ_str);
      return (ERR);
    }


    ret = krb5_kdb_encrypt_key(&master_encblock, rkey, &ekey);
    krb5_free_keyblock(rkey);
    if (ret != 0) {
      com_err(whoami, ret, str_ENCRYPT_KEY, princ_str);
      return (ERR);
    }

    entry.key = ekey;
    entry.salt_type = KRB5_KDB_SALTTYPE_NORMAL;
    entry.salt_length = 0;
    entry.salt = 0;
    
    ret = krb5_db_put_principal(&entry, &nentries);
    if (ret != 0)
      com_err(whoami, ret, str_PUT_PRINC, princ_str);
#ifdef KRB5B4
    krb5_xfree(ekey.contents);
#else
    xfree(ekey.contents);
#endif

    if (ret) return(ERR);

    printf(str_CREATED_PRINC, whoami, princ_str);

    return(OK);
}

/*
 * Function: create_admin_policy_db
 *
 * Purpose: Return "garbage" if the caller asks for it.
 *
 * Arguments:
 *
 *      input           (input) A null-terminated string,
 *                      or NULL.
 *      delay           (input/output) The number of seconds the
 *                      function should delay before returning.
 *      <return value>  (output) A string.
 *      
 * Requires:
 *      
 *      "input" must either be NULL or point to an address in the
 *      program's address space.  "delay" must point to an address in
 *      the program's address space.
 *
 * Effects:
 *      
 *      The function first sleeps for approximately the number of
 *      seconds specified in "delay".
 *      
 *      Then, if "input" is non-NULL and points to a null-terminated
 *      string which is equal to "garbage", the function sets "delay"
 *      to 42 and returns a string allocated with malloc(3) containing
 *      "more-garbage".
 *      
 *      If "input" is NULL or does not contain "garbage", the function
 *      returns NULL without modifying "delay".
 *      
 *      If "<return value>" is non-NULL, the caller should deallocate
 *      the string in it (with free(3)) when it is no longer needed.
 *      
 * Modifies:
 *      
 *      May allocate a new block of memory in the malloc(3) arena.
 *      May change the value in the memory location pointed to by
 *      "delay".
 */

int create_admin_policy_db()
{
  /* We don't have a create/destroy routine, so opening the db and
     closing it will have to do. */
  osa_adb_policy_t policy_db = NULL;
  osa_adb_ret_t ret;

  ret = osa_adb_open_policy(&policy_db, POLICY_DB);
  if (ret != OSA_ADB_OK) {
    com_err (whoami, ret, str_CREATING_POLICY_DB);
    return(-1);
  }

  /* Should create sample policies here */

  ret = osa_adb_close_policy(policy_db);
  if (ret != OSA_ADB_OK) {
    com_err (whoami, ret, str_CLOSING_POLICY_DB);
    return(-1);
  }

  printf(str_CREATED_POLICY_DB, whoami);

  return(OK);
}

/*

 * Function: iterator(ptr, entry)
 *
 * Purpose:
 *
 * 	Creates an entry in the Admin database corresponding to the
 * 	specified entry in the Kerberos database.
 *
 * Arguments:
 *
 *      ptr		(input) Actually of type osa_adb_princ_t,
 * 			represents the Admin database in which to
 * 			create the principal.
 *	entry		(input) The entry in the Kerberos database for
 * 			which to create an entry in the Admin
 * 			database.
 *      
 * Requires:
 *      
 *      "ptr" represents a valid, open Admin principal database.
 *      "entry" represents a valid, decoded Kerberos database
 *      principal entry.
 *
 * Effects:
 *      
 *      Modifies the Admin principal database by creating a principal
 *      in the database with the same name as "entry" and no other
 *      information.
 *      
 * Modifies:
 *      
 *      Does not modify any global memory.  Modifies the Admin
 *      principal database whose handle is passed into it.
 */

krb5_error_code
iterator(ptr, entry)
krb5_pointer ptr;
krb5_db_entry *entry;
{ 
  osa_adb_ret_t retval;
  krb5_error_code retval2;
  char *princ_str = NULL;
  osa_princ_ent_rec osa_princ;

  /* Zero the whole struct, and fill in the princ name */
  memset(&osa_princ, 0, sizeof(osa_princ_ent_rec));

  osa_princ.name = entry->principal;
  osa_princ.policy = NULL;

  retval = osa_adb_create_princ((osa_adb_princ_t) ptr, &osa_princ);
  if (retval != OSA_ADB_OK) {
    if (retval2 = krb5_unparse_name(entry->principal, &princ_str)) {
	com_err(whoami, retval2, str_UNPARSE_PRINC);
    }
    com_err(whoami, retval, str_CREATING_PRINC_ENTRY, 
	    (princ_str ? princ_str : str_A_PRINC));
    if (princ_str) free(princ_str);
  }
  return (0);
}

/*
 * Function: create_and_populate_admin_princ_db
 *
 * Purpose: Return "garbage" if the caller asks for it.
 *
 * Arguments:
 *
 *      input           (input) A null-terminated string,
 *                      or NULL.
 *      delay           (input/output) The number of seconds the
 *                      function should delay before returning.
 *      <return value>  (output) A string.
 *      
 * Requires:
 *      
 *      "input" must either be NULL or point to an address in the
 *      program's address space.  "delay" must point to an address in
 *      the program's address space.
 *
 * Effects:
 *      
 *      The function first sleeps for approximately the number of
 *      seconds specified in "delay".
 *      
 *      Then, if "input" is non-NULL and points to a null-terminated
 *      string which is equal to "garbage", the function sets "delay"
 *      to 42 and returns a string allocated with malloc(3) containing
 *      "more-garbage".
 *      
 *      If "input" is NULL or does not contain "garbage", the function
 *      returns NULL without modifying "delay".
 *      
 *      If "<return value>" is non-NULL, the caller should deallocate
 *      the string in it (with free(3)) when it is no longer needed.
 *      
 * Modifies:
 *      
 *      May allocate a new block of memory in the malloc(3) arena.
 *      May change the value in the memory location pointed to by
 *      "delay".
 */

int create_and_populate_admin_princ_db()
{
  osa_adb_princ_t princ_db = NULL;
  osa_adb_ret_t ret;

  /* We don't have a create/destroy routine, so opening the db and
     closing it will have to do. */

  ret = osa_adb_open_princ(&princ_db, PRINCIPAL_DB);
  if (ret != OSA_ADB_OK) {
    com_err (whoami, ret, str_CREATING_PRINC_DB);
    return(-1);
  }

  printf(str_CREATED_PRINC_DB, whoami);

  (void) krb5_db_iterate(iterator, princ_db);

  ret = osa_adb_close_princ(princ_db);
  if (ret != OSA_ADB_OK) {
    com_err (whoami, ret, str_CLOSING_PRINC_DB);
    return(-1);
  }


  return(OK);
}

#endif

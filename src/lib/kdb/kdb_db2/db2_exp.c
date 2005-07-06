/**********************************************************************
*
*	C %name:		db2_exp.c %
*	Instance:		idc_sec_2
*	Description:	
*	%created_by:	spradeep %
*	%date_created:	Tue Apr  5 11:44:00 2005 %
*
**********************************************************************/
#ifndef lint
static char *_csrc = "@(#) %filespec: db2_exp.c~5 %  (%full_filespec: db2_exp.c~5:csrc:idc_sec#2 %)";
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "k5-int.h"
#include <db.h>
#include <stdio.h>
#include <errno.h>
#include <utime.h>
#include "../kdb5.h"
#include "kdb_db2.h"
#include "kdb_xdr.h"
#include "policy_db.h"

/*
 *      Exposed API
 */

kdb_vftabl krb5_db_vftabl_db2 = {
  1,                                      /* major version number 1 */
  0,                                      /* minor version number 0 */
  0,                                      /* TBD. Not sure whether thread safe. For now, its not */
  /* init_library */			       krb5_db2_lib_init,
  /* fini_library */			       krb5_db2_lib_cleanup,
  /* init_module */			       krb5_db2_open,
  /* fini_module */			       krb5_db2_db_fini,
  /* db_create */			       krb5_db2_create,
  /* db_destroy */			       krb5_db2_destroy,
  /* db_get_age */                             krb5_db2_db_get_age,
  /* db_set_option */			       krb5_db2_db_set_option,
  /* db_lock */				       krb5_db2_db_lock,
  /* db_unlock */			       krb5_db2_db_unlock,
  /* db_get_principal */		       krb5_db2_db_get_principal,
  /* db_free_principal */		       krb5_db2_db_free_principal,
  /* db_put_principal */		       krb5_db2_db_put_principal,
  /* db_delete_principal */		       krb5_db2_db_delete_principal,
  /* db_iterate */			       krb5_db2_db_iterate,
  /* db_create_policy */                       krb5_db2_create_policy,
  /* db_get_policy */                          krb5_db2_get_policy,
  /* db_put_policy */                          krb5_db2_put_policy,
  /* db_iter_policy */                         krb5_db2_iter_policy,
  /* db_delete_policy */                       krb5_db2_delete_policy,
  /* db_free_policy */                         krb5_db2_free_policy,
  /* db_supported_realms */		       NULL,
  /* db_free_supported_realms */	       NULL,
  /* errcode_2_string */                       NULL,
  /* db_alloc */                               krb5_db2_alloc,
  /* db_free */                                krb5_db2_free,
  /* set_master_key */			       krb5_db2_set_master_key_ext,
  /* get_master_key */			       krb5_db2_db_get_mkey
};

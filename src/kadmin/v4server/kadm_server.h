/*
 * kadmin/v4server/kadm_server.h
 *
 * Copyright 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * Definitions for Kerberos administration server & client
 */

#ifndef KADM_SERVER_DEFS
#define KADM_SERVER_DEFS

#include <mit-copyright.h>
/*
 * kadm_server.h
 * Header file for the fourth attempt at an admin server
 * Doug Church, December 28, 1989, MIT Project Athena
 *    ps. Yes that means this code belongs to athena etc...
 *        as part of our ongoing attempt to copyright all greek names
 */

#include <sys/types.h>
#include <krb.h>
#include <des.h>
#include "k5-int.h"
#ifdef KADM5
#include <kadm5/admin.h>
#endif
#include "kadm.h"
#include "krb_db.h"

typedef struct {
  struct sockaddr_in admin_addr;
  struct sockaddr_in recv_addr;
  int recv_addr_len;
  int admin_fd;			/* our link to clients */
  char sname[ANAME_SZ];
  char sinst[INST_SZ];
  char krbrlm[REALM_SZ];
  krb5_principal sprinc;
  krb5_principal master_princ;
  krb5_keyblock master_keyblock;
  krb5_deltat max_life;
  krb5_deltat max_rlife;
  krb5_timestamp expiration;
  krb5_flags flags;
  krb5_kvno mkvno;
} Kadm_Server;

#define	ADD_ACL_FILE	"/v4acl.add"
#define	GET_ACL_FILE	"/v4acl.get"
#define	MOD_ACL_FILE	"/v4acl.mod"
#define	DEL_ACL_FILE	"/v4acl.del"
#define STAB_ACL_FILE	"/v4acl.srvtab"
#define STAB_SERVICES_FILE	"/v4stab_services"
#define STAB_HOSTS_FILE		"/v4stab_bad_hosts"

extern krb5_context kadm_context;

/* kadm_ser_wrap.c */
#ifdef KADM5
extern int kadm_ser_init(int, char *, kadm5_config_params *);
#else
extern int kadm_ser_init(int, char *);
#endif
extern int kadm_ser_in(u_char **, int *);

/* kadm_server.c */
int kadm_ser_cpw(u_char *, int, AUTH_DAT *, u_char **, int *);
int kadm_ser_add(u_char *, int, AUTH_DAT *, u_char **, int *);
int kadm_ser_del(u_char *, int, AUTH_DAT *, u_char **, int *);
int kadm_ser_mod(u_char *, int, AUTH_DAT *, u_char **, int *);
int kadm_ser_get(u_char *, int, AUTH_DAT *, u_char **, int *);
int kadm_ser_ckpw(u_char *, int, AUTH_DAT *, u_char **, int *);
int kadm_ser_stab(u_char *, int, AUTH_DAT *, u_char **, int *);

/* kadm_funcs.c */
krb5_error_code kadm_add_entry(char *, char *, char *, 
			       Kadm_vals *, Kadm_vals *);
krb5_error_code kadm_del_entry(char *, char *, char *, 
			       Kadm_vals *, Kadm_vals *);
krb5_error_code kadm_get_entry(char *, char *, char *, 
			       Kadm_vals *, u_char *, Kadm_vals *);
krb5_error_code kadm_mod_entry(char *, char *, char *, 
			       Kadm_vals *, Kadm_vals *, Kadm_vals *);
krb5_error_code kadm_change (char *, char *, char *, des_cblock);
krb5_error_code kadm_approve_pw(char *, char *, char *, des_cblock, char *);
krb5_error_code kadm_chg_srvtab(char *, char *, char *, Kadm_vals *);

/* kadm_supp.c */
void prin_vals(Kadm_vals *);
void kadm_prin_to_vals(u_char *, Kadm_vals *, Principal *);
void kadm_vals_to_prin(u_char *, Principal *, Kadm_vals *);

/* acl_files.c */
int acl_add(char *, char *);
int acl_delete(char *, char *);
int acl_check(char *, char *);
void acl_canonicalize_principal(char *, char *);
int acl_exact_match(char *, char *);
int acl_initialize(char *, int);

/* admin_server.c */
#ifdef KADM5
krb5_int32 convert_kadm5_to_kadm(krb5_int32);
#endif

#endif /* KADM_SERVER_DEFS */

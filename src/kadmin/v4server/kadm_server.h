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

#endif /* KADM_SERVER_DEFS */

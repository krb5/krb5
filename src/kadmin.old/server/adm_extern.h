/*
 * kadmin/server/adm_extern.h
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * Sandia National Laboratories also makes no representations about the 
 * suitability of the modifications, or additions to this software for 
 * any purpose.  It is provided "as is" without express or implied warranty.
 *
 * <<< Description >>>
 */

#ifndef __ADM_EXTERN__
#define __ADM_EXTERN__

#include "adm_defs.h"

typedef struct {
	/* Client Info */
  struct sockaddr_in client_name;
  krb5_address client_addr;
  krb5_principal client;
  char *name_of_client;
	/* Server Info */
  struct sockaddr_in server_name;
  krb5_address server_addr;
  krb5_principal server;
  char *name_of_service;
	/* Miscellaneous */
  int server_socket;
  int client_socket;
} global_client_server_info;
 
/* various externs for KDC */
extern krb5_encrypt_block master_encblock;
extern krb5_keyblock master_keyblock;
extern krb5_principal master_princ;
extern krb5_db_entry master_entry;

extern volatile int signal_requests_exit;
extern char *dbm_db_name;
extern char *realm;

extern krb5_keyblock tgs_key;
extern krb5_kvno tgs_kvno;
extern krb5_principal tgs_server;

extern global_client_server_info client_server_info;
extern char *adm5_tcp_portname;
extern int adm5_tcp_port_fd;

extern unsigned pidarraysize;
extern int *pidarray;

extern char *adm5_ver_str;
extern int adm5_ver_len;

extern int adm_debug_flag;

extern int send_seqno;

extern int exit_now;

extern short admin_port;

extern krb5_data inbuf;
extern krb5_data msg_data;

extern char *oper_type[];
extern char *ksrvutil_message[];
extern char *kadmind_general_response[];
extern char *kadmind_kpasswd_response[];
extern char *kadmind_ksrvutil_response[];
extern char *kadmind_kadmin_response[];

/* PROTOTYPES */

krb5_error_code adm_build_key
	PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   char *,
		   int,
		   krb5_db_entry));

krb5_error_code adm_change_pwd
	PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   char *,
		   char *,
		   int));

krb5_error_code adm_change_pwd_rnd
	PROTOTYPE((krb5_context,
		   char *,
		   char *));

krb5_error_code adm_add_new_key
	PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   char *,
		   char *,
		   int));

krb5_error_code adm_add_new_key_rnd
	PROTOTYPE((krb5_context, 
		   char *,
		   char *));

krb5_error_code adm_del_old_key
	PROTOTYPE((krb5_context,
		   char *,
		   char *));

krb5_error_code adm_mod_old_key
	PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   char *,
		   char *));

krb5_error_code adm_inq_old_key
	PROTOTYPE((krb5_context, 
		   krb5_auth_context,
		   char *,
		   char *));

krb5_error_code adm_print_exp_time
	PROTOTYPE((krb5_context, 
		   char *,
		   krb5_timestamp));

krb5_kvno adm_princ_exists
	PROTOTYPE((krb5_context, 
		   char *,
		   krb5_principal,
		   krb5_db_entry *,
		   int *));

krb5_error_code adm_enter_rnd_pwd_key
	PROTOTYPE((krb5_context,
		   char *,
		   krb5_principal,
		   int,
		   krb5_db_entry *));

krb5_error_code adm_find_keytype
	PROTOTYPE((krb5_db_entry *,
		   krb5_keytype,
		   krb5_int32,
		   krb5_key_data **));

krb5_error_code adm_update_tl_attrs
	PROTOTYPE((krb5_context,
		   krb5_db_entry *,
		   krb5_principal,
		   krb5_boolean));

krb5_error_code adm5_kadmin
	PROTOTYPE((krb5_context,
		   krb5_auth_context,
    		   char *,  
    		   char *,
    		   int *));

krb5_error_code adm_negotiate_key
	PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   char const *,
		   char *));

krb5_error_code setup_network
	PROTOTYPE((krb5_context,
		   const char *));

krb5_error_code process_client
	PROTOTYPE((krb5_context, 
		   char *));

krb5_error_code cleanexit
	PROTOTYPE((krb5_context,
		   int));

krb5_error_code closedown_db
	PROTOTYPE((krb5_context));

krb5_error_code process_args
	PROTOTYPE((krb5_context, 
		   int,
		   char **));

krb5_error_code init_db
	PROTOTYPE((krb5_context,
		   char *,
		   krb5_principal,
		   krb5_keyblock *));

void setup_com_err
	PROTOTYPE((krb5_context));

krb5_error_code princ_exists
	PROTOTYPE((krb5_context, 
		   krb5_principal, 
		   krb5_db_entry *));

krb5_error_code adm_enter_pwd_key
	PROTOTYPE((krb5_context,
   		   char * ,
    		   char * ,
    		   krb5_const_principal ,
    		   krb5_const_principal ,
    		   int ,
    		   int ,
    		   char * ,
    		   krb5_db_entry * ));

krb5_error_code adm5_change
	PROTOTYPE((krb5_context,
		   krb5_auth_context,
	    	   char *,
    		   krb5_principal));

int adm5_listen_and_process
	PROTOTYPE((krb5_context,
	    	   const char *));

krb5_error_code adm5_kpasswd
	PROTOTYPE((krb5_context,
		   krb5_auth_context,
    		   char *,
    		   kadmin_requests *,
    		   char *,
    		   int *));

#endif /* __ADM_EXTERN__ */

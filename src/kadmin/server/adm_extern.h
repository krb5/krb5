/*
 * $Source$
 * $Author$
 * $Id$
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

#include <krb5/copyright.h>

#ifndef __ADM_EXTERN__
#define __ADM_EXTERN__

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

extern volatile int signal_requests_exit;
extern char *dbm_db_name;

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
extern int recv_seqno;

extern int exit_now;

extern krb5_data inbuf;
extern krb5_data msg_data;

extern char *oper_type[];
extern char *ksrvutil_message[];
extern char *kadmind_general_response[];
extern char *kadmind_kpasswd_response[];
extern char *kadmind_ksrvutil_response[];
extern char *kadmind_kadmin_response[];


#endif /* __ADM_EXTERN__ */

/*
 * lib/krb4/krb4int.h
 *
 * Copyright 2001-2002, 2007 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * A series of private prototypes that we are not exporting but should
 * be available for self consistancy in the library.
 */

#include "port-sockets.h"

/* ad_print.c */
void ad_print(AUTH_DAT *x);

/* fgetst.c */
int fgetst(FILE *, char *, int);

/* getst.c */
int getst(int, char *, int);

/* g_cnffile.c */
FILE *krb__get_realmsfile(void);

FILE *krb__get_cnffile(void);

/* g_svc_in_tkt.c */
int krb_svc_init(char *, char *, char *, int, char *, char *);
int krb_svc_init_preauth(char *, char *, char *, int, char *, char *);

int krb_get_svc_in_tkt_preauth(char *, char *, char *, char *, char *, int, char *);

/* gethostname.c */
int k_gethostname(char *, int);

/* g_in_tkt.c */
int krb_get_in_tkt_preauth_creds(char *, char *, char *,
				 char *, char *, int,
				 key_proc_type, decrypt_tkt_type,
				 char *, char *, int, CREDENTIALS *, KRB_UINT32 *);

/* klog.c */
void kset_logfile(char *);

/* log.c */
void krb_log(const char *, ...)
#if !defined(__cplusplus) && (__GNUC__ > 2)
    __attribute__((__format__(__printf__, 1, 2)))
#endif
    ;

void krb_set_logfile(char *);

/* month_sname.c */
const char * month_sname(int);

/* password_to_key.c */
key_proc_type *krb_get_keyprocs (key_proc_type keyproc);
int KRB5_CALLCONV mit_passwd_to_key(char *user, char *instance, char *realm, 
				    char *passwd, C_Block key);
int KRB5_CALLCONV krb5_passwd_to_key(char *user, char *instance, char *realm,
				     char *passwd, C_Block key);
int KRB5_CALLCONV afs_passwd_to_key(char *user, char *instance, char *realm,
				    char *passwd, C_Block key);

/* rd_preauth.c */
#ifdef KRB_DB_DEFS
int krb_rd_preauth(KTEXT, char *, int, Principal *, des_cblock);
#endif

/* sendauth.c */
int krb_net_rd_sendauth(int, KTEXT, KRB4_32 *);

/* stime.c */
char *krb_stime(long *);

/* tf_util.c */
int tf_save_cred(char *, char *, char *, C_Block, int , int, KTEXT, KRB4_32);


/* unix_glue.c */
int krb_start_session(char *);

int krb_end_session(char *);

#ifndef _WIN32
/* For windows users, these are defined in krb.h */
char *krb_get_default_user (void);

int krb_set_default_user (char *);
#endif

/* RealmConfig-glue.c */
int krb_get_kpasswdhst(char *, char *, int);

/* err_txt.c */
void krb4int_et_init(void);
void krb4int_et_fini(void);

int krb4int_save_credentials_addr(
    char *, char *, char *, C_Block, int, int, KTEXT, KRB4_32, KRB_UINT32);

int krb4int_send_to_kdc_addr(KTEXT, KTEXT, char *,
			     struct sockaddr *, socklen_t *);

/* 
 * Exported by libdes425 and called by krb_get_in_pw_tkt, but not part of
 * the standard DES interface and therefore not prototyped in des.h.
 */
int KRB5_CALLCONV des_read_pw_string(char *, int, char *, int);

/*
 * include/kerberosIV/krb4-proto.h
 *
 * Copyright 1991, 1994 by the Massachusetts Institute of Technology.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Kerberos V4 prototypes
 */

#ifndef _KRB4_PROTO_H__
#define _KRB4_PROTO_H__

#ifndef P_TYPE_
#if defined(__STDC__) && !defined(KRB5_NO_PROTOTYPES)
# define	P_TYPE_(s) s
#else
# define P_TYPE_(s) ()
#endif
#endif /* P_TYPE_ */

/* add_ticket.c */
int add_ticket P_TYPE_((KTEXT , int , char *, int , char *, char *, char *, int , KTEXT ));

/* cr_err_reply.c */
void cr_err_reply P_TYPE_((KTEXT , char *, char *, char *, u_long , u_long , char *));

/* create_auth_reply.c */
KTEXT create_auth_reply P_TYPE_((char *, char *, char *, long , int , unsigned long , int , KTEXT ));

/* create_ciph.c */
int create_ciph P_TYPE_((KTEXT , C_Block , char *, char *, char *, unsigned long , int , KTEXT , unsigned long , C_Block ));

/* create_death_packet.c */
KTEXT krb_create_death_packet P_TYPE_((char *));

/* create_ticket.c */
int krb_create_ticket P_TYPE_((KTEXT , unsigned int , char *, char *, char *, long , char *, int , long , char *, char *, C_Block ));

/* debug_decl.c */

/* decomp_ticket.c */
int decomp_ticket P_TYPE_((KTEXT , unsigned char *, char *, char *, char *, unsigned KRB4_32 *, C_Block , int *, unsigned KRB4_32 *, char *, char *, C_Block , Key_schedule ));

/* dest_tkt.c */
int dest_tkt P_TYPE_((void ));

/* extract_ticket.c */
int extract_ticket P_TYPE_((KTEXT , int , char *, int *, int *, char *, KTEXT ));

/* fgetst.c */
int fgetst P_TYPE_((FILE *, char *, int ));

/* get_ad_tkt.c */
int get_ad_tkt P_TYPE_((char *, char *, char *, int ));

/* get_admhst.c */
int krb_get_admhst P_TYPE_((char *, char *, int ));

/* get_cred.c */
int krb_get_cred P_TYPE_((char *, char *, char *, CREDENTIALS *));

/* get_in_tkt.c */
int krb_get_pw_in_tkt P_TYPE_((char *, char *, char *, char *, char *, int , char *));
int placebo_read_password P_TYPE_((des_cblock *, char *, int ));
int placebo_read_pw_string P_TYPE_((char *, int , char *, int ));

/* get_krbhst.c */
int krb_get_krbhst P_TYPE_((char *, char *, int ));

/* get_krbrlm.c */
int krb_get_lrealm P_TYPE_((char *, int ));

/* get_phost.c */
char *krb_get_phost P_TYPE_((char *));

/* get_pw_tkt.c */
int get_pw_tkt P_TYPE_((char *, char *, char *, char *));

/* get_request.c */
int get_request P_TYPE_((KTEXT , int , char **, char **));

/* get_svc_in_tkt.c */
int krb_get_svc_in_tkt P_TYPE_((char *, char *, char *, char *, char *, int , char *));

/* get_tf_fullname.c */
int krb_get_tf_fullname P_TYPE_((char *, char *, char *, char *));

/* get_tf_realm.c */
int krb_get_tf_realm P_TYPE_((char *, char *));

#if 0    
/* getopt.c */
int getopt P_TYPE_((int , char **, char *));
#endif

/* getrealm.c */
char *krb_realmofhost P_TYPE_((char *));

/* getst.c */
int getst P_TYPE_((int , char *, int ));

/* in_tkt.c */
int in_tkt P_TYPE_((char *, char *));

/* k_gethostname.c */
int k_gethostname P_TYPE_((char *, int ));

/* klog.c */
char *klog P_TYPE_((int , char *, char * , char * , char * , char * , char * , char * , char * , char * , char * , char * ));
int kset_logfile P_TYPE_((char *));

/* kname_parse.c */
int kname_parse P_TYPE_((char *, char *, char *, char *));
int k_isname P_TYPE_((char *));
int k_isinst P_TYPE_((char *));
int k_isrealm P_TYPE_((char *));

/* kntoln.c */
int krb_kntoln P_TYPE_((AUTH_DAT *, char *));

/* krb_err_txt.c */

/* krb_get_in_tkt.c */
int krb_get_in_tkt P_TYPE_((char *, char *, char *, char *, char *, int , int (*key_proc )(), int (*decrypt_proc )(), char *));

/* kuserok.c */
int kuserok P_TYPE_((AUTH_DAT *, char *));

/* log.c */
void log P_TYPE_((char *, int , int , int , int , int , int , int , int , int , int ));
int set_logfile P_TYPE_((char *));
int new_log P_TYPE_((long , char *));

/* mk_err.c */
long krb_mk_err P_TYPE_((u_char *, long , char *));

/* mk_priv.c */
long krb_mk_priv P_TYPE_((u_char *, u_char *, u_long , Key_schedule , C_Block , struct sockaddr_in *, struct sockaddr_in *));

/* mk_req.c */
int krb_mk_req P_TYPE_((KTEXT , char *, char *, char *, long ));
int krb_set_lifetime P_TYPE_((int ));

/* mk_safe.c */
long krb_mk_safe P_TYPE_((u_char *, u_char *, u_long , C_Block *, struct sockaddr_in *, struct sockaddr_in *));

/* month_sname.c */
char *month_sname P_TYPE_((int ));

/* netread.c */
int krb_net_read P_TYPE_((int , char *, int ));

/* netwrite.c */
int krb_net_write P_TYPE_((int , char *, int ));

/* one.c */

/* pkt_cipher.c */
KTEXT pkt_cipher P_TYPE_((KTEXT ));

/* pkt_clen.c */
int pkt_clen P_TYPE_((KTEXT ));

/* rd_err.c */
int krb_rd_err P_TYPE_((u_char *, u_long , long *, MSG_DAT *));

/* rd_priv.c */
long krb_rd_priv P_TYPE_((u_char *, u_long , Key_schedule , C_Block *, struct sockaddr_in *, struct sockaddr_in *, MSG_DAT *));

/* rd_req.c */
int krb_set_key P_TYPE_((char *, int ));
int krb_rd_req P_TYPE_((KTEXT , char *, char *, unsigned KRB4_32 , AUTH_DAT *, char *));

/* rd_safe.c */
long krb_rd_safe P_TYPE_((u_char *, u_long , C_Block *, struct sockaddr_in *, struct sockaddr_in *, MSG_DAT *));

/* read_service_key.c */
int read_service_key P_TYPE_((char *, char *, char *, int , char *, char *));

/* recvauth.c */
int krb_recvauth P_TYPE_((long , int , KTEXT , char *, char *, struct sockaddr_in *, struct sockaddr_in *, AUTH_DAT *, char *, Key_schedule , char *));

/* save_credentials.c */
int krb_save_credentials P_TYPE_((char *, char *, char *, C_Block , int , int , KTEXT , long ));

/* send_to_kdc.c */
int send_to_kdc P_TYPE_((KTEXT , KTEXT , char *));

/* sendauth.c */
int krb_sendauth P_TYPE_((long , int , KTEXT , char *, char *, char *, u_long , MSG_DAT *, CREDENTIALS *, Key_schedule , struct sockaddr_in *, struct sockaddr_in *, char *));
int krb_sendsvc P_TYPE_((int , char *));

#if 0    
/* setenv.c */
/* int setenv P_TYPE_((char *, char *, int )); -- is also in telnetd/local-proto.h */
void unsetenv P_TYPE_((char *));
char *getenv P_TYPE_((char *));
char *_findenv P_TYPE_((char *, int *));
#endif

/* stime.c */
char *krb_stime P_TYPE_((long *));

/* tf_shm.c */
int krb_shm_create P_TYPE_((char *));
int krb_is_diskless P_TYPE_((void ));
int krb_shm_dest P_TYPE_((char *));

/* tf_util.c */
int tf_init P_TYPE_((char *, int ));
int tf_get_pname P_TYPE_((char *));
int tf_get_pinst P_TYPE_((char *));
int tf_get_cred P_TYPE_((CREDENTIALS *));
int tf_close P_TYPE_((void ));
int tf_save_cred P_TYPE_((char *, char *, char *, C_Block , int , int , KTEXT , long ));

/* tkt_string.c */
char *tkt_string P_TYPE_((void ));
void krb_set_tkt_string P_TYPE_((char *));

/* util.c */
int ad_print P_TYPE_((AUTH_DAT *));
int placebo_cblock_print P_TYPE_((des_cblock ));

#endif /*  _KRB4_PROTO_H__ */

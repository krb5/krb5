/* A series of private prototypes that we are not exporting but should
 * be available for self consistancy in the library.
 */

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

/* klog.c */
void kset_logfile(char *);

/* log.c */
void krb_log(const char *, ...);

void krb_set_logfile(char *);

/* mk_req.c */
int krb_set_lifetime(int);

/* month_sname.c */
const char * month_sname(int);

/* rd_preauth.c */
#ifdef KRB_DB_DEFS
int krb_rd_preauth(KTEXT, char *, int, Principal *, des_cblock);
#endif

/* sendauth.c */
int krb_net_rd_sendauth(int, KTEXT, char *);

/* stime.c */
char *krb_stime(long *);

/* tf_util.c */
int tf_save_cred(char *, char *, char *, C_Block, int , int, KTEXT, long);

/* unix_glue.c */
int krb_start_session(char *);

int krb_end_session(char *);

#ifndef _WINDOWS
/* For windows users, these are defined in krb.h */
char *krb_get_default_user (void);

int krb_set_default_user (char *);
#endif




/* A series of private prototypes that we are not exporting but should
 * be available for self consistancy in the library.
 */

/* getst.c */
int getst(int, char *, int);

/* tf_util.c */
int tf_save_cred(char *, char *, char *, C_Block, int , int, KTEXT, long);

/* g_cnffile.c */
FILE *krb__get_realmsfile(void);

FILE *krb__get_cnffile(void);

/* gethostname.c */
int k_gethostname(char *, int);


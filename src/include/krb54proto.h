/*
 * Kerberos V 5/4 prototypes
 */

extern krb5_error_code krb54_get_service_keyblock
	PROTOTYPE((char FAR *service, char FAR *instance, char FAR *realm,
		   int kvno, char FAR *file,
		   krb5_keyblock FAR * keyblock));
extern int decomp_tkt_krb5
	PROTOTYPE((KTEXT tkt, unsigned char *flags, char *pname,
		   char *pinstance, char *prealm, KRB5_K4_U32 *paddress,
		   des_cblock session, int *life, KRB5_K4_U32 *time_sec, 
		   char *sname, char *sinstance, krb5_keyblock *k5key));
extern int krb_set_key_krb5
	PROTOTYPE ((krb5_context ctx, krb5_keyblock *key));
void krb_clear_key_krb5
	PROTOTYPE ((krb5_context ctx));


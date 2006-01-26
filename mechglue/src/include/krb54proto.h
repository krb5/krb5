/*
 * Kerberos V 5/4 prototypes
 */

extern krb5_error_code krb54_get_service_keyblock
	(char *service, char *instance, char *realm,
		   int kvno, char *file,
		   krb5_keyblock * keyblock);
extern int decomp_tkt_krb5
	(KTEXT tkt, unsigned char *flags, char *pname,
		   char *pinstance, char *prealm, unsigned KRB4_32 *paddress,
		   des_cblock session, int *life, unsigned KRB4_32 *time_sec, 
		   char *sname, char *sinstance, krb5_keyblock *k5key);
extern int krb_set_key_krb5
	(krb5_context ctx, krb5_keyblock *key);
void krb_clear_key_krb5
	(krb5_context ctx);


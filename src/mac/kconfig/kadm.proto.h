/*
 * kadm.c
 */
extern int kerberos_changepw(char *name, char *password, char *new, char **reason);
extern int kadm_cli_send(unsigned char *st_dat, int st_siz, char *uname, char *uinstance, char *urealm);
extern paktype *krb_ask_tcp(paktype *pak, char *realm, tcprequest *tcprequest);
extern void krb_parse_principal(char *user, char *uname, char *uinst, char *urealm);
extern int krb_build_ap(char *cp, CREDENTIALS *cr, char *srealm, long checksum);
extern Boolean tcp_open(tcprequest *tcprequest);
extern void tcp_close(tcprequest *tcprequest);
extern Boolean tcp_transmit(tcprequest *tcprequest);
extern Boolean tcp_startread(tcprequest *tcprequest);
extern void tcp_readdone(void);
extern void tcp_freerequest(tcprequest *request);
extern paktype *newpaktype(int len);
extern void disposepak(paktype *pak);
extern void *stringcopy(void *dst, void *src);
extern int ustrcmp(char *src, char *dst);
extern long krb_mk_priv(unsigned char *in, unsigned char *out, unsigned long length, des_key_schedule schedule, C_Block key, struct tcprequest *tcprequest);
extern long krb_rd_priv(unsigned char *in, unsigned long in_length, Key_schedule schedule, C_Block key, struct tcprequest *tcprequest, MSG_DAT *m_data);
extern unsigned long lookupaddr(char *hostname);
extern pascal void dnsDone(struct hostInfo *info, char *userdata);

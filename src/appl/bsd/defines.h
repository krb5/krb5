#define OPTS_FORWARD_CREDS           0x00000020
#define OPTS_FORWARDABLE_CREDS       0x00000010
#define RCMD_BUFSIZ	5120

extern int kcmd (int *sock, char **ahost, int /* u_short */ rport,
		 char *locuser, char *remuser, char *cmd,
		 int *fd2p, char *service, char *realm,
		 krb5_creds **cred,
		 krb5_int32 *seqno, krb5_int32 *server_seqno,
		 struct sockaddr_in *laddr,
		 struct sockaddr_in *faddr,
		 krb5_auth_context *authconp,
		 krb5_flags authopts,
		 int anyport, int suppress_err);

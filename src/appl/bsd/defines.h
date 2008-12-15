#define OPTS_FORWARD_CREDS           0x00000020
#define OPTS_FORWARDABLE_CREDS       0x00000010
#define RCMD_BUFSIZ	5120

enum kcmd_proto {
  /* Old protocol: DES encryption only.  No subkeys.  No protection
     for cleartext length.  No ivec supplied.  OOB hacks used for
     rlogin.  Checksum may be omitted at connection startup.  */
  KCMD_OLD_PROTOCOL = 1,
  /* New protocol: Any encryption scheme.  Client-generated subkey
     required.  Prepend cleartext-length to cleartext data (but don't
     include it in count).  Starting ivec defined, chained.  In-band
     signalling.  Checksum required.  */
  KCMD_NEW_PROTOCOL,
  /* Hack: Get credentials, and use the old protocol iff the session
     key type is single-DES.  */
  KCMD_PROTOCOL_COMPAT_HACK,
  /* Using Kerberos version 4.  */
  KCMD_V4_PROTOCOL,
  /* ??? */
  KCMD_UNKNOWN_PROTOCOL
};

extern int kcmd (int *sock, char **ahost, int /* u_short */ rport,
		 char *locuser, char *remuser, char *cmd,
		 int *fd2p, char *service, char *realm,
		 krb5_creds **cred,
		 krb5_int32 *seqno, krb5_int32 *server_seqno,
		 struct sockaddr_in *laddr,
		 struct sockaddr_in *faddr,
		 krb5_auth_context *authconp,
		 krb5_flags authopts,
		 int anyport, int suppress_err,
		 enum kcmd_proto *protonum /* input and output */
		 );

extern int rcmd_stream_read (int fd, char *buf, size_t len, int secondary);
extern int rcmd_stream_write (int fd, char *buf, size_t len, int secondary);
extern int getport (int * /* portnum */, int * /* addrfamily */);

extern void rcmd_stream_init_krb5 (krb5_keyblock *in_keyblock,
				   int encrypt_flag, int lencheck,
				   int am_client, enum kcmd_proto protonum);

extern void rcmd_stream_init_normal(void);

#ifndef HAVE_STRSAVE
extern char *strsave(const char *sp);
#endif

krb5_error_code rd_and_store_for_creds(krb5_context context, 
				       krb5_auth_context auth_context,
				       krb5_data *inbuf, krb5_ticket *ticket,
				       krb5_ccache *ccache);


int princ_maps_to_lname(krb5_principal principal, char *luser);
int default_realm(krb5_principal principal);

#ifdef NEED_SETENV
extern int setenv(char *, char *, int);
#endif

#include "fake-addrinfo.h"

#ifdef KRB_DEFS
krb5_error_code krb5_compat_recvauth(krb5_context, krb5_auth_context *,
				     krb5_pointer, char *, krb5_principal, 
				     krb5_int32, krb5_keytab,
				     krb5_int32, char *, char *,
				     struct sockaddr_in *, 
				     struct sockaddr_in *, char *,
				     krb5_ticket **, krb5_int32 *, 
				     AUTH_DAT **, Key_schedule, char *);

krb5_error_code
krb5_compat_recvauth_version(krb5_context, krb5_auth_context *,
			     krb5_pointer, krb5_principal, krb5_int32, 
			     krb5_keytab, krb5_int32, char *, char *,
			     struct sockaddr_in *, struct sockaddr_in *,
			     char *, krb5_ticket **, krb5_int32*, 
			     AUTH_DAT **,  Key_schedule, krb5_data *);
#endif

#include "port-sockets.h"

/* krbports.h -- fallback port numbers in case /etc/services isn't changed */
/* used by: appl/bsd/rcp.c, rlogin.c, rsh.c, knetd.c
            kadmin/kadm_ser_wrap.c, lib/kadm/kadm_cli_wrap.c
	    lib/krb/send_to_kdc.c
	    movemail/movemail.c, pfrom/popmail.c
	    server/kerberos.c, slave/kprop.c, kpropd.c
*/

#define KRB_SHELL_PORT 544
#define UCB_SHELL_PORT 514

#define KLOGIN_PORT 543
#define EKLOGIN_PORT 2105
#define UCB_LOGIN_PORT 513

#define KADM_PORT 751
#define KERBEROS_PORT 750
#define KERBEROS_SEC_PORT 88
#define KRB_PROP_PORT 754

#define KPOP_PORT 1109
#define POP3_PORT 110

#define KNETD_PORT 2053

/* already in rkinit_private.h */
#define RKINIT_PORT 2108

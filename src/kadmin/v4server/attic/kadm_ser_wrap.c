/*
 * $Source$
 * $Author$
 *
 * Copyright 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * Kerberos administration server-side support functions
 */

#ifndef	lint
static char rcsid_module_c[] =
"$Header$";
#endif	lint

#include <mit-copyright.h>
/* 
kadm_ser_wrap.c
unwraps wrapped packets and calls the appropriate server subroutine
*/

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/socket.h>
#include <krb.h>
#include <kadm.h>
#include <kadm_err.h>
#include <krb_err.h>
#include <syslog.h>
#include "kadm_server.h"

#ifdef OVSEC_KADM
#include <ovsec_admin/admin.h>
extern void *ovsec_handle;
#endif

Kadm_Server server_parm;

/* 
kadm_ser_init
set up the server_parm structure
*/
kadm_ser_init(inter, realm)
    int inter;			/* interactive or from file */
    char realm[];
{
    struct servent *sep;
    struct hostent *hp;
    char hostname[MAXHOSTNAMELEN];
    char *mkey_name;
    krb5_error_code retval;
    int numfound = 1;
    krb5_boolean more;
    krb5_db_entry master_entry;
    
    if (gethostname(hostname, sizeof(hostname)))
	return KADM_NO_HOSTNAME;
    
    (void) strcpy(server_parm.sname, PWSERV_NAME);
    (void) strcpy(server_parm.sinst, KRB_MASTER);
    (void) strcpy(server_parm.krbrlm, realm);
    if (krb5_build_principal(&server_parm.sprinc,
			     strlen(realm),
			     realm,
			     PWSERV_NAME,
			     KRB_MASTER, 0))
	return KADM_NO_MAST;

    /* setting up the addrs */
    server_parm.admin_fd = -1;
    if ((sep = getservbyname(KADM_SNAME, "tcp")) == NULL)
	return KADM_NO_SERV;
    memset((char *)&server_parm.admin_addr, 0,sizeof(server_parm.admin_addr));
    server_parm.admin_addr.sin_family = AF_INET;
    if ((hp = gethostbyname(hostname)) == NULL)
	return KADM_NO_HOSTNAME;
    memcpy((char *) &server_parm.admin_addr.sin_addr.s_addr, hp->h_addr,
	   hp->h_length);
    server_parm.admin_addr.sin_port = sep->s_port;

    /* setting up the database */
    mkey_name = KRB5_KDB_M_NAME;
    server_parm.master_keyblock.keytype = KEYTYPE_DES;
#ifdef PROVIDE_DES_CBC_CRC
#ifdef KRB5B4
    server_parm.master_encblock.crypto_entry = krb5_des_cst_entry.system;
#else
    server_parm.master_encblock.crypto_entry = &mit_des_cryptosystem_entry;
#endif /* KRB5B4 */
#else
    error(You gotta figure out what cryptosystem to use in the KDC);
#endif
    retval = krb5_db_setup_mkey_name(mkey_name, realm, (char **) 0,
				     &server_parm.master_princ);
    if (retval)
	return KADM_NO_MAST;
    krb5_db_fetch_mkey(server_parm.master_princ,
		       &server_parm.master_encblock,
		       (inter == 1), FALSE, NULL,
		       &server_parm.master_keyblock);
    if (retval)
	return KADM_NO_MAST;
    retval = krb5_db_verify_master_key(server_parm.master_princ,
				       &server_parm.master_keyblock,
				       &server_parm.master_encblock);
    if (retval)
	return KADM_NO_VERI;
    retval = krb5_process_key(&server_parm.master_encblock,
			      &server_parm.master_keyblock);
    if (retval)
	return KADM_NO_VERI;

    retval = krb5_db_get_principal(server_parm.master_princ,
				   &master_entry, &numfound, &more);
    if (retval || more || !numfound)
	return KADM_NO_VERI;
    server_parm.max_life = master_entry.max_life;
    server_parm.max_rlife = master_entry.max_renewable_life;
    server_parm.expiration = master_entry.expiration;
    server_parm.mkvno = master_entry.kvno;
    /* don't set flags, as master has some extra restrictions
       (??? quoted from kdb_edit.c) */
    krb5_db_free_principal(&master_entry, numfound);
    return KADM_SUCCESS;
}


static void errpkt(dat, dat_len, code)
u_char **dat;
int *dat_len;
int code;
{
    krb4_uint32 retcode;
    char *pdat;

    free((char *)*dat);			/* free up req */
    *dat_len = KADM_VERSIZE + sizeof(krb4_uint32);
    *dat = (u_char *) malloc((unsigned)*dat_len);
    if (!(*dat)) {
	syslog(LOG_ERR, "malloc(%d) returned null while in errpkt!", *dat_len);
	abort();
    }
    pdat = (char *) *dat;
    retcode = htonl((krb4_uint32) code);
    (void) strncpy(pdat, KADM_ULOSE, KADM_VERSIZE);
    memcpy(&pdat[KADM_VERSIZE], (char *)&retcode, sizeof(krb4_uint32));
    return;
}

/*
kadm_ser_in
unwrap the data stored in dat, process, and return it.
*/
kadm_ser_in(dat,dat_len)
u_char **dat;
int *dat_len;
{
    u_char *in_st;			/* pointer into the sent packet */
    int in_len,retc;			/* where in packet we are, for
					   returns */
    krb4_uint32 r_len;			/* length of the actual packet */
    KTEXT_ST authent;			/* the authenticator */
    AUTH_DAT ad;			/* who is this, klink */
    krb4_uint32 ncksum;			/* checksum of encrypted data */
    des_key_schedule sess_sched;	/* our schedule */
    MSG_DAT msg_st;
    u_char *retdat, *tmpdat;
    int retval, retlen;

    if (strncmp(KADM_VERSTR, (char *)*dat, KADM_VERSIZE)) {
	errpkt(dat, dat_len, KADM_BAD_VER);
	return KADM_BAD_VER;
    }
    in_len = KADM_VERSIZE;
    /* get the length */
    if ((retc = stv_long(*dat, &r_len, in_len, *dat_len)) < 0)
	return KADM_LENGTH_ERROR;
    in_len += retc;
    authent.length = *dat_len - r_len - KADM_VERSIZE - sizeof(krb4_uint32);
    memcpy((char *)authent.dat, (char *)(*dat) + in_len, authent.length);
    authent.mbz = 0;
    /* service key should be set before here */
    if (retc = krb_rd_req(&authent, server_parm.sname, server_parm.sinst,
			  server_parm.recv_addr.sin_addr.s_addr, &ad, (char *)0))
    {
	errpkt(dat, dat_len,retc + krb_err_base);
	return retc + krb_err_base;
    }

#define clr_cli_secrets() {memset((char *)sess_sched, 0, sizeof(sess_sched)); memset((char *)ad.session, 0, sizeof(ad.session));}

    in_st = *dat + *dat_len - r_len;
#ifdef NOENCRYPTION
    ncksum = 0;
#else
    ncksum = quad_cksum((des_cblock *)in_st, (des_cblock *)0, (krb4_int32) r_len, 0,
			(des_cblock *)ad.session);
#endif
    if (ncksum!=ad.checksum) {		/* yow, are we correct yet */
	clr_cli_secrets();
	errpkt(dat, dat_len,KADM_BAD_CHK);
	return KADM_BAD_CHK;
    }
#ifdef NOENCRYPTION
    memset(sess_sched, 0, sizeof(sess_sched));
#else
    des_key_sched(ad.session, sess_sched);
#endif
    if (retc = (int) krb_rd_priv(in_st, r_len, sess_sched, ad.session, 
				 &server_parm.recv_addr,
				 &server_parm.admin_addr, &msg_st)) {
	clr_cli_secrets();
	errpkt(dat, dat_len,retc + krb_err_base);
	return retc + krb_err_base;
    }
    switch (msg_st.app_data[0]) {
    case CHANGE_PW:
	retval = kadm_ser_cpw(msg_st.app_data+1,(int) msg_st.app_length,&ad,
			      &retdat, &retlen);
	break;
#ifndef OVSEC_KADM
    case ADD_ENT:
	retval = kadm_ser_add(msg_st.app_data+1,(int) msg_st.app_length,&ad,
			      &retdat, &retlen);
	break;
    case GET_ENT:
	retval = kadm_ser_get(msg_st.app_data+1,(int) msg_st.app_length,&ad,
			      &retdat, &retlen);
	break;
    case MOD_ENT:
	retval = kadm_ser_mod(msg_st.app_data+1,(int) msg_st.app_length,&ad,
			      &retdat, &retlen);
	break;
    case CHECK_PW:
	retval = kadm_ser_ckpw(msg_st.app_data+1,(int) msg_st.app_length,&ad,
			       &retdat, &retlen);
	break;
    case CHG_STAB:
	retval = kadm_ser_stab(msg_st.app_data+1,(int) msg_st.app_length,&ad,
			       &retdat, &retlen);
	break;
#endif /* OVSEC_KADM */
    default:
	clr_cli_secrets();
	errpkt(dat, dat_len, KADM_NO_OPCODE);
	return KADM_NO_OPCODE;
    }
    /* Now seal the response back into a priv msg */
    free((char *)*dat);
    tmpdat = (u_char *) malloc((unsigned)(retlen + KADM_VERSIZE +
					  sizeof(krb4_uint32)));
    if (!tmpdat) {
	clr_cli_secrets();
	syslog(LOG_ERR, "malloc(%d) returned null while in kadm_ser_in!",
	    retlen + KADM_VERSIZE + sizeof(krb4_uint32));
	errpkt(dat, dat_len, KADM_NOMEM);
	return KADM_NOMEM;
    }
    (void) strncpy((char *)tmpdat, KADM_VERSTR, KADM_VERSIZE);
    retval = htonl((krb4_uint32)retval);
    memcpy((char *)tmpdat + KADM_VERSIZE, (char *)&retval, sizeof(krb4_uint32));
    if (retlen) {
	memcpy((char *)tmpdat + KADM_VERSIZE + sizeof(krb4_uint32), (char *)retdat,
	       retlen);
	free((char *)retdat);
    }
    /* slop for mk_priv stuff */
    *dat = (u_char *) malloc((unsigned) (retlen + KADM_VERSIZE +
					 sizeof(krb4_uint32) + 200));
    if ((*dat_len = krb_mk_priv(tmpdat, *dat,
				(krb4_uint32) (retlen + KADM_VERSIZE +
					  sizeof(krb4_uint32)),
				sess_sched,
				ad.session, &server_parm.admin_addr,
				&server_parm.recv_addr)) < 0) {
	clr_cli_secrets();
	errpkt(dat, dat_len, KADM_NO_ENCRYPT);
	free(tmpdat);
	return KADM_NO_ENCRYPT;
    }
    clr_cli_secrets();
    free(tmpdat);
    return KADM_SUCCESS;
}

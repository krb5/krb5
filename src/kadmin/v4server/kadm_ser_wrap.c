/*
 * kadmin/v4server/kadm_ser_wrap.c
 *
 * Copyright 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * Kerberos administration server-side support functions
 */


#include <mit-copyright.h>
/* 
kadm_ser_wrap.c
unwraps wrapped packets and calls the appropriate server subroutine
*/

#include <stdio.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include "kadm_server.h"
#include <kadm.h>
#include <kadm_err.h>
#include <krb_err.h>
#include <syslog.h>

#ifdef KADM5
#include <kadm5/admin.h>
#endif

Kadm_Server server_parm;

/* 
kadm_ser_init
set up the server_parm structure
*/
#ifdef KADM5
int
kadm_ser_init(inter, realm, params)
    int inter;			/* interactive or from file */
    char realm[];
    kadm5_config_params *params;
#else
int
kadm_ser_init(inter, realm)
    int inter;			/* interactive or from file */
    char realm[];
#endif
{
    struct servent *sep;
    struct hostent *hp;
    char hostname[MAXHOSTNAMELEN];
    char *mkey_name;
    krb5_error_code retval;
    int numfound = 1;
    krb5_boolean more;
    krb5_db_entry master_entry;
    krb5_key_data *kdatap;
    
    if (gethostname(hostname, sizeof(hostname)))
	return KADM_NO_HOSTNAME;
    
    (void) strcpy(server_parm.sname, PWSERV_NAME);
    (void) strcpy(server_parm.sinst, KRB_MASTER);
    if (strlen (realm) > REALM_SZ)
	return KADM_REALM_TOO_LONG;
    (void) strncpy(server_parm.krbrlm, realm, sizeof(server_parm.krbrlm)-1);
    server_parm.krbrlm[sizeof(server_parm.krbrlm) - 1] = '\0';

    if (krb5_425_conv_principal(kadm_context, server_parm.sname,
				server_parm.sinst, server_parm.krbrlm,
				&server_parm.sprinc))
	return KADM_NO_MAST;
    server_parm.admin_fd = -1;
    /* setting up the addrs */
    if ((sep = getservbyname(KADM_SNAME, "tcp")) == NULL)
	return KADM_NO_SERV;
    memset((char *)&server_parm.admin_addr, 0,sizeof(server_parm.admin_addr));
    server_parm.admin_addr.sin_family = AF_INET;
    if ((hp = gethostbyname(hostname)) == NULL)
	return KADM_NO_HOSTNAME;
    memcpy((char *) &server_parm.admin_addr.sin_addr.s_addr, hp->h_addr,
	   sizeof(server_parm.admin_addr.sin_addr.s_addr));
    server_parm.admin_addr.sin_port = sep->s_port;
    /* setting up the database */
    mkey_name = KRB5_KDB_M_NAME;

    server_parm.master_keyblock.enctype = params->enctype;
    
    retval = krb5_db_setup_mkey_name(kadm_context, mkey_name, realm,
				     (char **) 0,
				     &server_parm.master_princ);
    if (retval)
	return KADM_NO_MAST;
    krb5_db_fetch_mkey(kadm_context, server_parm.master_princ,
		       server_parm.master_keyblock.enctype,
		       (inter == 1), FALSE,
		       params->stash_file,
		       NULL,
		       &server_parm.master_keyblock);
    if (retval)
	return KADM_NO_MAST;
    retval = krb5_db_verify_master_key(kadm_context, server_parm.master_princ,
				       &server_parm.master_keyblock);
    if (retval)
	return KADM_NO_VERI;
    retval = krb5_db_get_principal(kadm_context, server_parm.master_princ,
				   &master_entry, &numfound, &more);
    if (retval || more || !numfound)
	return KADM_NO_VERI;

    retval = krb5_dbe_find_enctype(kadm_context,
				   &master_entry,
				   -1, -1, -1,
				   &kdatap);
    if (retval)
        return KRB5_PROG_KEYTYPE_NOSUPP;
    server_parm.max_life = master_entry.max_life;
    server_parm.max_rlife = master_entry.max_renewable_life;
    server_parm.expiration = master_entry.expiration;
    server_parm.mkvno = kdatap->key_data_kvno;
    /* don't set flags, as master has some extra restrictions
       (??? quoted from kdb_edit.c) */
    krb5_db_free_principal(kadm_context, &master_entry, numfound);
    return KADM_SUCCESS;
}


static void errpkt(dat, dat_len, code)
u_char **dat;
int *dat_len;
int code;
{
    krb5_ui_4 retcode;
    char *pdat;

    free((char *)*dat);			/* free up req */
    *dat_len = KADM_VERSIZE + sizeof(krb5_ui_4);
    *dat = (u_char *) malloc((unsigned)*dat_len);
    if (!(*dat)) {
	syslog(LOG_ERR, "malloc(%d) returned null while in errpkt!", *dat_len);
	abort();
    }
    pdat = (char *) *dat;
    retcode = htonl((krb5_ui_4) code);
    (void) strncpy(pdat, KADM_ULOSE, KADM_VERSIZE);
    memcpy(&pdat[KADM_VERSIZE], (char *)&retcode, sizeof(krb5_ui_4));
    return;
}

/*
kadm_ser_in
unwrap the data stored in dat, process, and return it.
*/
int
kadm_ser_in(dat,dat_len)
u_char **dat;
int *dat_len;
{
    u_char *in_st;			/* pointer into the sent packet */
    int in_len,retc;			/* where in packet we are, for
					   returns */
    krb5_ui_4 r_len;			/* length of the actual packet */
    KTEXT_ST authent;			/* the authenticator */
    AUTH_DAT ad;			/* who is this, klink */
    krb5_ui_4 ncksum;			/* checksum of encrypted data */
    des_key_schedule sess_sched;	/* our schedule */
    MSG_DAT msg_st;
    u_char *retdat, *tmpdat;
    int retval, retlen;

    if ((*dat_len < KADM_VERSIZE + sizeof(krb5_ui_4))
	|| strncmp(KADM_VERSTR, (char *)*dat, KADM_VERSIZE)) {
	errpkt(dat, dat_len, KADM_BAD_VER);
	return KADM_BAD_VER;
    }
    in_len = KADM_VERSIZE;
    /* get the length */
    if ((retc = stv_long(*dat, &r_len, in_len, *dat_len)) < 0
	|| (r_len > *dat_len - KADM_VERSIZE - sizeof(krb5_ui_4))
	|| (*dat_len - r_len - KADM_VERSIZE -
	    sizeof(krb5_ui_4) > sizeof(authent.dat))) {
	errpkt(dat, dat_len, KADM_LENGTH_ERROR);
	return KADM_LENGTH_ERROR;
    }

    in_len += retc;
    authent.length = *dat_len - r_len - KADM_VERSIZE - sizeof(krb5_ui_4);
    memcpy((char *)authent.dat, (char *)(*dat) + in_len, authent.length);
    authent.mbz = 0;
    /* service key should be set before here */
    retc = krb_rd_req(&authent, server_parm.sname, server_parm.sinst,
		      server_parm.recv_addr.sin_addr.s_addr, &ad, (char *)0);
    if (retc)
    {
	errpkt(dat, dat_len,retc + krb_err_base);
	return retc + krb_err_base;
    }

#define clr_cli_secrets() {memset((char *)sess_sched, 0, sizeof(sess_sched)); memset((char *)ad.session, 0, sizeof(ad.session));}

    in_st = *dat + *dat_len - r_len;
#ifdef NOENCRYPTION
    ncksum = 0;
#else
    ncksum = quad_cksum(in_st, (krb5_ui_4 *)0, (long) r_len, 0, &ad.session);
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

    retc = (int) krb_rd_priv(in_st, r_len, sess_sched, &ad.session, 
			     &server_parm.recv_addr,
			     &server_parm.admin_addr, &msg_st);
    if (retc) {
	clr_cli_secrets();
	errpkt(dat, dat_len,retc + krb_err_base);
	return retc + krb_err_base;
    }
    switch (msg_st.app_data[0]) {
    case CHANGE_PW:
	retval = kadm_ser_cpw(msg_st.app_data+1,(int) msg_st.app_length,&ad,
			      &retdat, &retlen);
	break;
    case ADD_ENT:
	retval = kadm_ser_add(msg_st.app_data+1,(int) msg_st.app_length,&ad,
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
#ifndef KADM5
    case DEL_ENT:
	retval = kadm_ser_del(msg_st.app_data+1,(int) msg_st.app_length,&ad,
			      &retdat, &retlen);
	break;
#endif /* KADM5 */
    case GET_ENT:
	retval = kadm_ser_get(msg_st.app_data+1,(int) msg_st.app_length,&ad,
			      &retdat, &retlen);
	break;
    case CHG_STAB:
	retval = kadm_ser_stab(msg_st.app_data+1,(int) msg_st.app_length,&ad,
			       &retdat, &retlen);
	break;
    default:
	clr_cli_secrets();
	errpkt(dat, dat_len, KADM_NO_OPCODE);
	return KADM_NO_OPCODE;
    }
    /* Now seal the response back into a priv msg */
    free((char *)*dat);
    tmpdat = (u_char *) malloc((unsigned)(retlen + KADM_VERSIZE +
					  sizeof(krb5_ui_4)));
    if (!tmpdat) {
	clr_cli_secrets();
	syslog(LOG_ERR, "malloc(%d) returned null while in kadm_ser_in!",
	    retlen + KADM_VERSIZE + sizeof(krb5_ui_4));
	errpkt(dat, dat_len, KADM_NOMEM);
	return KADM_NOMEM;
    }
    (void) strncpy((char *)tmpdat, KADM_VERSTR, KADM_VERSIZE);
    retval = htonl((krb5_ui_4)retval);
    memcpy((char *)tmpdat + KADM_VERSIZE, (char *)&retval, sizeof(krb5_ui_4));
    if (retlen) {
	memcpy((char *)tmpdat + KADM_VERSIZE + sizeof(krb5_ui_4), (char *)retdat,
	       retlen);
	free((char *)retdat);
    }
    /* slop for mk_priv stuff */
    *dat = (u_char *) malloc((unsigned) (retlen + KADM_VERSIZE +
					 sizeof(krb5_ui_4) + 200));
    if ((*dat_len = krb_mk_priv(tmpdat, *dat,
				(u_long) (retlen + KADM_VERSIZE +
					  sizeof(krb5_ui_4)),
				sess_sched,
				&ad.session, &server_parm.admin_addr,
				&server_parm.recv_addr)) < 0) {
	clr_cli_secrets();
	errpkt(dat, dat_len, KADM_NO_ENCRYPT);
	return KADM_NO_ENCRYPT;
    }
    clr_cli_secrets();
    return KADM_SUCCESS;
}

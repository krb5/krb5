/*
 * lib/krb4/kadm_net.c
 *
 * Copyright 1988, 2002 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * Kerberos administration server client-side network access routines
 * These routines do actual network traffic, in a machine dependent manner.
 */

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include "krb5/autoconf.h"
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#define	DEFINE_SOCKADDR		/* Ask krb.h for struct sockaddr, etc */
#include "port-sockets.h"
#include "krb.h"
#include "krbports.h"
#include "kadm.h"
#include "kadm_err.h"
#include "prot.h"

/* XXX FIXME! */
#if defined(_WIN32)
	#define SIGNAL(s, f) 0
#else
	#define SIGNAL(s, f) signal(s, f)
#endif

static void clear_secrets(des_cblock sess_key, Key_schedule sess_sched);
/* XXX FIXME! */
#ifdef SIGPIPE
static krb5_sigtype (*opipe)();
#endif

/*
 * kadm_init_link
 *	receives    : principal, instance, realm
 *
 * initializes client parm, the Kadm_Client structure which holds the
 * data about the connection between the server and client, the services
 * used, the locations and other fun things
 */
int
kadm_init_link(char *principal, char *instance, char *realm,
	       Kadm_Client *client_parm, int changepw)
{
    struct servent *sep;	       /* service we will talk to */
    u_short sep_port;
    struct hostent *hop;	       /* host we will talk to */
    char adm_hostname[MAXHOSTNAMELEN];
    char *scol = 0;

    (void) strcpy(client_parm->sname, principal);
    (void) strcpy(client_parm->sinst, instance);
    (void) strcpy(client_parm->krbrlm, realm);
    client_parm->admin_fd = -1;
    client_parm->default_port = 1;

    /*
     * set up the admin_addr - fetch name of admin or kpasswd host
     * (usually the admin host is the kpasswd host unless you have
     * some sort of realm on crack)
     */
    if (changepw) {
#if 0 /* XXX */
	if (krb_get_kpasswdhst(adm_hostname, client_parm->krbrlm, 1) != KSUCCESS)
#endif
	    if (krb_get_admhst(adm_hostname, client_parm->krbrlm, 1) != KSUCCESS)
		return KADM_NO_HOST;
    } else {
	if (krb_get_admhst(adm_hostname, client_parm->krbrlm, 1) != KSUCCESS)
	    return KADM_NO_HOST;
    }
    scol = strchr(adm_hostname,':');
    if (scol) *scol = 0;
    if ((hop = gethostbyname(adm_hostname)) == NULL)
	/*
	 * couldn't find the admin servers address
	 */
	return KADM_UNK_HOST;
    if (scol) {
	sep_port = htons(atoi(scol+1));
	client_parm->default_port = 0;
    } else if ((sep = getservbyname(KADM_SNAME, "tcp")) != NULL)
	sep_port = sep->s_port;
    else
	sep_port = htons(KADM_PORT); /* KADM_SNAME = kerberos_master/tcp */
    memset(&client_parm->admin_addr, 0, sizeof(client_parm->admin_addr));
    client_parm->admin_addr.sin_family = hop->h_addrtype;
    memcpy(&client_parm->admin_addr.sin_addr, hop->h_addr, hop->h_length);
    client_parm->admin_addr.sin_port = sep_port;

    return KADM_SUCCESS;
}

/*
 * kadm_cli_send
 *	recieves   : opcode, packet, packet length, serv_name, serv_inst
 *	returns    : return code from the packet build, the server, or
 *			 something else
 *
 * It assembles a packet as follows:
 *	 8 bytes    : VERSION STRING
 *	 4 bytes    : LENGTH OF MESSAGE DATA and OPCODE
 *		    : KTEXT
 *		    : OPCODE       \
 *		    : DATA          > Encrypted (with make priv)
 *		    : ......       /
 *
 * If it builds the packet and it is small enough, then it attempts to open the
 * connection to the admin server.  If the connection is succesfully open
 * then it sends the data and waits for a reply.
 */
int
kadm_cli_send(Kadm_Client *client_parm,
	      u_char *st_dat,	/* the actual data */
	      size_t st_siz,	/* length of said data */
	      u_char **ret_dat, /* to give return info */
	      size_t *ret_siz)	/* length of returned info */
{
/* Macros for use in returning data... used in kadm_cli_send */
#define RET_N_FREE(r) {clear_secrets(sess_key, sess_sched); free((char *)act_st); free((char *)priv_pak); return r;}
#define RET_N_FREE2(r) {free((char *)*ret_dat); *ret_dat = 0; *ret_siz = 0; clear_secrets(sess_key, sess_sched); return(r);}

    int		act_len;      /* current offset into packet, return */
    KRB_INT32	retdat;		/* data */
    KTEXT_ST	authent;	/* the authenticator we will build */
    u_char	*act_st;      /* the pointer to the complete packet */
    u_char	*priv_pak;	/* private version of the packet */
    long	priv_len;	/* length of private packet */
    u_long	cksum;		/* checksum of the packet */
    MSG_DAT	mdat;
    u_char	*return_dat;
    u_char	*p;
    KRB_UINT32	uretdat;

    /* Keys for use in the transactions */
    des_cblock	sess_key;	/* to be filled in by kadm_cli_keyd */
    Key_schedule sess_sched;

    act_st = malloc(KADM_VERSIZE); /* verstr stored first */
    strncpy((char *)act_st, KADM_VERSTR, KADM_VERSIZE);
    act_len = KADM_VERSIZE;

    if ((retdat = kadm_cli_keyd(client_parm, sess_key, sess_sched)) != KADM_SUCCESS) {
	free(act_st);
	return retdat;	       /* couldnt get key working */
    }
    priv_pak = malloc(st_siz + 200);
    /* 200 bytes for extra info case */
    /* XXX Check mk_priv return type */
    if ((priv_len = krb_mk_priv(st_dat, priv_pak, (u_long)st_siz,
				sess_sched, (C_Block *)sess_key,
				&client_parm->my_addr,
				&client_parm->admin_addr)) < 0)
	RET_N_FREE(KADM_NO_ENCRYPT); /* whoops... we got a lose here */
    /*
     * here is the length of priv data.  receiver calcs size of
     * authenticator by subtracting vno size, priv size, and
     * sizeof(u_long) (for the size indication) from total size
     */
    act_len += vts_long((KRB_UINT32)priv_len, &act_st, (int)act_len);
#ifdef NOENCRYPTION
    cksum = 0;
#else
    cksum = quad_cksum(priv_pak, NULL, priv_len, 0, &sess_key);
#endif
    /* XXX cast unsigned->signed */
    if ((retdat = krb_mk_req_creds(&authent, &client_parm->creds, (long)cksum)) != NULL) {
	/* authenticator? */
	RET_N_FREE(retdat);
    }

    act_st = realloc(act_st, (unsigned) (act_len + authent.length
					    + priv_len));
    if (!act_st) {
	clear_secrets(sess_key, sess_sched);
	free(priv_pak);
	return KADM_NOMEM;
    }
    memcpy(act_st + act_len, authent.dat, authent.length);
    memcpy(act_st + act_len + authent.length, priv_pak, priv_len);
    free(priv_pak);
    if ((retdat = kadm_cli_out(client_parm, act_st,
			       act_len + authent.length + priv_len,
			       ret_dat, ret_siz)) != KADM_SUCCESS)
	RET_N_FREE(retdat);
    free(act_st);

    /* first see if it's a YOULOSE */
    if ((*ret_siz >= KADM_VERSIZE) &&
	!strncmp(KADM_ULOSE, (char *)*ret_dat, KADM_VERSIZE))
    {
	/* it's a youlose packet */
	if (*ret_siz < KADM_VERSIZE + 4)
	    RET_N_FREE2(KADM_BAD_VER);
	p = *ret_dat + KADM_VERSIZE;
	KRB4_GET32BE(uretdat, p);
	/* XXX unsigned->signed */
	retdat = (KRB_INT32)uretdat;
	RET_N_FREE2(retdat);
    }
    /* need to decode the ret_dat */
    if ((retdat = krb_rd_priv(*ret_dat, (u_long)*ret_siz, sess_sched,
			      (C_Block *)sess_key, &client_parm->admin_addr,
			      &client_parm->my_addr, &mdat)) != NULL)
	RET_N_FREE2(retdat);
    if (mdat.app_length < KADM_VERSIZE + 4)
	/* too short! */
	RET_N_FREE2(KADM_BAD_VER);
    if (strncmp((char *)mdat.app_data, KADM_VERSTR, KADM_VERSIZE))
	/* bad version */
	RET_N_FREE2(KADM_BAD_VER);
    p = mdat.app_data + KADM_VERSIZE;
    KRB4_GET32BE(uretdat, p);
    /* XXX unsigned->signed */
    retdat = (KRB_INT32)uretdat;
    if ((mdat.app_length - KADM_VERSIZE - 4) != 0) {
	if (!(return_dat =
	      malloc((unsigned)(mdat.app_length - KADM_VERSIZE - 4))))
	    RET_N_FREE2(KADM_NOMEM);
	memcpy(return_dat, p, mdat.app_length - KADM_VERSIZE - 4);
    } else {
	/* If it's zero length, still need to malloc a 1 byte string; */
	/* malloc's of zero will return NULL on AIX & A/UX */
	if (!(return_dat = malloc((unsigned) 1)))
	    RET_N_FREE2(KADM_NOMEM);
	*return_dat = '\0';
    }
    free(*ret_dat);
    clear_secrets(sess_key, sess_sched);
    *ret_dat = return_dat;
    *ret_siz = mdat.app_length - KADM_VERSIZE - 4;
    return retdat;
}

int kadm_cli_conn(Kadm_Client *client_parm)
{					/* this connects and sets my_addr */
#if 0
    int on = 1;
#endif
    if ((client_parm->admin_fd =
	 socket(client_parm->admin_addr.sin_family, SOCK_STREAM,0)) < 0)
	return KADM_NO_SOCK;		/* couldnt create the socket */
    if (SOCKET_CONNECT(client_parm->admin_fd,
		(struct sockaddr *) & client_parm->admin_addr,
		sizeof(client_parm->admin_addr))) {
	(void) SOCKET_CLOSE(client_parm->admin_fd);
	client_parm->admin_fd = -1;

        /* The V4 kadmind port number is 751.  The RFC assigned
	   number, for V5, is 749.  Sometimes the entry in
	   /etc/services on a client machine will say 749, but the
	   server may be listening on port 751.  We try to partially
	   cope by automatically falling back to try port 751 if we
	   don't get a reply on port we are using.  */
        if (client_parm->admin_addr.sin_port != htons(KADM_PORT)
	     && client_parm->default_port) {
	    client_parm->admin_addr.sin_port = htons(KADM_PORT);
	    return kadm_cli_conn(client_parm);
	}

	return KADM_NO_CONN;		/* couldnt get the connect */
    }
#ifdef SIGPIPE
    opipe = SIGNAL(SIGPIPE, SIG_IGN);
#endif
    client_parm->my_addr_len = sizeof(client_parm->my_addr);
    if (SOCKET_GETSOCKNAME(client_parm->admin_fd,
		    (struct sockaddr *) & client_parm->my_addr,
		    &client_parm->my_addr_len) < 0) {
	(void) SOCKET_CLOSE(client_parm->admin_fd);
	client_parm->admin_fd = -1;
#ifdef SIGPIPE
	(void) SIGNAL(SIGPIPE, opipe);
#endif
	return KADM_NO_HERE;		/* couldnt find out who we are */
    }
#if 0
    if (setsockopt(client_parm.admin_fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&on,
		   sizeof(on)) < 0) {
	(void) closesocket(client_parm.admin_fd);
	client_parm.admin_fd = -1;
#ifdef SIGPIPE
	(void) SIGNAL(SIGPIPE, opipe);
#endif
	return KADM_NO_CONN;		/* XXX */
    }
#endif
    return KADM_SUCCESS;
}

void kadm_cli_disconn(Kadm_Client *client_parm)
{
    (void) SOCKET_CLOSE(client_parm->admin_fd);
#ifdef SIGPIPE
    (void) SIGNAL(SIGPIPE, opipe);
#endif
    return;
}

int kadm_cli_out(Kadm_Client *client_parm, u_char *dat, int dat_len,
		 u_char **ret_dat, size_t *ret_siz)
{
    u_short		dlen;
    int			retval;
    unsigned char	buf[2], *p;

    dlen = (u_short)dat_len;
    if (dlen > 0x7fff)		/* XXX krb_net_write signedness */
	return KADM_NO_ROOM;

    p = buf;
    KRB4_PUT16BE(p, dlen);
    if (krb_net_write(client_parm->admin_fd, (char *)buf, 2) < 0)
	return SOCKET_ERRNO;	/* XXX */

    if (krb_net_write(client_parm->admin_fd, (char *)dat, (int)dat_len) < 0)
	return SOCKET_ERRNO;	/* XXX */

    retval = krb_net_read(client_parm->admin_fd, (char *)buf, 2);
    if (retval != 2) {
	if (retval < 0)
	    return SOCKET_ERRNO; /* XXX */
	else
	    return EPIPE;	/* short read ! */
    }

    p = buf;
    KRB4_GET16BE(dlen, p);
    if (dlen > INT_MAX)		/* XXX krb_net_read signedness */
	return KADM_NO_ROOM;
    *ret_dat = malloc(dlen);
    if (!*ret_dat)
	return KADM_NOMEM;

    retval = krb_net_read(client_parm->admin_fd, (char *)*ret_dat, (int)dlen);
    if (retval != dlen) {
	if (retval < 0)
	    return SOCKET_ERRNO; /* XXX */
	else
	    return EPIPE;	/* short read ! */
    }
    *ret_siz = dlen;
    return KADM_SUCCESS;
}

static void
clear_secrets(des_cblock sess_key, Key_schedule sess_sched)
{
    memset(sess_key, 0, sizeof(sess_key));
    memset(sess_sched, 0, sizeof(sess_sched));
    return;
}

/* takes in the sess_key and key_schedule and sets them appropriately */
int kadm_cli_keyd(Kadm_Client *client_parm,
		  des_cblock s_k, des_key_schedule s_s)
{
    int stat;

    memcpy(s_k, client_parm->creds.session, sizeof(des_cblock));
    stat = key_sched(s_k, s_s);
    if (stat)
	return stat;
    return KADM_SUCCESS;
}				       /* This code "works" */

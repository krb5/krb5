/*
 * lib/krb5/krb/compat_recv.c
 *
 * Copyright 1993 by the Massachusetts Institute of Technology.
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
 *
 * convenience sendauth/recvauth functions, with compatibility with V4
 * recvauth.
 *
 * NOTE: linking in this function will pull in V4 kerberos routines.
 *
 * WARNING: In the V4-style arguments, the ticket and kdata arguments
 * have different types than the V4 recvauth; in V4, they were KTEXT
 * and AUTH_DAT *, respectively.  Here, they are KTEXT * and AUTH_DAT **
 * and they are allocated by recvauth if and only if we end up talking
 * to a V4 sendauth.
 */

#define NEED_SOCKETS
#include "k5-int.h"
#if !defined(_MACINTOSH)
#ifdef KRB5_KRB4_COMPAT
#include <kerberosIV/krb.h>
#endif
#include "com_err.h"
#include <errno.h>

#include <stdio.h>
#include <string.h>

#include "defines.h"

#ifdef KRB5_KRB4_COMPAT
static int krb_v4_recvauth(long options, int fd, KTEXT ticket,
			   char *service, char *instance, 
			   struct sockaddr_in *faddr,
			   struct sockaddr_in *laddr,
			   AUTH_DAT *kdata,
			   char *filename,
			   Key_schedule schedule,
			   char *version);
#endif

#define	KRB_V4_SENDAUTH_VERS	"AUTHV0.1" /* MUST be 8 chars long */
#define KRB_V5_SENDAUTH_VERS	"KRB5_SENDAUTH_V1.0"

#define KRB5_RECVAUTH_V4	4
#define KRB5_RECVAUTH_V5	5

#ifdef KRB5_KRB4_COMPAT
krb5_error_code
krb5_compat_recvauth(context, auth_context,
	             /* IN */
		     fdp, appl_version, server, flags, keytab,
		     v4_options, v4_service, v4_instance, v4_faddr, v4_laddr,
		     v4_filename, 
		     /* OUT */
		     ticket,
		     auth_sys, v4_kdata, v4_schedule, v4_version)
    krb5_context context;
    krb5_auth_context  *auth_context;
	krb5_pointer	fdp;
	char	*appl_version;
	krb5_principal	server;
	krb5_int32	flags;
	krb5_keytab    	keytab;
	krb5_ticket  ** ticket;
        krb5_int32      *auth_sys;

	/*
	 * Version 4 arguments
	 */
	krb5_int32 v4_options;	 /* bit-pattern of options */
	char *v4_service;	 /* service expected */
	char *v4_instance;	 /* inst expected (may be filled in) */
	struct sockaddr_in *v4_faddr; /* foreign address */
	struct sockaddr_in *v4_laddr; /* local address */
	AUTH_DAT **v4_kdata;	 /* kerberos data (returned) */
	char *v4_filename;	 /* name of file with service keys */
	Key_schedule v4_schedule; /* key schedule (return) */
	char *v4_version;		 /* version string (filled in) */
{
	union verslen {
		krb5_int32	len;
		char		vers[4];
	} vers;
	char	*buf;
	int	len, length;
	krb5_int32	retval;
	int		fd = *( (int *) fdp);
#ifdef KRB5_KRB4_COMPAT
	KTEXT		v4_ticket;	 /* storage for client's ticket */
#endif
		
	if ((retval = krb5_net_read(context, fd, vers.vers, 4)) != 4)
		return((retval < 0) ? errno : ECONNABORTED);

#ifdef KRB5_KRB4_COMPAT
	if (!strncmp(vers.vers, KRB_V4_SENDAUTH_VERS, 4)) {
		/*
		 * We must be talking to a V4 sendauth; read in the
		 * rest of the version string and make sure.
		 */
		if ((retval = krb5_net_read(context, fd, vers.vers, 4)) != 4)
			return((retval < 0) ? errno : ECONNABORTED);
		
		if (strncmp(vers.vers, KRB_V4_SENDAUTH_VERS+4, 4))
			return KRB5_SENDAUTH_BADAUTHVERS;

		*auth_sys = KRB5_RECVAUTH_V4;

		*v4_kdata = (AUTH_DAT *) malloc( sizeof(AUTH_DAT) );
		v4_ticket = (KTEXT) malloc(sizeof(KTEXT_ST));

		retval = krb_v4_recvauth(v4_options, fd, v4_ticket,
					 v4_service, v4_instance, v4_faddr,
					 v4_laddr, *v4_kdata, v4_filename,
					 v4_schedule, v4_version);
		krb5_xfree(v4_ticket);
		/*
		 * XXX error code translation?
		 */
		switch (retval) {
		case RD_AP_OK:
		    return 0;
		case RD_AP_TIME:
		    return KRB5KRB_AP_ERR_SKEW;
		case RD_AP_EXP:
		    return KRB5KRB_AP_ERR_TKT_EXPIRED;
		case RD_AP_NYV:
		    return KRB5KRB_AP_ERR_TKT_NYV;
		case RD_AP_NOT_US:
		    return KRB5KRB_AP_ERR_NOT_US;
		case RD_AP_UNDEC:
		    return KRB5KRB_AP_ERR_BAD_INTEGRITY;
		case RD_AP_REPEAT:
		    return KRB5KRB_AP_ERR_REPEAT;
		case RD_AP_MSG_TYPE:
		    return KRB5KRB_AP_ERR_MSG_TYPE;
		case RD_AP_MODIFIED:
		    return KRB5KRB_AP_ERR_MODIFIED;
		case RD_AP_ORDER:
		    return KRB5KRB_AP_ERR_BADORDER;
		case RD_AP_BADD:
		    return KRB5KRB_AP_ERR_BADADDR;
		default:
		    return KRB5_SENDAUTH_BADRESPONSE;
		}
	}
#endif

	/*
	 * Assume that we're talking to a V5 recvauth; read in the
	 * the version string, and make sure it matches.
	 */
	
	len = (int) ntohl(vers.len);

	if (len < 0 || len > 255)
		return KRB5_SENDAUTH_BADAUTHVERS;

	buf = malloc((unsigned) len);
	if (!buf)
		return ENOMEM;
	
	length = krb5_net_read(context, fd, buf, len);
	if (len != length) {
		krb5_xfree(buf);
		if (len < 0)
			return errno;
		else
			return ECONNABORTED;
	}

	if (strcmp(buf, KRB_V5_SENDAUTH_VERS)) {
		krb5_xfree(buf);
		return KRB5_SENDAUTH_BADAUTHVERS;
	}
	krb5_xfree(buf);

	*auth_sys = KRB5_RECVAUTH_V5;
	
	retval = krb5_recvauth(context, auth_context, fdp, appl_version, server,
			       flags | KRB5_RECVAUTH_SKIP_VERSION, 
			       keytab, ticket);

	return retval;
}

krb5_error_code
krb5_compat_recvauth_version(context, auth_context,
			     /* IN */
			     fdp, server, flags, keytab,
			     v4_options, v4_service, v4_instance, v4_faddr,
			     v4_laddr,
			     v4_filename, 
			     /* OUT */
			     ticket,
			     auth_sys, v4_kdata, v4_schedule,
			     version)
    krb5_context context;
    krb5_auth_context  *auth_context;
	krb5_pointer	fdp;
	krb5_principal	server;
	krb5_int32	flags;
	krb5_keytab    	keytab;
	krb5_ticket  ** ticket;
        krb5_int32      *auth_sys;

	/*
	 * Version 4 arguments
	 */
	krb5_int32 v4_options;	 /* bit-pattern of options */
	char *v4_service;	 /* service expected */
	char *v4_instance;	 /* inst expected (may be filled in) */
	struct sockaddr_in *v4_faddr; /* foreign address */
	struct sockaddr_in *v4_laddr; /* local address */
	AUTH_DAT **v4_kdata;	 /* kerberos data (returned) */
	char *v4_filename;	 /* name of file with service keys */
	Key_schedule v4_schedule; /* key schedule (return) */
    krb5_data *version;		/* application version filled in */
{
	union verslen {
		krb5_int32	len;
		char		vers[4];
	} vers;
	char	*buf;
	int	len, length;
	krb5_int32	retval;
	int		fd = *( (int *) fdp);
#ifdef KRB5_KRB4_COMPAT
	KTEXT		v4_ticket;	 /* storage for client's ticket */
#endif
		
	if ((retval = krb5_net_read(context, fd, vers.vers, 4)) != 4)
		return((retval < 0) ? errno : ECONNABORTED);

#ifdef KRB5_KRB4_COMPAT
	if (v4_faddr->sin_family == AF_INET
	    && !strncmp(vers.vers, KRB_V4_SENDAUTH_VERS, 4)) {
		/*
		 * We must be talking to a V4 sendauth; read in the
		 * rest of the version string and make sure.
		 */
		if ((retval = krb5_net_read(context, fd, vers.vers, 4)) != 4)
			return((retval < 0) ? errno : ECONNABORTED);
		
		if (strncmp(vers.vers, KRB_V4_SENDAUTH_VERS+4, 4))
			return KRB5_SENDAUTH_BADAUTHVERS;

		*auth_sys = KRB5_RECVAUTH_V4;

		*v4_kdata = (AUTH_DAT *) malloc( sizeof(AUTH_DAT) );
		v4_ticket = (KTEXT) malloc(sizeof(KTEXT_ST));

		version->length = KRB_SENDAUTH_VLEN; /* no trailing \0! */
		version->data = malloc (KRB_SENDAUTH_VLEN + 1);
		version->data[KRB_SENDAUTH_VLEN] = 0;
		if (version->data == 0)
		    return errno;
		retval = krb_v4_recvauth(v4_options, fd, v4_ticket,
					 v4_service, v4_instance, v4_faddr,
					 v4_laddr, *v4_kdata, v4_filename,
					 v4_schedule, version->data);
		krb5_xfree(v4_ticket);
		/*
		 * XXX error code translation?
		 */
		switch (retval) {
		case RD_AP_OK:
		    return 0;
		case RD_AP_TIME:
		    return KRB5KRB_AP_ERR_SKEW;
		case RD_AP_EXP:
		    return KRB5KRB_AP_ERR_TKT_EXPIRED;
		case RD_AP_NYV:
		    return KRB5KRB_AP_ERR_TKT_NYV;
		case RD_AP_NOT_US:
		    return KRB5KRB_AP_ERR_NOT_US;
		case RD_AP_UNDEC:
		    return KRB5KRB_AP_ERR_BAD_INTEGRITY;
		case RD_AP_REPEAT:
		    return KRB5KRB_AP_ERR_REPEAT;
		case RD_AP_MSG_TYPE:
		    return KRB5KRB_AP_ERR_MSG_TYPE;
		case RD_AP_MODIFIED:
		    return KRB5KRB_AP_ERR_MODIFIED;
		case RD_AP_ORDER:
		    return KRB5KRB_AP_ERR_BADORDER;
		case RD_AP_BADD:
		    return KRB5KRB_AP_ERR_BADADDR;
		default:
		    return KRB5_SENDAUTH_BADRESPONSE;
		}
	}
#endif

	/*
	 * Assume that we're talking to a V5 recvauth; read in the
	 * the version string, and make sure it matches.
	 */
	
	len = (int) ntohl(vers.len);

	if (len < 0 || len > 255)
		return KRB5_SENDAUTH_BADAUTHVERS;

	buf = malloc((unsigned) len);
	if (!buf)
		return ENOMEM;
	
	length = krb5_net_read(context, fd, buf, len);
	if (len != length) {
		krb5_xfree(buf);
		if (len < 0)
			return errno;
		else
			return ECONNABORTED;
	}

	if (strcmp(buf, KRB_V5_SENDAUTH_VERS)) {
		krb5_xfree(buf);
		return KRB5_SENDAUTH_BADAUTHVERS;
	}
	krb5_xfree(buf);

	*auth_sys = KRB5_RECVAUTH_V5;
	
	retval = krb5_recvauth_version(context, auth_context, fdp, server,
				       flags | KRB5_RECVAUTH_SKIP_VERSION, 
				       keytab, ticket, version);

	return retval;
}
#endif /* KRB5_KRB4_COMPAT */


#ifndef max
#define	max(a,b) (((a) > (b)) ? (a) : (b))
#endif /* max */

#ifdef KRB5_KRB4_COMPAT	
static int
krb_v4_recvauth(options, fd, ticket, service, instance, faddr, laddr, kdata,
		filename, schedule, version)
long options;			 /* bit-pattern of options */
int fd;				 /* file descr. to read from */
KTEXT ticket;			 /* storage for client's ticket */
char *service;			 /* service expected */
char *instance;			 /* inst expected (may be filled in) */
struct sockaddr_in *faddr;	 /* address of foreign host on fd */
struct sockaddr_in *laddr;	 /* local address */
AUTH_DAT *kdata;		 /* kerberos data (returned) */
char *filename;			 /* name of file with service keys */
Key_schedule schedule;		 /* key schedule (return) */
char *version;			 /* version string (filled in) */
{
    int cc, old_vers = 0;
    int rem;
    krb5_int32 tkt_len, priv_len;
    krb5_ui_4 cksum;
    u_char tmp_buf[MAX_KTXT_LEN+max(KRB_SENDAUTH_VLEN+1,21)];

    /* read the application version string */
    if ((krb_net_read(fd, version, KRB_SENDAUTH_VLEN) !=
	 KRB_SENDAUTH_VLEN))
	return(errno);
    version[KRB_SENDAUTH_VLEN] = '\0';

    /* get the length of the ticket */
    if (krb_net_read(fd, (char *)&tkt_len, sizeof(tkt_len)) !=
	sizeof(tkt_len))
	return(errno);
    
    /* sanity check */
    ticket->length = ntohl((unsigned long)tkt_len);
    if ((ticket->length <= 0) || (ticket->length > MAX_KTXT_LEN)) {
	if (options & KOPT_DO_MUTUAL) {
	    rem = KFAILURE;
	    goto mutual_fail;
	} else
	    return(KFAILURE); /* XXX there may still be junk on the fd? */
    }		

    /* read the ticket */
    if (krb_net_read(fd, (char *) ticket->dat, ticket->length)
	!= ticket->length)
	return(errno);

    /*
     * now have the ticket.  decrypt it to get the authenticated
     * data.
     */
    rem = krb_rd_req(ticket,service,instance,faddr->sin_addr.s_addr,
		     kdata,filename);

    if (old_vers) return(rem);	 /* XXX can't do mutual with old client */

    /* if we are doing mutual auth, compose a response */
    if (options & KOPT_DO_MUTUAL) {
	if (rem != KSUCCESS)
	    /* the krb_rd_req failed */
	    goto mutual_fail;

	/* add one to the (formerly) sealed checksum, and re-seal it
	   for return to the client */
	cksum = kdata->checksum + 1;
	cksum = htonl(cksum);
#ifndef NOENCRYPTION
	key_sched(kdata->session,schedule);
#endif /* !NOENCRYPTION */
	priv_len = krb_mk_priv((unsigned char *)&cksum,
			       tmp_buf,
			       (unsigned long) sizeof(cksum),
			       schedule,
			       &kdata->session,
			       laddr,
			       faddr);
	if (priv_len < 0) {
	    /* re-sealing failed; notify the client */
	    rem = KFAILURE;	 /* XXX */
mutual_fail:
	    priv_len = -1;
	    tkt_len = htonl((unsigned long) priv_len);
	    /* a length of -1 is interpreted as an authentication
	       failure by the client */
	    if ((cc = krb_net_write(fd, (char *)&tkt_len, sizeof(tkt_len)))
		!= sizeof(tkt_len))
		return(cc);
	    return(rem);
	} else {
	    /* re-sealing succeeded, send the private message */
	    tkt_len = htonl((unsigned long)priv_len);
	    if ((cc = krb_net_write(fd, (char *)&tkt_len, sizeof(tkt_len)))
		 != sizeof(tkt_len))
		return(cc);
	    if ((cc = krb_net_write(fd, (char *)tmp_buf, (int) priv_len))
		!= (int) priv_len)
		return(cc);
	}
    }
    return(rem);
}
#endif
#endif

#include <sys/select.h>
#include "port-sockets.h"

int
accept_a_connection (int debug_port, struct sockaddr *from,
		     socklen_t *fromlenp)
{
    int n, s, fd, s4 = -1, s6 = -1, on = 1;
    fd_set sockets;

    FD_ZERO(&sockets);

#ifdef KRB5_USE_INET6
    {
	struct sockaddr_in6 sock_in6;

	if ((s = socket(AF_INET6, SOCK_STREAM, PF_UNSPEC)) < 0) {
	    if ((errno == EPROTONOSUPPORT) || (errno == EAFNOSUPPORT))
		goto skip_ipv6;
	    fprintf(stderr, "Error in socket(INET6): %s\n", strerror(errno));
	    exit(2);
	}

	memset((char *) &sock_in6, 0,sizeof(sock_in6));
	sock_in6.sin6_family = AF_INET6;
	sock_in6.sin6_port = htons(debug_port);
	sock_in6.sin6_addr = in6addr_any;

	(void) setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
			  (char *)&on, sizeof(on));

	if ((bind(s, (struct sockaddr *) &sock_in6, sizeof(sock_in6))) < 0) {
	    fprintf(stderr, "Error in bind(INET6): %s\n", strerror(errno));
	    exit(2);
	}

	if ((listen(s, 5)) < 0) {
	    fprintf(stderr, "Error in listen(INET6): %s\n", strerror(errno));
	    exit(2);
	}
	s6 = s;
	FD_SET(s, &sockets);
    skip_ipv6:
	;
    }
#endif

    {
	struct sockaddr_in sock_in;

	if ((s = socket(AF_INET, SOCK_STREAM, PF_UNSPEC)) < 0) {
	    fprintf(stderr, "Error in socket: %s\n", strerror(errno));
	    exit(2);
	}

	memset((char *) &sock_in, 0,sizeof(sock_in));
	sock_in.sin_family = AF_INET;
	sock_in.sin_port = htons(debug_port);
	sock_in.sin_addr.s_addr = INADDR_ANY;

	(void) setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
			  (char *)&on, sizeof(on));

	if ((bind(s, (struct sockaddr *) &sock_in, sizeof(sock_in))) < 0) {
	    if (s6 >= 0 && errno == EADDRINUSE)
		goto try_ipv6_only;
	    fprintf(stderr, "Error in bind: %s\n", strerror(errno));
	    exit(2);
	}

	if ((listen(s, 5)) < 0) {
	    fprintf(stderr, "Error in listen: %s\n", strerror(errno));
	    exit(2);
	}
	s4 = s;
	FD_SET(s, &sockets);
    try_ipv6_only:
	;
    }
    if (s4 == -1 && s6 == -1) {
	fprintf(stderr, "No valid sockets established, exiting\n");
	exit(2);
    }
    n = select(((s4 < s6) ? s6 : s4) + 1, &sockets, 0, 0, 0);
    if (n < 0) {
	fprintf(stderr, "select error: %s\n", strerror(errno));
	exit(2);
    } else if (n == 0) {
	fprintf(stderr, "internal error? select returns 0\n");
	exit(2);
    }
    if (s6 != -1 && FD_ISSET(s6, &sockets)) {
	if (s4 != -1)
	    close(s4);
	s = s6;
    } else if (FD_ISSET(s4, &sockets)) {
	if (s6 != -1)
	    close(s6);
	s = s4;
    } else {
	fprintf(stderr,
		"internal error? select returns positive, "
		"but neither fd available\n");
	exit(2);
    }

    if ((fd = accept(s, from, fromlenp)) < 0) {
	fprintf(stderr, "Error in accept: %s\n", strerror(errno));
	exit(2);
    }

    close(s);
    return fd;
}
